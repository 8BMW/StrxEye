"""Certificate Transparency through SSLMate's Cert Spotter API.

A second CT source next to crt.sh: crt.sh is frequently overloaded, and
having both means a run still gets certificate data when one is down.
Certificates are identified by the SHA-256 of the certificate, the same ID
the tls collector uses, so a certificate seen in CT and served by the site
becomes a single node.
"""

from __future__ import annotations

import json

from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, fetch
from ..targets import TargetError, normalize_domain
from .base import Collector, CollectorContext, Findings
from .crtsh import issuer_org

API = "https://api.certspotter.com/v1/issuances"
METHOD = "Certificate Transparency search (Cert Spotter API)"


class CertSpotterCollector(Collector):
    name = "certspotter"
    title = "Certificate Transparency (Cert Spotter)"
    description = "Unexpired certificates for the domain and its subdomains."
    accepts = frozenset({EntityType.DOMAIN})
    sources = ("api.certspotter.com",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        params = {"domain": target.value, "include_subdomains": "true",
                  "expand": ["dns_names", "issuer"]}
        response = await fetch(ctx.client, API, params=params, limiter=ctx.limiter,  # type: ignore[arg-type]
                               retries=ctx.settings.network.retries)
        try:
            rows = response.json()
        except json.JSONDecodeError:
            raise FetchError("api.certspotter.com did not return JSON") from None
        if not isinstance(rows, list) or not rows:
            return found
        evidence = found.add_evidence(str(response.request.url), response.text,
                                      "application/json")
        domain = target.value
        subdomains: set[str] = set()
        limit = ctx.settings.collection.max_certificates
        for row in rows[:limit]:
            names = set()
            for raw in row.get("dns_names", []):
                try:
                    names.add(normalize_domain(raw.removeprefix("*.")))
                except TargetError:
                    continue
            issuer = (row.get("issuer") or {}).get("name", "")
            cert = found.entity(
                EntityType.CERTIFICATE, f"sha256:{row['cert_sha256']}",
                issuer=issuer, not_before=row.get("not_before"), not_after=row.get("not_after"),
                revoked=row.get("revoked"), names=sorted(names)[:50],
                url=f"https://crt.sh/?q={row['cert_sha256']}")
            for name in sorted(names)[:50]:
                ref = target if name == domain else found.entity(EntityType.DOMAIN, name)
                found.relate(cert, RelationType.CERTIFICATE_ISSUED_FOR, ref, evidence_id=evidence)
                if name.endswith("." + domain):
                    subdomains.add(name)
            org = issuer_org(issuer)
            if org:
                ca = found.entity(EntityType.ORGANIZATION, org, role="certificate authority")
                found.relate(cert, RelationType.ISSUED_BY, ca, evidence_id=evidence)
        found.observe(target, "ct.unexpired_certificate_count", len(rows), method=METHOD,
                      evidence_id=evidence)
        for name in sorted(subdomains)[: ctx.settings.collection.max_subdomains]:
            sub = found.entity(EntityType.DOMAIN, name)
            found.relate(sub, RelationType.SUBDOMAIN_OF, target, evidence_id=evidence,
                         confidence=0.8)
            found.observe(target, "ct.subdomain", name, method=METHOD, evidence_id=evidence,
                          confidence=0.8)
        return found
