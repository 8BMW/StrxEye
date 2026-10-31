"""Certificate Transparency search through crt.sh.

CT logs record every publicly trusted certificate at issuance, which makes
them the best passive source of subdomains. A name appearing in a
certificate only proves someone obtained a certificate for it, not that the
name resolves or is in use today, hence the reduced confidence on derived
subdomains.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, fetch
from ..targets import TargetError, normalize_domain
from .base import Collector, CollectorContext, Findings

API = "https://crt.sh/"
METHOD = "Certificate Transparency search (crt.sh JSON API)"
MAX_NAMES_PER_CERT = 50
_ORG = re.compile(r"(?:^|,\s*)O=(\"[^\"]+\"|[^,]+)")


def issuer_org(issuer: str) -> str | None:
    match = _ORG.search(issuer or "")
    return match.group(1).strip('"').strip() if match else None


def cert_names(entry: dict[str, Any]) -> set[str]:
    names = set()
    for raw in str(entry.get("name_value", "")).splitlines() + [entry.get("common_name") or ""]:
        raw = raw.strip().lower()
        if raw.startswith("*."):
            raw = raw[2:]
        try:
            names.add(normalize_domain(raw))
        except TargetError:
            continue  # CNs are sometimes free text or email addresses
    return names


class CrtShCollector(Collector):
    name = "crtsh"
    title = "Certificate Transparency (crt.sh)"
    description = "Certificates logged for the domain and subdomains found in them."
    accepts = frozenset({EntityType.DOMAIN})
    sources = ("crt.sh",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        ctx.limiter.set_interval("crt.sh", 1.5)
        domain = target.value
        entries: dict[int, dict[str, Any]] = {}
        for query in (f"%.{domain}", domain):
            url = f"{API}?q={query}&output=json"
            try:
                # Pass the query as params so httpx percent-encodes the "%"
                # wildcard instead of mistaking it for an escape sequence.
                response = await fetch(ctx.client, API, retries=ctx.settings.network.retries,
                                       limiter=ctx.limiter,
                                       params={"q": query, "output": "json"})
            except FetchError as exc:
                if not entries:
                    raise FetchError(f"{exc} (crt.sh is often overloaded; retry in a few "
                                     "minutes)") from None
                found.partial = True
                found.notes.append(f"second crt.sh query failed: {exc}")
                continue
            text = response.text
            try:
                rows = json.loads(text) if text.strip() else []
            except json.JSONDecodeError:
                raise FetchError("crt.sh returned a non-JSON page (often a temporary "
                                 "overload); try again later") from None
            evidence = found.add_evidence(url, text, "application/json")
            for row in rows:
                if isinstance(row, dict) and "id" in row:
                    row["_evidence"] = evidence
                    entries.setdefault(row["id"], row)

        if not entries:
            return found
        found.observe(target, "ct.certificate_count", len(entries), method=METHOD)

        subdomains: set[str] = set()
        for entry in entries.values():
            subdomains.update(n for n in cert_names(entry) if n.endswith("." + domain))

        limit = ctx.settings.collection.max_subdomains
        if len(subdomains) > limit:
            found.partial = True
            found.notes.append(f"{len(subdomains)} subdomains found; kept the first {limit} "
                               "(collection.max_subdomains)")
        for name in sorted(subdomains)[:limit]:
            sub = found.entity(EntityType.DOMAIN, name)
            found.relate(sub, RelationType.SUBDOMAIN_OF, target, confidence=0.8)
            found.observe(target, "ct.subdomain", name, method=METHOD, confidence=0.8)

        newest = sorted(entries.values(), key=lambda e: e.get("not_before") or "", reverse=True)
        cert_limit = ctx.settings.collection.max_certificates
        if len(newest) > cert_limit:
            found.notes.append(f"{len(newest)} certificates logged; graphed the newest "
                               f"{cert_limit} (collection.max_certificates)")
        for entry in newest[:cert_limit]:
            self._certificate(found, target, entry)
        return found

    def _certificate(self, found: Findings, target: EntityRef, entry: dict[str, Any]) -> None:
        evidence = entry["_evidence"]
        names = sorted(cert_names(entry))
        cert = found.entity(
            EntityType.CERTIFICATE,
            f"crtsh:{entry['id']}",
            serial=entry.get("serial_number"),
            issuer=entry.get("issuer_name"),
            common_name=entry.get("common_name"),
            not_before=entry.get("not_before"),
            not_after=entry.get("not_after"),
            logged_at=entry.get("entry_timestamp"),
            names=names[:MAX_NAMES_PER_CERT],
            url=f"https://crt.sh/?id={entry['id']}",
        )
        for name in names[:MAX_NAMES_PER_CERT]:
            ref = target if name == target.value else found.entity(EntityType.DOMAIN, name)
            found.relate(cert, RelationType.CERTIFICATE_ISSUED_FOR, ref, evidence_id=evidence)
        org = issuer_org(entry.get("issuer_name", ""))
        if org:
            ca = found.entity(EntityType.ORGANIZATION, org, role="certificate authority")
            found.relate(cert, RelationType.ISSUED_BY, ca, evidence_id=evidence)
