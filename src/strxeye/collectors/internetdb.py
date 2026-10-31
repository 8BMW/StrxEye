"""Shodan InternetDB: what Shodan's own scanners last saw on an IP.

This is passive from our side: we ask Shodan, we do not contact the IP.
The data can be weeks old. Vulnerabilities are Shodan's guesses from
software versions in banners, not confirmed findings, and are stored with
low confidence for that reason.
"""

from __future__ import annotations

import json

from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, fetch
from ..targets import TargetError, normalize_domain
from .base import Collector, CollectorContext, Findings

API = "https://internetdb.shodan.io/"
METHOD = "Shodan InternetDB lookup (HTTPS)"


class InternetDbCollector(Collector):
    name = "internetdb"
    title = "Open ports and services (Shodan InternetDB)"
    description = "Ports, hostnames, software (CPE) and banner-based CVE guesses from Shodan scans."
    accepts = frozenset({EntityType.IP})
    sources = ("internetdb.shodan.io",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        url = API + target.value
        response = await fetch(ctx.client, url, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries, allow_statuses=(404,))
        if response.status_code == 404:
            return found  # Shodan has no record of this address
        try:
            data = response.json()
        except json.JSONDecodeError:
            raise FetchError("internetdb.shodan.io did not return JSON") from None
        evidence = found.add_evidence(url, response.text, "application/json")
        obs = dict(method=METHOD, evidence_id=evidence, source_url=url)

        if data.get("ports"):
            found.observe(target, "scan.open_ports", sorted(data["ports"]), **obs)
        if data.get("tags"):
            found.observe(target, "scan.tags", data["tags"], **obs)
        for cpe in data.get("cpes", [])[:50]:
            tech = found.entity(EntityType.TECHNOLOGY, cpe, cpe=True)
            found.relate(target, RelationType.USES_TECHNOLOGY, tech, evidence_id=evidence,
                         confidence=0.6)
        for hostname in data.get("hostnames", [])[:100]:
            try:
                host = found.entity(EntityType.DOMAIN, normalize_domain(hostname))
            except TargetError:
                continue
            found.observe(target, "scan.hostname", host.value, **obs, confidence=0.6)
            found.relate(target, RelationType.ASSOCIATED_WITH, host, evidence_id=evidence,
                         confidence=0.6)
        for cve in data.get("vulns", [])[:200]:
            ref = found.entity(EntityType.INDICATOR, cve.upper(), kind="vulnerability")
            found.observe(target, "scan.possible_vulnerability", cve.upper(), **obs,
                          confidence=0.4)
            found.relate(target, RelationType.ASSOCIATED_WITH, ref, evidence_id=evidence,
                         confidence=0.4)
        return found
