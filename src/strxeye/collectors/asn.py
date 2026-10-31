"""IP-to-ASN mapping through Team Cymru's public DNS interface.

Cymru derives this from BGP routing tables, so it answers a different
question from RDAP: who *announces* the prefix today, not who it is
registered to. The two often differ (customers of a hosting provider,
leased blocks), which is why both are collected and kept separate.
"""

from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver

from ..models import EntityRef, EntityType, RelationType
from .base import Collector, CollectorContext, Findings

METHOD = "DNS TXT query to Team Cymru IP-to-ASN service"


def origin_query_name(address: str) -> str:
    ip = ipaddress.ip_address(address)
    if ip.version == 4:
        return ".".join(reversed(address.split("."))) + ".origin.asn.cymru.com"
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_fields(txt: str) -> list[str]:
    return [part.strip() for part in txt.strip('"').split("|")]


async def txt(ctx: CollectorContext, name: str) -> list[str]:
    try:
        answer = await ctx.resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    if answer.rrset is None:
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer.rrset]


class AsnCollector(Collector):
    name = "asn"
    title = "BGP origin (Team Cymru)"
    description = "Announcing AS number and BGP prefix for an IP; AS name for an AS number."
    accepts = frozenset({EntityType.IP, EntityType.ASN})
    sources = ("Team Cymru (asn.cymru.com) via DNS",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        try:
            if target.type is EntityType.IP:
                await self._ip(found, target, ctx)
            else:
                await self._describe_asn(found, target, ctx, target.value[2:])
        except dns.exception.Timeout:
            if found.empty:
                raise
            found.partial = True
            found.notes.append("some Team Cymru lookups timed out")
        return found

    async def _ip(self, found: Findings, target: EntityRef, ctx: CollectorContext) -> None:
        if not ipaddress.ip_address(target.value).is_global:
            found.notes.append("address is not globally routable")
            return
        name = origin_query_name(target.value)
        records = await txt(ctx, name)
        if not records:
            return
        evidence = found.add_evidence(f"{name} TXT", "\n".join(records))
        asns: set[str] = set()
        for record in records:
            # "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"
            fields = parse_fields(record)
            if len(fields) < 2:
                continue
            prefix = str(ipaddress.ip_network(fields[1], strict=False))
            net = found.entity(EntityType.NETWORK, prefix, bgp_prefix=True)
            found.relate(target, RelationType.BELONGS_TO_NETWORK, net, evidence_id=evidence)
            found.observe(target, "bgp.prefix", prefix, method=METHOD, evidence_id=evidence)
            # Multi-origin prefixes list several ASNs separated by spaces.
            for number in fields[0].split():
                asn = found.entity(EntityType.ASN, f"AS{int(number)}")
                asns.add(number)
                found.relate(net, RelationType.ANNOUNCED_BY, asn, evidence_id=evidence)
                found.observe(target, "bgp.origin_asn", asn.value, method=METHOD,
                              evidence_id=evidence)
            if len(fields) >= 3 and fields[2]:
                found.observe(target, "bgp.registry_country", fields[2], method=METHOD,
                              evidence_id=evidence)
        for number in sorted(asns):
            await self._describe_asn(found, EntityRef(type=EntityType.ASN, value=f"AS{number}"),
                                     ctx, number)

    async def _describe_asn(self, found, asn_ref, ctx, number: str) -> None:
        name = f"AS{number}.asn.cymru.com"
        records = await txt(ctx, name)
        if not records:
            return
        evidence = found.add_evidence(f"{name} TXT", "\n".join(records))
        # "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
        fields = parse_fields(records[0])
        if len(fields) >= 5:
            found.entity(EntityType.ASN, asn_ref.value, name=fields[4], registry=fields[2])
            found.observe(asn_ref, "bgp.as_name", fields[4], method=METHOD, evidence_id=evidence)
            found.observe(asn_ref, "bgp.as_registry", fields[2], method=METHOD,
                          evidence_id=evidence)
