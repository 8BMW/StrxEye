from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from ..models import EntityRef, EntityType, RelationType
from ..targets import TargetError, normalize_domain, normalize_ip
from .base import Collector, CollectorContext, Findings

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


def resolver_label(resolver: dns.asyncresolver.Resolver) -> str:
    return "dns query via " + ", ".join(str(ns) for ns in resolver.nameservers[:3])


async def query(
    resolver: dns.asyncresolver.Resolver, name: str, rdtype: str
) -> dns.resolver.Answer | None:
    """Resolve one record type. Returns None when the name has no records of
    that type; lets NXDOMAIN propagate so the caller can stop early."""
    try:
        return await resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except dns.resolver.NoNameservers:
        return None


class DnsCollector(Collector):
    name = "dns"
    title = "DNS records"
    description = "A, AAAA, CNAME, MX, NS, TXT, SOA and CAA records, plus the DMARC policy."
    accepts = frozenset({EntityType.DOMAIN})
    sources = ("configured DNS resolver",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        method = resolver_label(ctx.resolver)
        domain = target.value

        async def one(rdtype: str) -> dns.resolver.Answer | None:
            try:
                return await query(ctx.resolver, domain, rdtype)
            except dns.exception.Timeout:
                found.partial = True
                found.notes.append(f"{rdtype} lookup timed out")
                return None

        try:
            answers = await asyncio.gather(*(one(rdtype) for rdtype in RECORD_TYPES))
        except dns.resolver.NXDOMAIN:
            found.notes.append(f"{domain} does not exist (NXDOMAIN)")
            return found

        for rdtype, answer in zip(RECORD_TYPES, answers, strict=True):
            if answer is None or answer.rrset is None:
                continue
            evidence = found.add_evidence(f"{domain} {rdtype}", answer.rrset.to_text())
            for rdata in answer.rrset:
                self._record(found, target, rdtype, rdata, method, evidence)

        await self._dmarc(found, target, ctx, method)
        return found

    def _record(self, found, target, rdtype, rdata, method, evidence) -> None:
        if rdtype in ("A", "AAAA"):
            ip = found.entity(EntityType.IP, normalize_ip(rdata.address))
            found.observe(target, f"dns.{rdtype.lower()}", ip.value, method=method,
                          evidence_id=evidence)
            found.relate(target, RelationType.RESOLVES_TO, ip, evidence_id=evidence)
        elif rdtype in ("CNAME", "NS", "MX"):
            host = rdata.exchange if rdtype == "MX" else rdata.target
            try:
                other = found.entity(EntityType.DOMAIN, normalize_domain(host.to_text()))
            except TargetError:
                # e.g. "MX 0 ." (null MX, RFC 7505) means "accepts no mail".
                found.observe(target, "dns.mx.null", True, method=method, evidence_id=evidence)
                return
            value = {"host": other.value, "preference": rdata.preference} if rdtype == "MX" \
                else other.value
            found.observe(target, f"dns.{rdtype.lower()}", value, method=method,
                          evidence_id=evidence)
            relation = {
                "CNAME": RelationType.ALIAS_OF,
                "NS": RelationType.USES_NAMESERVER,
                "MX": RelationType.MAIL_HANDLED_BY,
            }[rdtype]
            found.relate(target, relation, other, evidence_id=evidence)
        elif rdtype == "TXT":
            text = b"".join(rdata.strings).decode("utf-8", "replace")
            kind = "dns.txt.spf" if text.lower().startswith("v=spf1") else "dns.txt"
            found.observe(target, kind, text, method=method, evidence_id=evidence)
        elif rdtype == "SOA":
            found.observe(
                target,
                "dns.soa",
                {
                    "mname": rdata.mname.to_text().rstrip("."),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "minimum": rdata.minimum,
                },
                method=method,
                evidence_id=evidence,
            )
        elif rdtype == "CAA":
            found.observe(
                target,
                "dns.caa",
                {"tag": rdata.tag.decode(), "value": rdata.value.decode("utf-8", "replace")},
                method=method,
                evidence_id=evidence,
            )

    async def _dmarc(self, found, target, ctx, method) -> None:
        name = f"_dmarc.{target.value}"
        try:
            answer = await query(ctx.resolver, name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
            answer = None
        records = []
        if answer is not None and answer.rrset is not None:
            records = [b"".join(r.strings).decode("utf-8", "replace") for r in answer.rrset]
        policies = [r for r in records if r.lower().startswith("v=dmarc1")]
        if policies:
            evidence = found.add_evidence(f"{name} TXT", "\n".join(records))
            found.observe(target, "dns.dmarc", policies[0], method=method, evidence_id=evidence)
        # Absence of DMARC is only meaningful for names that exist, which we
        # know because the main lookup did not return NXDOMAIN.
        elif not found.empty:
            found.observe(target, "dns.dmarc.missing", True, method=method)


class ReverseDnsCollector(Collector):
    name = "reverse_dns"
    title = "Reverse DNS"
    description = "PTR record for an IP address."
    accepts = frozenset({EntityType.IP})
    sources = ("configured DNS resolver",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        try:
            answer = await ctx.resolver.resolve_address(target.value, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return found
        if answer.rrset is None:
            return found
        evidence = found.add_evidence(f"PTR {target.value}", answer.rrset.to_text())
        for rdata in answer.rrset:
            try:
                name = normalize_domain(rdata.target.to_text())
            except TargetError:
                continue
            host = found.entity(EntityType.DOMAIN, name)
            found.observe(target, "dns.ptr", name, method=resolver_label(ctx.resolver),
                          evidence_id=evidence)
            # A PTR is set by whoever controls the IP block, not the domain,
            # so it says nothing certain about the domain's owner.
            found.relate(target, RelationType.REVERSE_DNS, host, evidence_id=evidence,
                         confidence=0.8)
        return found
