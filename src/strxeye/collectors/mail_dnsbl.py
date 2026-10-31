"""DNS-based checks: email security records for domains, and DNS block
lists (DNSBLs) for IP addresses. Both only send DNS queries through the
configured resolver."""

from __future__ import annotations

import asyncio
import ipaddress

import dns.exception
import dns.resolver

from ..models import EntityRef, EntityType, RelationType
from .base import Collector, CollectorContext, Findings
from .dns_records import resolver_label

# Selectors used by the most common mail providers. Querying them is a
# plain DNS lookup; a hit shows which provider signs the domain's mail.
DKIM_SELECTORS = ("google", "selector1", "selector2", "k1", "k2", "default", "s1", "s2",
                  "dkim", "mail", "mandrill", "smtp", "mxvault", "zoho", "protonmail")


async def txt_records(ctx: CollectorContext, name: str) -> list[str]:
    try:
        answer = await ctx.resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    if answer.rrset is None:
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer.rrset]


class MailSecurityCollector(Collector):
    name = "mailsec"
    title = "Email security records"
    description = "MTA-STS, TLS reporting, BIMI and DKIM keys for common selectors."
    accepts = frozenset({EntityType.DOMAIN})
    sources = ("configured DNS resolver",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        method = resolver_label(ctx.resolver)
        d = target.value
        checks = {
            "mail.mta_sts": f"_mta-sts.{d}",
            "mail.tls_rpt": f"_smtp._tls.{d}",
            "mail.bimi": f"default._bimi.{d}",
        }
        results = await asyncio.gather(*(txt_records(ctx, n) for n in checks.values()))
        for (kind, name), records in zip(checks.items(), results, strict=True):
            prefix = {"mail.mta_sts": "v=sts", "mail.tls_rpt": "v=tlsrpt",
                      "mail.bimi": "v=bimi"}[kind]
            policy = [r for r in records if r.lower().startswith(prefix)]
            if policy:
                ev = found.add_evidence(f"{name} TXT", "\n".join(records))
                found.observe(target, kind, policy[0], method=method, evidence_id=ev)
            else:
                found.observe(target, f"{kind}.missing", True, method=method)

        names = [f"{s}._domainkey.{d}" for s in DKIM_SELECTORS]
        dkim = await asyncio.gather(*(txt_records(ctx, n) for n in names))
        for selector, records in zip(DKIM_SELECTORS, dkim, strict=True):
            keys = [r for r in records if "p=" in r]
            if keys:
                ev = found.add_evidence(f"{selector}._domainkey.{d} TXT", "\n".join(keys))
                found.observe(target, "mail.dkim_selector", selector, method=method,
                              evidence_id=ev)
        return found


# (zone, title, meaning). Listing codes are 127.0.0.x; Spamhaus and others
# answer 127.255.255.x when they refuse the query (for example from a large
# public resolver), which must not be read as a listing.
DNSBLS = (
    ("zen.spamhaus.org", "Spamhaus ZEN", "Listed by Spamhaus (spam sources, exploited hosts or "
                                         "end-user ranges that should not send mail)."),
    ("bl.spamcop.net", "SpamCop", "Reported by SpamCop users as a spam source."),
    ("b.barracudacentral.org", "Barracuda Reputation", "Poor email reputation at Barracuda."),
    ("dnsbl.dronebl.org", "DroneBL", "Listed as a drone, open proxy or botnet member."),
    ("psbl.surriel.com", "PSBL", "Sent mail to Passive Spam Block List spam traps."),
    ("all.s5h.net", "s5h.net", "Listed by s5h.net for spam or abuse."),
)


class DnsblCollector(Collector):
    name = "dnsbl"
    title = "DNS block lists"
    description = f"Checks the IP against {len(DNSBLS)} DNS block lists used by mail servers."
    accepts = frozenset({EntityType.IP})
    sources = tuple(z for z, _, _ in DNSBLS) + ("(queried through your DNS resolver)",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        ip = ipaddress.ip_address(target.value)
        if ip.version != 4 or not ip.is_global:
            return found  # most DNSBLs only publish IPv4 zones
        reversed_ip = ".".join(reversed(target.value.split(".")))
        method = resolver_label(ctx.resolver)

        async def check(zone):
            name = f"{reversed_ip}.{zone}"
            try:
                answer = await ctx.resolver.resolve(name, "A", raise_on_no_answer=False)
            except dns.resolver.NXDOMAIN:
                return zone, name, []
            except (dns.resolver.NoNameservers, dns.exception.Timeout):
                return zone, name, None
            codes = [r.to_text() for r in answer.rrset] if answer.rrset is not None else []
            return zone, name, codes

        results = await asyncio.gather(*(check(z) for z, _, _ in DNSBLS))
        meta = {z: (t, m) for z, t, m in DNSBLS}
        clean, refused = [], []
        for zone, name, codes in results:
            title, meaning = meta[zone]
            if codes is None:
                refused.append(title)
                continue
            listed = [c for c in codes if c.startswith("127.") and not c.startswith("127.255.")]
            if any(c.startswith("127.255.") for c in codes):
                refused.append(title)
            if not listed:
                clean.append(title)
                continue
            ev = found.add_evidence(f"{name} A", "\n".join(codes))
            listing = found.entity(EntityType.INDICATOR, title, kind="threat list")
            found.observe(target, "threat.listed",
                          {"feed": title, "severity": "low", "meaning": meaning,
                           "return_codes": listed},
                          method=method, evidence_id=ev, confidence=0.8)
            found.relate(target, RelationType.OBSERVED_IN, listing, evidence_id=ev,
                         confidence=0.8)
        if refused:
            found.notes.append("query refused or failed (often because the resolver is a "
                               "large public one): " + ", ".join(refused))
        if clean and found.empty:
            found.observe(target, "threat.not_listed", clean, method=method)
        return found
