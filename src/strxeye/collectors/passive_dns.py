"""Passive DNS history from mnemonic's public PassiveDNS API.

Passive DNS shows what a name resolved to in the past (and which names
pointed at an IP), which live DNS cannot. Records come from mnemonic's
sensors, so coverage is partial: a missing record does not mean the
resolution never happened. Historical links get confidence 0.7 because
they describe the past, not the present.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, fetch
from ..targets import TargetError, normalize_domain, normalize_ip
from .base import Collector, CollectorContext, Findings

API = "https://api.mnemonic.no/pdns/v3/"
METHOD = "Passive DNS lookup (mnemonic PassiveDNS API)"
LIMIT = 200


def iso(ms: int | None) -> str | None:
    return datetime.fromtimestamp(ms / 1000, UTC).isoformat() if ms else None


class PassiveDnsCollector(Collector):
    name = "passive_dns"
    title = "Passive DNS history (mnemonic)"
    description = "Historical A/AAAA/CNAME/NS/MX resolutions with first and last seen dates."
    accepts = frozenset({EntityType.DOMAIN, EntityType.IP})
    sources = ("api.mnemonic.no",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        url = f"{API}{target.value}"
        response = await fetch(ctx.client, url, params={"limit": str(LIMIT)},
                               limiter=ctx.limiter, retries=ctx.settings.network.retries)
        try:
            body = response.json()
        except json.JSONDecodeError:
            raise FetchError("api.mnemonic.no did not return JSON") from None
        records = body.get("data") or []
        if not records:
            return found
        evidence = found.add_evidence(str(response.request.url), response.text,
                                      "application/json")
        if body.get("count", 0) > LIMIT:
            found.partial = True
            found.notes.append(f"{body['count']} records exist; stored the first {LIMIT}")

        for rec in records:
            rrtype = (rec.get("rrtype") or "").lower()
            query, answer = rec.get("query", ""), rec.get("answer", "")
            value = {"rrtype": rrtype, "query": query, "answer": answer,
                     "first_seen": iso(rec.get("firstSeenTimestamp")),
                     "last_seen": iso(rec.get("lastSeenTimestamp")), "times": rec.get("times")}
            found.observe(target, "pdns.record", value, method=METHOD, evidence_id=evidence,
                          confidence=0.7)
            try:
                if rrtype in ("a", "aaaa"):
                    domain = found.entity(EntityType.DOMAIN, normalize_domain(query))
                    ip = found.entity(EntityType.IP, normalize_ip(answer))
                    found.relate(domain, RelationType.RESOLVES_TO, ip, evidence_id=evidence,
                                 confidence=0.7)
                elif rrtype == "cname":
                    src = found.entity(EntityType.DOMAIN, normalize_domain(query))
                    dst = found.entity(EntityType.DOMAIN, normalize_domain(answer))
                    found.relate(src, RelationType.ALIAS_OF, dst, evidence_id=evidence,
                                 confidence=0.7)
                elif rrtype in ("ns", "mx"):
                    src = found.entity(EntityType.DOMAIN, normalize_domain(query))
                    dst = found.entity(EntityType.DOMAIN, normalize_domain(answer))
                    relation = (RelationType.USES_NAMESERVER if rrtype == "ns"
                                else RelationType.MAIL_HANDLED_BY)
                    found.relate(src, relation, dst, evidence_id=evidence, confidence=0.7)
            except TargetError:
                continue  # malformed or internal names in sensor data
        return found
