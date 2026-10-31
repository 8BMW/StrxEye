"""Checks IP addresses against public block and threat lists.

Lists are downloaded whole and cached on disk (``FEED_TTL``) so looking up
many IPs costs one download per list, and the queried IPs are never sent
to the list operators.

Each list says something different, and severity reflects that:

* Spamhaus DROP: netblocks hijacked or run by criminal operations.
* abuse.ch Feodo Tracker: botnet command-and-control servers.
* Tor exit list: the address relays Tor traffic. Informational only.
"""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import cache_dir
from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, fetch
from .base import Collector, CollectorContext, Findings

FEED_TTL = 6 * 3600


@dataclass(frozen=True)
class Feed:
    key: str
    title: str
    url: str
    severity: str
    confidence: float
    explanation: str


FEEDS = (
    Feed("spamhaus_drop_v4", "Spamhaus DROP (IPv4)", "https://www.spamhaus.org/drop/drop_v4.json",
         "high", 0.9, "Netblock listed by Spamhaus as hijacked or controlled by criminals."),
    Feed("spamhaus_drop_v6", "Spamhaus DROP (IPv6)", "https://www.spamhaus.org/drop/drop_v6.json",
         "high", 0.9, "Netblock listed by Spamhaus as hijacked or controlled by criminals."),
    Feed("feodo", "abuse.ch Feodo Tracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
         "high", 0.9, "Listed as a botnet command-and-control server."),
    Feed("tor_exit", "Tor exit nodes", "https://check.torproject.org/torbulkexitlist",
         "info", 1.0, "Address is a Tor exit relay; traffic from it is not from its operator."),
)


def _cache_path(feed: Feed) -> Path:
    return cache_dir() / f"feed-{feed.key}.txt"


async def load_feed(ctx: CollectorContext, feed: Feed) -> tuple[str, str]:
    """Return (content, fetched_at_iso) from cache if fresh, else download."""
    key = f"feed-{feed.key}"
    if key in ctx.cache:
        return ctx.cache[key]
    path = _cache_path(feed)
    if path.exists() and time.time() - path.stat().st_mtime < FEED_TTL:
        content = path.read_text(encoding="utf-8")
    else:
        response = await fetch(ctx.client, feed.url, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries)
        content = response.text
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    fetched = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime))
    ctx.cache[key] = (content, fetched)
    return content, fetched


def match(feed: Feed, content: str, ip: ipaddress._BaseAddress) -> dict[str, Any] | None:
    if feed.key.startswith("spamhaus"):
        for line in content.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            cidr = row.get("cidr")
            if cidr and ip in ipaddress.ip_network(cidr, strict=False):
                return {"cidr": cidr, "sblid": row.get("sblid"), "rir": row.get("rir")}
        return None
    if feed.key == "feodo":
        for row in json.loads(content):
            if row.get("ip_address") == str(ip):
                return {k: row.get(k) for k in ("malware", "status", "port", "first_seen",
                                                "last_online", "as_name")}
        return None
    if feed.key == "tor_exit":
        return {} if str(ip) in {ln.strip() for ln in content.splitlines()} else None
    return None


class ThreatFeedCollector(Collector):
    name = "threatfeeds"
    title = "Threat and block lists"
    description = "Spamhaus DROP, abuse.ch Feodo Tracker (botnet C2) and Tor exit list."
    accepts = frozenset({EntityType.IP})
    sources = ("spamhaus.org", "feodotracker.abuse.ch", "check.torproject.org "
               "(lists are downloaded; your IPs are not sent)")

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        ip = ipaddress.ip_address(target.value)
        if not ip.is_global:
            return found
        failures = []
        checked = []
        for feed in FEEDS:
            if feed.key.endswith("_v4") and ip.version != 4:
                continue
            if feed.key.endswith("_v6") and ip.version != 6:
                continue
            try:
                content, fetched = await load_feed(ctx, feed)
            except FetchError as exc:
                failures.append(f"{feed.title}: {exc}")
                continue
            checked.append(feed.title)
            hit = match(feed, content, ip)
            if hit is None:
                continue
            evidence = found.add_evidence(
                f"{feed.url} (list fetched {fetched})",
                json.dumps({"feed": feed.title, "entry": hit, "ip": str(ip)}, indent=2),
                "application/json")
            listing = found.entity(EntityType.INDICATOR, feed.title, kind="threat list",
                                   url=feed.url)
            found.observe(target, "threat.listed",
                          {"feed": feed.title, "severity": feed.severity,
                           "meaning": feed.explanation, **hit},
                          method=f"Match against downloaded list ({fetched})",
                          evidence_id=evidence, source_url=feed.url, confidence=feed.confidence)
            found.relate(target, RelationType.OBSERVED_IN, listing, evidence_id=evidence,
                         confidence=feed.confidence)
            if hit.get("malware"):
                malware = found.entity(EntityType.MALWARE, str(hit["malware"]))
                found.relate(target, RelationType.ASSOCIATED_WITH, malware,
                             evidence_id=evidence, confidence=feed.confidence)
        if failures:
            found.notes.extend(failures)
            if not checked:
                raise FetchError("; ".join(failures))
            found.partial = True
        if checked and found.empty:
            # Record the negative result explicitly: "checked and not listed"
            # is a useful fact, and distinct from "not checked".
            found.observe(target, "threat.not_listed", checked,
                          method="Match against downloaded lists", confidence=1.0)
        return found
