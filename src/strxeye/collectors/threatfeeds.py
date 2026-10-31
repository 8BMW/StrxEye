"""Checks IPs and domains against public block and threat lists.

Lists are downloaded whole and cached on disk (``FEED_TTL``), so checking
many targets costs one download per list, and the targets themselves are
never sent to the list operators.

Each list answers a different question, and its severity and confidence
reflect that. A listing in Spamhaus DROP (netblocks run by criminals) is
much stronger than a listing in a scanner list (the address knocked on
someone's SSH port). The ``meaning`` text is shown to the analyst so the
difference stays visible.
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
    kind: str  # parser name, see PARSERS
    applies_to: str  # "ip4", "ip6", "ip" or "domain"
    severity: str
    confidence: float
    meaning: str


FEEDS: tuple[Feed, ...] = (
    Feed("spamhaus_drop_v4", "Spamhaus DROP (IPv4)", "https://www.spamhaus.org/drop/drop_v4.json",
         "spamhaus", "ip4", "high", 0.9,
         "Netblock listed by Spamhaus as hijacked or controlled by criminals."),
    Feed("spamhaus_drop_v6", "Spamhaus DROP (IPv6)", "https://www.spamhaus.org/drop/drop_v6.json",
         "spamhaus", "ip6", "high", 0.9,
         "Netblock listed by Spamhaus as hijacked or controlled by criminals."),
    Feed("feodo", "abuse.ch Feodo Tracker",
         "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "feodo", "ip", "high", 0.9,
         "Listed as a botnet command-and-control server."),
    Feed("firehol_level1", "FireHOL Level 1", "https://raw.githubusercontent.com/firehol/"
         "blocklist-ipsets/master/firehol_level1.netset", "cidr", "ip4", "medium", 0.8,
         "In FireHOL's level 1 set: aggregated attack, malware and hijacked-netblock lists "
         "suitable for blocking with few false positives."),
    Feed("et_compromised", "Emerging Threats compromised hosts",
         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "ip", "ip4",
         "medium", 0.8, "Proofpoint ET lists the address as a known compromised host."),
    Feed("binarydefense", "Binary Defense ban list", "https://www.binarydefense.com/banlist.txt",
         "ip", "ip4", "medium", 0.7, "Seen attacking Binary Defense's sensor network."),
    Feed("ipsum_3", "IPsum (on 3+ lists)",
         "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "ip", "ip4",
         "medium", 0.75, "Appears on at least three independent public block lists."),
    Feed("cins_army", "CINS Army", "https://cinsscore.com/list/ci-badguys.txt", "ip", "ip4",
         "low", 0.7, "Sentinel IPS network flagged the address for poor reputation or attacks."),
    Feed("blocklist_de", "blocklist.de", "https://lists.blocklist.de/lists/all.txt", "ip", "ip",
         "low", 0.7, "Reported by fail2ban users for attacks (SSH, mail, web logins) "
                     "within the last 48 hours."),
    Feed("greensnow", "GreenSnow", "https://blocklist.greensnow.co/greensnow.txt", "ip", "ip4",
         "low", 0.7, "Observed by GreenSnow sensors scanning or brute-forcing."),
    Feed("dshield_top", "DShield top attacking subnets", "https://feeds.dshield.org/block.txt",
         "dshield", "ip4", "low", 0.6,
         "Inside one of the 20 subnets reporting the most attacks to SANS DShield."),
    Feed("tor_exit", "Tor exit nodes", "https://check.torproject.org/torbulkexitlist", "ip", "ip",
         "info", 1.0, "Address is a Tor exit relay; traffic from it is not from its operator."),
    Feed("phishing_army", "Phishing Army",
         "https://phishing.army/download/phishing_army_blocklist.txt", "domain", "domain",
         "high", 0.8, "Domain listed as hosting phishing."),
    Feed("openphish", "OpenPhish community feed", "https://openphish.com/feed.txt", "url_host",
         "domain", "high", 0.85, "A phishing URL on this host is in OpenPhish's current feed."),
)


def _cache_path(feed: Feed) -> Path:
    return cache_dir() / f"feed-{feed.key}.txt"


async def load_feed(ctx: CollectorContext, feed: Feed) -> tuple[Any, str]:
    """Parsed feed and its fetch time, from memory, disk cache or network."""
    key = f"feed-{feed.key}"
    if key in ctx.cache:
        return ctx.cache[key]
    path = _cache_path(feed)
    if path.exists() and time.time() - path.stat().st_mtime < FEED_TTL:
        content = path.read_text(encoding="utf-8", errors="replace")
    else:
        response = await fetch(ctx.client, feed.url, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries)
        content = response.text
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    fetched = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime))
    ctx.cache[key] = (PARSERS[feed.kind](content), fetched)
    return ctx.cache[key]


def _lines(content: str):
    for line in content.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line:
            yield line


def _parse_ips(content: str) -> set[str]:
    out = set()
    for line in _lines(content):
        token = line.split()[0]
        try:
            out.add(str(ipaddress.ip_address(token)))
        except ValueError:
            continue
    return out


def _parse_cidrs(content: str) -> list[tuple[Any, dict]]:
    nets = []
    for line in _lines(content):
        try:
            nets.append((ipaddress.ip_network(line.split()[0], strict=False), {"cidr": line}))
        except ValueError:
            continue
    return nets


def _parse_spamhaus(content: str) -> list[tuple[Any, dict]]:
    nets = []
    for line in content.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("cidr"):
            nets.append((ipaddress.ip_network(row["cidr"], strict=False),
                         {"cidr": row["cidr"], "sblid": row.get("sblid")}))
    return nets


def _parse_dshield(content: str) -> list[tuple[Any, dict]]:
    nets = []
    for line in _lines(content):
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].isdigit():
            continue
        try:
            net = ipaddress.ip_network(f"{parts[0]}/{parts[2]}", strict=False)
        except ValueError:
            continue
        nets.append((net, {"cidr": str(net), "attacks": parts[3] if len(parts) > 3 else None,
                           "network_name": parts[4] if len(parts) > 4 else None}))
    return nets


def _parse_feodo(content: str) -> dict[str, dict]:
    return {row["ip_address"]: {k: row.get(k) for k in ("malware", "status", "port",
                                                          "first_seen", "last_online")}
            for row in json.loads(content) if row.get("ip_address")}


def _parse_domains(content: str) -> set[str]:
    return {line.split()[-1].lower().rstrip(".") for line in _lines(content)}


def _parse_url_hosts(content: str) -> dict[str, str]:
    hosts: dict[str, str] = {}
    for line in _lines(content):
        host = (urlsplit(line).hostname or "").lower()
        if host:
            hosts.setdefault(host, line)
    return hosts


PARSERS: dict[str, Callable[[str], Any]] = {
    "ip": _parse_ips, "cidr": _parse_cidrs, "spamhaus": _parse_spamhaus,
    "dshield": _parse_dshield, "feodo": _parse_feodo, "domain": _parse_domains,
    "url_host": _parse_url_hosts,
}


def match(feed: Feed, parsed: Any, target: EntityRef) -> dict[str, Any] | None:
    if feed.applies_to == "domain":
        name = target.value
        if feed.kind == "url_host":
            return {"example_url": parsed[name]} if name in parsed else None
        return {} if name in parsed else None
    ip = ipaddress.ip_address(target.value)
    if feed.kind == "ip":
        return {} if str(ip) in parsed else None
    if feed.kind == "feodo":
        return parsed.get(str(ip))
    for net, info in parsed:
        if net.version == ip.version and ip in net:
            return info
    return None


def applies(feed: Feed, target: EntityRef) -> bool:
    if target.type is EntityType.DOMAIN:
        return feed.applies_to == "domain"
    version = ipaddress.ip_address(target.value).version
    return feed.applies_to == "ip" or feed.applies_to == f"ip{version}"


class ThreatFeedCollector(Collector):
    name = "threatfeeds"
    title = "Threat and block lists"
    description = (f"{len(FEEDS)} public lists: botnet C2, hijacked netblocks, attackers, "
                   "scanners, Tor exits and phishing domains.")
    accepts = frozenset({EntityType.IP, EntityType.DOMAIN})
    sources = ("spamhaus.org", "abuse.ch", "FireHOL", "Emerging Threats", "Binary Defense",
               "IPsum", "CINS Army", "blocklist.de", "GreenSnow", "SANS DShield", "Tor Project",
               "Phishing Army", "OpenPhish (lists are downloaded; your targets are not sent)")

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        if target.type is EntityType.IP and not ipaddress.ip_address(target.value).is_global:
            return found
        failures, checked = [], []
        for feed in FEEDS:
            if not applies(feed, target):
                continue
            try:
                parsed, fetched = await load_feed(ctx, feed)
            except FetchError as exc:
                failures.append(f"{feed.title}: {exc}")
                continue
            checked.append(feed.title)
            hit = match(feed, parsed, target)
            if hit is None:
                continue
            evidence = found.add_evidence(
                f"{feed.url} (list fetched {fetched})",
                json.dumps({"feed": feed.title, "entry": hit, "target": target.value}, indent=2),
                "application/json")
            listing = found.entity(EntityType.INDICATOR, feed.title, kind="threat list",
                                   url=feed.url)
            found.observe(target, "threat.listed",
                          {"feed": feed.title, "severity": feed.severity,
                           "meaning": feed.meaning, **hit},
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
            # "Checked and not listed" is a fact worth keeping, distinct from
            # "not checked".
            found.observe(target, "threat.not_listed", checked,
                          method="Match against downloaded lists", confidence=1.0)
        return found
