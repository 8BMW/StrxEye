"""Network and hosting context from public, keyless APIs: RIPEstat,
PeeringDB, GreyNoise Community, Robtex, HackerTarget and urlscan.io."""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, fetch
from ..targets import TargetError, normalize_domain, normalize_ip, normalize_url
from .base import Collector, CollectorContext, Findings


async def get_json(ctx: CollectorContext, url: str, params: dict | None = None,
                   allow: tuple[int, ...] = ()) -> tuple[Any, str, str, int]:
    response = await fetch(ctx.client, url, params=params, limiter=ctx.limiter,
                           retries=ctx.settings.network.retries, allow_statuses=allow)
    try:
        data = response.json()
    except json.JSONDecodeError:
        raise FetchError(f"{response.request.url.host} did not return JSON") from None
    return data, response.text, str(response.request.url), response.status_code


def _public_ip(target: EntityRef) -> bool:
    return target.type is not EntityType.IP or ipaddress.ip_address(target.value).is_global


class RipeStatCollector(Collector):
    name = "ripestat"
    title = "Routing, RPKI and abuse contact (RIPEstat)"
    description = ("Announced prefix and origin AS, RPKI validity, the network's abuse "
                   "contact and a geolocation estimate.")
    accepts = frozenset({EntityType.IP, EntityType.ASN})
    sources = ("stat.ripe.net",)
    BASE = "https://stat.ripe.net/data/{call}/data.json"

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        if not _public_ip(target):
            return found
        resource = target.value[2:] if target.type is EntityType.ASN else target.value
        if target.type is EntityType.ASN:
            await self._asn(found, target, ctx, resource)
            return found

        data, raw, url, _ = await get_json(ctx, self.BASE.format(call="prefix-overview"),
                                           {"resource": resource})
        overview = data.get("data", {})
        ev = found.add_evidence(url, raw, "application/json")
        obs = dict(method="RIPEstat prefix-overview", evidence_id=ev, source_url=url)
        prefix = overview.get("resource")
        origins = [a for a in overview.get("asns", []) if a.get("asn")]
        found.observe(target, "routing.announced", bool(overview.get("announced")), **obs)
        if prefix and "/" in str(prefix):
            net = found.entity(EntityType.NETWORK, str(ipaddress.ip_network(prefix, strict=False)))
            found.relate(target, RelationType.BELONGS_TO_NETWORK, net, evidence_id=ev)
            for a in origins:
                asn = found.entity(EntityType.ASN, f"AS{a['asn']}", name=a.get("holder"))
                found.relate(net, RelationType.ANNOUNCED_BY, asn, evidence_id=ev)

        # RPKI tells whether the announcing AS is authorised for the prefix;
        # "invalid" can indicate a hijack or a misconfiguration.
        if prefix and origins:
            try:
                data, raw, url, _ = await get_json(
                    ctx, self.BASE.format(call="rpki-validation"),
                    {"resource": str(origins[0]["asn"]), "prefix": prefix})
                status = data.get("data", {}).get("status")
                if status:
                    ev = found.add_evidence(url, raw, "application/json")
                    found.observe(target, "routing.rpki", {"status": status,
                                                           "origin": f"AS{origins[0]['asn']}",
                                                           "prefix": prefix},
                                  method="RIPEstat rpki-validation", evidence_id=ev,
                                  source_url=url)
            except FetchError as exc:
                found.partial = True
                found.notes.append(f"RPKI check failed: {exc}")

        for call, kind, method in (("abuse-contact-finder", "network.abuse_contact",
                                    "RIPEstat abuse-contact-finder"),
                                   ("maxmind-geo-lite", "geo.estimate",
                                    "RIPEstat maxmind-geo-lite (MaxMind GeoLite2)")):
            try:
                data, raw, url, _ = await get_json(ctx, self.BASE.format(call=call),
                                                   {"resource": resource})
            except FetchError as exc:
                found.partial = True
                found.notes.append(f"{call} failed: {exc}")
                continue
            ev = found.add_evidence(url, raw, "application/json")
            d = data.get("data", {})
            if call == "abuse-contact-finder":
                # Abuse mailboxes are role accounts published for reporting
                # abuse, not personal contacts.
                for contact in d.get("abuse_contacts", [])[:5]:
                    found.observe(target, kind, contact, method=method, evidence_id=ev,
                                  source_url=url)
            else:
                for res in d.get("located_resources", []):
                    for loc in res.get("locations", []):
                        if loc.get("country") and loc["country"] != "?":
                            found.observe(target, kind,
                                          {"country": loc["country"],
                                           "city": loc.get("city") or None},
                                          method=method, evidence_id=ev, source_url=url,
                                          confidence=0.5)
        return found

    async def _asn(self, found, target, ctx, number: str) -> None:
        data, raw, url, _ = await get_json(ctx, self.BASE.format(call="as-overview"),
                                           {"resource": number})
        d = data.get("data", {})
        ev = found.add_evidence(url, raw, "application/json")
        obs = dict(method="RIPEstat as-overview", evidence_id=ev, source_url=url)
        if d.get("holder"):
            found.observe(target, "routing.as_holder", d["holder"], **obs)
        found.observe(target, "routing.announced", bool(d.get("announced")), **obs)


class PeeringDbCollector(Collector):
    name = "peeringdb"
    title = "Network profile (PeeringDB)"
    description = "What kind of network an AS is (hosting, ISP, content), its website and policy."
    accepts = frozenset({EntityType.ASN})
    sources = ("peeringdb.com",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        data, raw, url, _ = await get_json(ctx, "https://www.peeringdb.com/api/net",
                                           {"asn": target.value[2:]})
        rows = data.get("data") or []
        if not rows:
            return found
        net = rows[0]
        ev = found.add_evidence(url, raw, "application/json")
        obs = dict(method="PeeringDB network lookup", evidence_id=ev, source_url=url)
        profile = {k: net.get(k) for k in ("name", "website", "info_type", "info_traffic",
                                           "info_scope", "policy_general", "info_prefixes4")}
        found.observe(target, "peeringdb.network", profile, **obs)
        if net.get("info_type"):
            found.entity(EntityType.ASN, target.value, network_type=net["info_type"])
        if net.get("name"):
            org = found.entity(EntityType.ORGANIZATION, net["name"], website=net.get("website"))
            found.relate(target, RelationType.OPERATED_BY, org, evidence_id=ev, confidence=0.9)
        return found


class GreyNoiseCollector(Collector):
    name = "greynoise"
    title = "Internet scanner check (GreyNoise Community)"
    description = ("Whether the IP mass-scans the internet (noise) or is a known benign "
                   "business service (RIOT), with GreyNoise's classification.")
    accepts = frozenset({EntityType.IP})
    sources = ("api.greynoise.io",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        if not _public_ip(target) or ":" in target.value:
            return found  # the community API covers IPv4 only
        # 404 is a valid answer: "not observed scanning the internet".
        data, raw, url, _ = await get_json(
            ctx, f"https://api.greynoise.io/v3/community/{target.value}", allow=(404,))
        if "noise" not in data:
            raise FetchError(data.get("message") or "unexpected GreyNoise response")
        ev = found.add_evidence(url, raw, "application/json")
        value = {k: data.get(k) for k in ("noise", "riot", "classification", "name",
                                          "last_seen", "message")}
        found.observe(target, "greynoise.status", value, method="GreyNoise Community API",
                      evidence_id=ev, source_url=data.get("link") or url)
        return found


class RobtexCollector(Collector):
    name = "robtex"
    title = "Passive DNS and routing (Robtex)"
    description = "Domains Robtex has seen pointing at the IP, and its BGP route."
    accepts = frozenset({EntityType.IP})
    sources = ("freeapi.robtex.com",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        if not _public_ip(target) or ":" in target.value:
            return found
        ctx.limiter.set_interval("freeapi.robtex.com", 1.0)
        data, raw, url, _ = await get_json(
            ctx, f"https://freeapi.robtex.com/ipquery/{target.value}")
        if data.get("status") != "ok":
            raise FetchError(f"Robtex: {data.get('status', 'no status')}")
        ev = found.add_evidence(url, raw, "application/json")
        obs = dict(method="Robtex IP query", evidence_id=ev, source_url=url)
        if data.get("bgproute"):
            found.observe(target, "robtex.route", {"route": data["bgproute"],
                                                   "as": data.get("as"),
                                                   "as_name": data.get("asname")}, **obs)
        for row in (data.get("pas") or [])[:100]:
            try:
                host = found.entity(EntityType.DOMAIN, normalize_domain(row.get("o", "")))
            except TargetError:
                continue
            found.relate(host, RelationType.RESOLVES_TO, target, evidence_id=ev, confidence=0.7)
            found.observe(target, "robtex.passive_domain", host.value, **obs, confidence=0.7)
        return found


class HackerTargetCollector(Collector):
    name = "hackertarget"
    title = "Host search and reverse IP (HackerTarget)"
    description = "Subdomains with their IPs for a domain; other domains on the same IP."
    accepts = frozenset({EntityType.DOMAIN, EntityType.IP})
    sources = ("api.hackertarget.com (free tier: 50 queries a day)",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        if not _public_ip(target):
            return found
        endpoint = "hostsearch" if target.type is EntityType.DOMAIN else "reverseiplookup"
        response = await fetch(ctx.client, f"https://api.hackertarget.com/{endpoint}/",
                               params={"q": target.value}, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries)
        text = response.text.strip()
        lowered = text.lower()
        if "api count exceeded" in lowered or lowered.startswith("error"):
            raise FetchError(f"HackerTarget: {text[:120]}")
        if not text or "no records" in lowered or "no dns a records" in lowered:
            return found
        ev = found.add_evidence(str(response.request.url), text)
        method = f"HackerTarget {endpoint}"
        for line in text.splitlines()[:500]:
            parts = [p.strip() for p in line.split(",")]
            try:
                host = normalize_domain(parts[0])
            except TargetError:
                continue
            if target.type is EntityType.DOMAIN:
                sub = found.entity(EntityType.DOMAIN, host)
                if host != target.value and host.endswith("." + target.value):
                    found.relate(sub, RelationType.SUBDOMAIN_OF, target, evidence_id=ev,
                                 confidence=0.8)
                    found.observe(target, "hackertarget.subdomain", host, method=method,
                                  evidence_id=ev, confidence=0.8)
                if len(parts) > 1:
                    try:
                        ip = found.entity(EntityType.IP, normalize_ip(parts[1]))
                        found.relate(sub, RelationType.RESOLVES_TO, ip, evidence_id=ev,
                                     confidence=0.7)
                    except TargetError:
                        pass
            else:
                other = found.entity(EntityType.DOMAIN, host)
                found.relate(other, RelationType.RESOLVES_TO, target, evidence_id=ev,
                             confidence=0.7)
                found.observe(target, "hackertarget.cohosted_domain", host, method=method,
                              evidence_id=ev, confidence=0.7)
        return found


class UrlscanCollector(Collector):
    name = "urlscan"
    title = "Public scans (urlscan.io)"
    description = ("Recent public urlscan.io scans of the domain or IP: pages, servers, "
                   "page titles and the IPs that served them.")
    accepts = frozenset({EntityType.DOMAIN, EntityType.IP})
    sources = ("urlscan.io",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        if not _public_ip(target):
            return found
        field = "domain" if target.type is EntityType.DOMAIN else "ip"
        ctx.limiter.set_interval("urlscan.io", 2.0)
        data, raw, url, _ = await get_json(ctx, "https://urlscan.io/api/v1/search/",
                                           {"q": f'{field}:"{target.value}"', "size": "20"})
        results = data.get("results") or []
        if not results:
            return found
        ev = found.add_evidence(url, raw, "application/json")
        found.observe(target, "urlscan.total", data.get("total", len(results)),
                      method="urlscan.io search", evidence_id=ev, source_url=url)
        for r in results:
            page, task = r.get("page", {}), r.get("task", {})
            summary = {"time": task.get("time"), "url": page.get("url"), "ip": page.get("ip"),
                       "server": page.get("server"), "title": page.get("title"),
                       "status": page.get("status"), "report": r.get("result")}
            found.observe(target, "urlscan.scan", summary, method="urlscan.io search",
                          evidence_id=ev, source_url=r.get("result") or url, confidence=0.9)
            try:
                if page.get("url"):
                    ref = found.entity(EntityType.URL, normalize_url(page["url"]),
                                       title=page.get("title"))
                    found.relate(target, RelationType.ASSOCIATED_WITH, ref, evidence_id=ev,
                                 confidence=0.8)
                if target.type is EntityType.DOMAIN and page.get("ip"):
                    ip = found.entity(EntityType.IP, normalize_ip(page["ip"]))
                    found.relate(target, RelationType.RESOLVES_TO, ip, evidence_id=ev,
                                 confidence=0.7)
            except TargetError:
                continue
        return found
