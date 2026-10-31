import json

import httpx
import pytest
import respx

from conftest import FakeResolver, StaticCollector
from strxeye.collectors.base import Findings
from strxeye.collectors.mail_dnsbl import DnsblCollector, MailSecurityCollector
from strxeye.collectors.malware_intel import (
    AbuseChCollector,
    AbuseIpdbCollector,
    MalpediaCollector,
)
from strxeye.collectors.network_intel import (
    GreyNoiseCollector,
    HackerTargetCollector,
    PeeringDbCollector,
    RipeStatCollector,
    RobtexCollector,
    UrlscanCollector,
)
from strxeye.config import Settings
from strxeye.engine import Engine, RunOptions
from strxeye.models import CollectionStatus, EntityRef, EntityType, RelationType
from strxeye.net import FetchError
from strxeye.targets import parse_target

IP = EntityRef(type=EntityType.IP, value="45.155.205.20")
DOMAIN = EntityRef(type=EntityType.DOMAIN, value="example.com")
ASN = EntityRef(type=EntityType.ASN, value="AS64500")
RIPE = "https://stat.ripe.net/data/{}/data.json"


def kinds(found):
    out = {}
    for o in found.observations:
        out.setdefault(o.kind, []).append(o.value)
    return out


def test_malware_target():
    assert parse_target("malware:QakBot") == EntityRef(type=EntityType.MALWARE, value="QakBot")


@respx.mock
async def test_ripestat_ip(make_ctx):
    respx.get(RIPE.format("prefix-overview")).mock(return_value=httpx.Response(200, json={
        "data": {"resource": "45.155.205.0/24", "announced": True,
                 "asns": [{"asn": 64500, "holder": "EXAMPLE-AS"}]}}))
    respx.get(RIPE.format("rpki-validation")).mock(return_value=httpx.Response(
        200, json={"data": {"status": "invalid"}}))
    respx.get(RIPE.format("abuse-contact-finder")).mock(return_value=httpx.Response(
        200, json={"data": {"abuse_contacts": ["abuse@example.net"]}}))
    respx.get(RIPE.format("maxmind-geo-lite")).mock(return_value=httpx.Response(200, json={
        "data": {"located_resources": [{"locations": [{"country": "NL", "city": "Amsterdam"}]}]}}))
    found = await RipeStatCollector().collect(IP, make_ctx())
    k = kinds(found)
    assert k["routing.rpki"][0]["status"] == "invalid"
    assert k["network.abuse_contact"] == ["abuse@example.net"]
    geo = next(o for o in found.observations if o.kind == "geo.estimate")
    assert geo.value == {"country": "NL", "city": "Amsterdam"} and geo.confidence == 0.5
    rels = {(r.source.value, r.type, r.target.value) for r in found.relationships}
    assert ("45.155.205.0/24", RelationType.ANNOUNCED_BY, "AS64500") in rels


@respx.mock
async def test_ripestat_partial_when_side_calls_fail(make_ctx, monkeypatch):
    monkeypatch.setattr("strxeye.net._backoff", lambda a: 0)
    respx.get(RIPE.format("prefix-overview")).mock(return_value=httpx.Response(200, json={
        "data": {"resource": "45.155.205.0/24", "announced": True, "asns": []}}))
    respx.get(url__regex=r"stat\.ripe\.net/data/(abuse|maxmind)").mock(
        return_value=httpx.Response(503))
    found = await RipeStatCollector().collect(IP, make_ctx())
    assert found.status is CollectionStatus.PARTIAL


@respx.mock
async def test_peeringdb(make_ctx):
    respx.get("https://www.peeringdb.com/api/net").mock(return_value=httpx.Response(200, json={
        "data": [{"name": "Example Net", "website": "https://example.net",
                  "info_type": "Content", "policy_general": "Open"}]}))
    found = await PeeringDbCollector().collect(ASN, make_ctx())
    assert kinds(found)["peeringdb.network"][0]["info_type"] == "Content"
    assert found.entities[ASN].attributes["network_type"] == "Content"


@respx.mock
async def test_greynoise_not_observed_is_data(make_ctx):
    respx.get("https://api.greynoise.io/v3/community/45.155.205.20").mock(
        return_value=httpx.Response(404, json={"ip": "45.155.205.20", "noise": False,
                                               "riot": False,
                                               "message": "IP not observed scanning."}))
    found = await GreyNoiseCollector().collect(IP, make_ctx())
    assert kinds(found)["greynoise.status"][0]["noise"] is False


@respx.mock
async def test_greynoise_rate_limit_is_error(make_ctx):
    respx.get("https://api.greynoise.io/v3/community/45.155.205.20").mock(
        return_value=httpx.Response(429, json={"message": "rate limited"}))
    with pytest.raises(FetchError):
        await GreyNoiseCollector().collect(IP, make_ctx())


@respx.mock
async def test_robtex(make_ctx):
    respx.get("https://freeapi.robtex.com/ipquery/45.155.205.20").mock(
        return_value=httpx.Response(200, json={"status": "ok", "bgproute": "45.155.205.0/24",
                                               "as": 64500, "pas": [{"o": "shop.example"}]}))
    found = await RobtexCollector().collect(IP, make_ctx())
    assert ("shop.example", RelationType.RESOLVES_TO) in {
        (r.source.value, r.type) for r in found.relationships}


@respx.mock
async def test_hackertarget_hostsearch_and_quota(make_ctx):
    route = respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(
            200, text="www.example.com,93.184.215.14\nexample.com,93.184.215.14"))
    found = await HackerTargetCollector().collect(DOMAIN, make_ctx())
    assert kinds(found)["hackertarget.subdomain"] == ["www.example.com"]
    route.mock(return_value=httpx.Response(200, text="API count exceeded - Increase Quota"))
    with pytest.raises(FetchError, match="count exceeded"):
        await HackerTargetCollector().collect(DOMAIN, make_ctx())


@respx.mock
async def test_urlscan(make_ctx):
    respx.get("https://urlscan.io/api/v1/search/").mock(return_value=httpx.Response(200, json={
        "total": 1, "results": [{"task": {"time": "2026-10-01T00:00:00Z"},
                                 "page": {"url": "https://example.com/login", "ip": "93.184.215.14",
                                          "title": "Login", "status": "200"},
                                 "result": "https://urlscan.io/api/v1/result/abc/"}]}))
    found = await UrlscanCollector().collect(DOMAIN, make_ctx())
    assert kinds(found)["urlscan.scan"][0]["title"] == "Login"
    assert any(e.type is EntityType.URL for e in found.entities.values())


async def test_mail_security(make_ctx):
    resolver = FakeResolver({
        ("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=1"'],
        ("selector1._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; p=MIGf"'],
    })
    found = await MailSecurityCollector().collect(DOMAIN, make_ctx(resolver))
    k = kinds(found)
    assert k["mail.mta_sts"] == ["v=STSv1; id=1"]
    assert k["mail.dkim_selector"] == ["selector1"]
    assert "mail.bimi.missing" in k and "mail.tls_rpt.missing" in k


async def test_dnsbl_listing_and_refusal(make_ctx):
    resolver = FakeResolver({
        ("20.205.155.45.bl.spamcop.net", "A"): ["127.0.0.2"],
        # Spamhaus refuses queries from large public resolvers like this:
        ("20.205.155.45.zen.spamhaus.org", "A"): ["127.255.255.254"],
    }, nxdomain={f"20.205.155.45.{z}" for z in ("b.barracudacentral.org", "dnsbl.dronebl.org",
                                                 "psbl.surriel.com", "all.s5h.net")})
    found = await DnsblCollector().collect(IP, make_ctx(resolver))
    listed = [o.value["feed"] for o in found.observations if o.kind == "threat.listed"]
    assert listed == ["SpamCop"]
    assert any("Spamhaus ZEN" in n for n in found.notes)


MALPEDIA = "https://malpedia.caad.fkie.fraunhofer.de/api"


@respx.mock
async def test_malpedia_profile_and_attribution(make_ctx):
    respx.get(f"{MALPEDIA}/find/family/QakBot").mock(return_value=httpx.Response(200, json=[
        {"name": "win.qakbot", "alt_names": ["Qbot"]}]))
    respx.get(f"{MALPEDIA}/get/family/win.qakbot").mock(return_value=httpx.Response(200, json={
        "common_name": "QakBot", "alt_names": ["Qbot"], "attribution": ["GOLD LAGOON"],
        "description": "Banking trojan.", "urls": ["https://a", "https://b"]}))
    target = EntityRef(type=EntityType.MALWARE, value="QakBot")
    found = await MalpediaCollector().collect(target, make_ctx())
    profile = kinds(found)["malware.profile"][0]
    assert profile["malpedia_id"] == "win.qakbot" and profile["references"] == 2
    rel = next(r for r in found.relationships if r.type is RelationType.ATTRIBUTED_TO)
    assert rel.target == EntityRef(type=EntityType.THREAT_ACTOR, value="GOLD LAGOON")
    assert rel.confidence == 0.6


@respx.mock
async def test_malpedia_unknown_family(make_ctx):
    respx.get(f"{MALPEDIA}/find/family/nothing").mock(return_value=httpx.Response(200, json=[]))
    found = await MalpediaCollector().collect(
        EntityRef(type=EntityType.MALWARE, value="nothing"), make_ctx())
    assert found.status is CollectionStatus.NO_DATA


def keyed(make_ctx, name="k"):
    ctx = make_ctx()
    ctx.secret = lambda key: name
    return ctx


@respx.mock
async def test_abusech_ioc_and_urlhaus(make_ctx):
    tf = respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(return_value=httpx.Response(
        200, json={"query_status": "ok", "data": [{"ioc": "45.155.205.20:443",
                                                    "ioc_type": "ip:port",
                                                    "malware": "win.cobalt_strike",
                                                    "malware_printable": "Cobalt Strike",
                                                    "confidence_level": 100}]}))
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(return_value=httpx.Response(
        200, json={"query_status": "ok", "url_count": 1,
                   "urls": [{"url": "http://45.155.205.20/x.exe", "url_status": "online",
                             "threat": "malware_download"}]}))
    found = await AbuseChCollector().collect(IP, keyed(make_ctx, "secret-key"))
    assert tf.calls[0].request.headers["Auth-Key"] == "secret-key"
    assert json.loads(tf.calls[0].request.content)["search_term"] == "45.155.205.20"
    assert any(e.type is EntityType.MALWARE and e.value == "Cobalt Strike"
               for e in found.entities.values())
    assert kinds(found)["urlhaus.host"][0]["online"] == 1


@respx.mock
async def test_abusech_family_infrastructure(make_ctx):
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(return_value=httpx.Response(
        200, json={"query_status": "ok", "data": [
            {"ioc": "c2.bad.example", "ioc_type": "domain", "confidence_level": 75},
            {"ioc": "198.51.100.9:8443", "ioc_type": "ip:port", "confidence_level": 100}]}))
    family = EntityRef(type=EntityType.MALWARE, value="win.emotet")
    found = await AbuseChCollector().collect(family, keyed(make_ctx))
    linked = {(r.source.value, r.confidence) for r in found.relationships
              if r.target == family}
    assert linked == {("c2.bad.example", 0.75), ("198.51.100.9", 1.0)}


@respx.mock
async def test_abuseipdb(make_ctx):
    route = respx.get("https://api.abuseipdb.com/api/v2/check").mock(return_value=httpx.Response(
        200, json={"data": {"abuseConfidenceScore": 87, "totalReports": 40, "isTor": False}}))
    found = await AbuseIpdbCollector().collect(IP, keyed(make_ctx, "abuse-key"))
    assert route.calls[0].request.headers["Key"] == "abuse-key"
    assert kinds(found)["abuseipdb.report"][0]["abuseConfidenceScore"] == 87


async def test_discovered_malware_is_expanded_to_its_profile():
    class Feed(StaticCollector):
        async def collect(self, target, ctx):
            found = Findings(self.name)
            family = found.entity(EntityType.MALWARE, "Emotet")
            found.relate(target, RelationType.ASSOCIATED_WITH, family)
            return found

    class Profile(StaticCollector):
        async def collect(self, target, ctx):
            found = Findings(self.name)
            found.observe(target, "malware.profile", {"common_name": target.value}, method="t")
            return found

    engine = Engine(Settings(), collectors={
        "feed": Feed("feed", accepts={EntityType.IP}),
        "malpedia": Profile("malpedia", accepts={EntityType.MALWARE}),
        "abusech": AbuseChCollector(),  # needs a key; must be skipped silently
    }, secret=lambda name: None)
    report = await engine.run(IP, RunOptions(expand=True))
    ran = sorted((r.collector, r.target.value) for r in report.results)
    assert ran == [("feed", "45.155.205.20"), ("malpedia", "Emotet")]
