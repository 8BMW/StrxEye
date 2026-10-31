import json

import httpx
import pytest
import respx

from conftest import StaticCollector
from strxeye.collectors import threatfeeds
from strxeye.collectors.certspotter import CertSpotterCollector
from strxeye.collectors.gleif import GleifCollector
from strxeye.collectors.internetdb import InternetDbCollector
from strxeye.collectors.passive_dns import PassiveDnsCollector
from strxeye.collectors.reputation import OtxCollector, VirusTotalCollector
from strxeye.collectors.threatfeeds import ThreatFeedCollector
from strxeye.config import Settings
from strxeye.engine import Engine, EngineError, RunOptions
from strxeye.models import CollectionStatus, EntityRef, EntityType, RelationType
from strxeye.net import FetchError
from strxeye.targets import TargetError, parse_target

IP = EntityRef(type=EntityType.IP, value="45.155.205.20")
DOMAIN = EntityRef(type=EntityType.DOMAIN, value="example.com")
HASH = EntityRef(type=EntityType.HASH, value="a" * 64)


def test_org_and_hash_targets():
    assert parse_target("org:  Example   Corp ") == EntityRef(type=EntityType.ORGANIZATION,
                                                            value="Example Corp")
    assert parse_target("ABC" * 1 + "d" * 29, EntityType.HASH).value == "abc" + "d" * 29
    with pytest.raises(TargetError):
        parse_target("xyz", EntityType.HASH)


@respx.mock
async def test_internetdb(make_ctx):
    respx.get("https://internetdb.shodan.io/45.155.205.20").mock(return_value=httpx.Response(
        200, json={"ip": IP.value, "ports": [443, 22], "hostnames": ["host.example.com"],
                   "cpes": ["cpe:/a:openbsd:openssh"], "tags": ["cloud"],
                   "vulns": ["cve-2023-48795"]}))
    found = await InternetDbCollector().collect(IP, make_ctx())
    kinds = {o.kind: o for o in found.observations}
    assert kinds["scan.open_ports"].value == [22, 443]
    vuln = kinds["scan.possible_vulnerability"]
    assert vuln.value == "CVE-2023-48795" and vuln.confidence < 0.5
    assert any(r.type is RelationType.USES_TECHNOLOGY for r in found.relationships)


@respx.mock
async def test_internetdb_unknown_ip_is_no_data(make_ctx):
    respx.get("https://internetdb.shodan.io/45.155.205.20").mock(
        return_value=httpx.Response(404, json={"detail": "No information available"}))
    assert (await InternetDbCollector().collect(IP, make_ctx())).status is CollectionStatus.NO_DATA


@respx.mock
async def test_certspotter_uses_sha256_ids(make_ctx):
    respx.get("https://api.certspotter.com/v1/issuances").mock(return_value=httpx.Response(
        200, json=[{"cert_sha256": "ab" * 32, "dns_names": ["example.com", "*.api.example.com"],
                    "issuer": {"name": "C=US, O=Let's Encrypt, CN=R11"},
                    "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z"}]))
    found = await CertSpotterCollector().collect(DOMAIN, make_ctx())
    certs = [e.value for e in found.entities.values() if e.type is EntityType.CERTIFICATE]
    assert certs == ["sha256:" + "ab" * 32]  # same ID format as the tls collector
    assert {o.value for o in found.observations if o.kind == "ct.subdomain"} == {"api.example.com"}


@respx.mock
async def test_passive_dns(make_ctx):
    respx.get("https://api.mnemonic.no/pdns/v3/example.com").mock(return_value=httpx.Response(
        200, json={"count": 2, "data": [
            {"rrtype": "a", "query": "example.com", "answer": "192.0.2.10",
             "firstSeenTimestamp": 1600000000000, "lastSeenTimestamp": 1700000000000, "times": 4},
            {"rrtype": "cname", "query": "www.example.com", "answer": "example.com"},
            {"rrtype": "a", "query": "bad name!", "answer": "192.0.2.11"}]}))
    found = await PassiveDnsCollector().collect(DOMAIN, make_ctx())
    rels = {(r.source.value, r.type, r.target.value, r.confidence) for r in found.relationships}
    assert ("example.com", RelationType.RESOLVES_TO, "192.0.2.10", 0.7) in rels
    assert ("www.example.com", RelationType.ALIAS_OF, "example.com", 0.7) in rels
    first = next(o for o in found.observations if o.value.get("answer") == "192.0.2.10")
    assert first.value["first_seen"].startswith("2020-09-13")


@pytest.fixture
def feeds(monkeypatch, tmp_path):
    monkeypatch.setattr(threatfeeds, "cache_dir", lambda: tmp_path)
    # A router of its own: routes added to respx's global router would leak
    # into later tests.
    with respx.mock(assert_all_called=False) as router:
        router.get("https://www.spamhaus.org/drop/drop_v4.json").mock(
            return_value=httpx.Response(
                200, text='{"cidr":"45.155.205.0/24","sblid":"SBL1","rir":"ripe"}\n'
                          '{"type":"metadata"}\n'))
        router.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json").mock(
            return_value=httpx.Response(200, json=[{"ip_address": "5.188.10.5",
                                                    "malware": "QakBot", "status": "online",
                                                    "port": 443}]))
        tor = router.get("https://check.torproject.org/torbulkexitlist").mock(
            return_value=httpx.Response(200, text="192.0.2.99\n"))
        yield tor


async def test_threatfeeds_hits_and_cache(make_ctx, feeds):
    found = await ThreatFeedCollector().collect(IP, make_ctx())
    listed = [o.value for o in found.observations if o.kind == "threat.listed"]
    assert listed[0]["feed"] == "Spamhaus DROP (IPv4)" and listed[0]["sblid"] == "SBL1"

    botnet = EntityRef(type=EntityType.IP, value="5.188.10.5")
    found = await ThreatFeedCollector().collect(botnet, make_ctx())
    assert any(e.type is EntityType.MALWARE and e.value == "QakBot"
               for e in found.entities.values())
    # Second and third lookups came from the disk cache, not the network.
    assert feeds.call_count == 1


async def test_threatfeeds_records_clean_result(make_ctx, feeds):
    clean = EntityRef(type=EntityType.IP, value="8.8.4.4")
    found = await ThreatFeedCollector().collect(clean, make_ctx())
    assert [o.kind for o in found.observations] == ["threat.not_listed"]


@respx.mock
async def test_threatfeeds_all_down_is_error(make_ctx, monkeypatch, tmp_path):
    monkeypatch.setattr(threatfeeds, "cache_dir", lambda: tmp_path)
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(503))
    monkeypatch.setattr("strxeye.net._backoff", lambda a: 0)
    with pytest.raises(FetchError):
        await ThreatFeedCollector().collect(IP, make_ctx())


OTX_BODY = {"indicator": "example.com", "reputation": 0, "validation": [],
            "pulse_info": {"count": 1, "pulses": [{"id": "p1", "name": "Campaign X",
                                                   "created": "2026-01-02T00:00:00",
                                                   "tags": ["phishing"],
                                                   "malware_families": [
                                                       {"display_name": "Agent Tesla"}],
                                                   "adversary": ""}]}}


@respx.mock
async def test_otx(make_ctx):
    route = respx.get("https://otx.alienvault.com/api/v1/indicators/domain/example.com/general"
                      ).mock(return_value=httpx.Response(200, json=OTX_BODY))
    ctx = make_ctx()
    ctx.secret = lambda name: "otx-key" if name == "otx" else None
    found = await OtxCollector().collect(DOMAIN, ctx)
    assert route.calls[0].request.headers["X-OTX-API-KEY"] == "otx-key"
    pulse = next(o for o in found.observations if o.kind == "otx.pulse")
    assert pulse.value["name"] == "Campaign X" and pulse.confidence == 0.5
    assert any(e.type is EntityType.MALWARE and e.value == "Agent Tesla"
               for e in found.entities.values())


@respx.mock
async def test_otx_ipv6_and_hash_paths(make_ctx):
    v6 = respx.get("https://otx.alienvault.com/api/v1/indicators/IPv6/2001:db8::1/general").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}}))
    await OtxCollector().collect(EntityRef(type=EntityType.IP, value="2001:db8::1"), make_ctx())
    assert v6.called


@respx.mock
async def test_virustotal(make_ctx):
    route = respx.get(f"https://www.virustotal.com/api/v3/files/{'a' * 64}").mock(
        return_value=httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 40, "harmless": 0},
            "meaningful_name": "invoice.exe",
            "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"}}}}))
    ctx = make_ctx()
    ctx.secret = lambda name: "vt-key"
    found = await VirusTotalCollector().collect(HASH, ctx)
    assert route.calls[0].request.headers["x-apikey"] == "vt-key"
    kinds = {o.kind: o.value for o in found.observations}
    assert kinds["vt.analysis_stats"]["malicious"] == 40
    assert kinds["vt.threat_label"] == "trojan.emotet"


async def test_keyed_collector_is_skipped_without_key():
    e = Engine(Settings(), collectors={"dns": StaticCollector("dns"),
                                       "virustotal": VirusTotalCollector()},
               secret=lambda name: None)
    assert [c.name for c in e.select(DOMAIN, RunOptions())] == ["dns"]
    with pytest.raises(EngineError, match="strxeye keys set virustotal"):
        e.select(DOMAIN, RunOptions(collectors=["virustotal"]))
    with_key = Engine(Settings(), collectors={"virustotal": VirusTotalCollector()},
                      secret=lambda name: "k")
    assert len(with_key.select(DOMAIN, RunOptions())) == 1


def gleif_record(lei, name, city="Dover"):
    return {"attributes": {"lei": lei, "entity": {
        "legalName": {"name": name}, "jurisdiction": "US-DE", "status": "ACTIVE",
        "category": "GENERAL",
        "legalAddress": {"addressLines": ["1 Secret Street"], "city": city, "country": "US"},
        "headquartersAddress": {"addressLines": ["2 Other Street"], "city": city,
                                "country": "US"}},
        "registration": {"status": "ISSUED", "initialRegistrationDate": "2020-01-01T00:00:00Z"}}}


@respx.mock
async def test_gleif_candidates_and_parent(make_ctx):
    respx.get("https://api.gleif.org/api/v1/lei-records").mock(return_value=httpx.Response(
        200, json={"meta": {"pagination": {"total": 1}},
                   "data": [gleif_record("LEI1", "EXAMPLE SUB LTD")]}))
    respx.get("https://api.gleif.org/api/v1/lei-records/LEI1/direct-parent").mock(
        return_value=httpx.Response(200, json={"data": gleif_record("LEI0", "EXAMPLE HOLDINGS")}))
    target = EntityRef(type=EntityType.ORGANIZATION, value="Example")
    found = await GleifCollector().collect(target, make_ctx())
    rels = {(r.source.value, r.type, r.target.value) for r in found.relationships}
    assert ("Example", RelationType.ASSOCIATED_WITH, "EXAMPLE SUB LTD") in rels
    assert ("EXAMPLE SUB LTD", RelationType.OPERATED_BY, "EXAMPLE HOLDINGS") in rels
    # Street addresses are never stored.
    dumped = json.dumps([e.model_dump() for e in found.entities.values()])
    dumped += "".join(e.content for e in found.evidence.values())
    assert "Secret Street" not in dumped and "Other Street" not in dumped
