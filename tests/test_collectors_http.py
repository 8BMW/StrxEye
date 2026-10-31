import json

import httpx
import pytest
import respx

from strxeye.collectors.crtsh import CrtShCollector, issuer_org
from strxeye.collectors.rdap import RdapCollector, network_cidr
from strxeye.collectors.wayback import WaybackCollector
from strxeye.collectors.website import HttpCollector
from strxeye.config import Settings
from strxeye.models import EntityRef, EntityType, RelationType
from strxeye.net import FetchError, UnsafeTargetError

DOMAIN = EntityRef(type=EntityType.DOMAIN, value="example.com")

BOOTSTRAP_DNS = {"services": [[["com", "net"], ["http://insecure.test/", "https://rdap.test/com/"]]]}
BOOTSTRAP_V4 = {"services": [[["1.0.0.0/8"], ["https://rdap.apnic.test/"]],
                             [["1.1.0.0/16"], ["https://rdap.specific.test/"]]]}


def vcard(*props):
    return ["vcard", [["version", {}, "text", "4.0"], *props]]


DOMAIN_RDAP = {
    "ldhName": "EXAMPLE.COM",
    "status": ["client delete prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"}],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
    "secureDNS": {"delegationSigned": True},
    "entities": [
        {"roles": ["registrar"], "vcardArray": vcard(["fn", {}, "text", "RESERVED-IANA"]),
         "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}]},
        {"roles": ["registrant"], "vcardArray": vcard(
            ["fn", {}, "text", "Jane Doe"], ["email", {}, "text", "jane@example.com"])},
    ],
}


@respx.mock
async def test_rdap_domain(make_ctx):
    respx.get("https://data.iana.org/rdap/dns.json").mock(
        return_value=httpx.Response(200, json=BOOTSTRAP_DNS))
    respx.get("https://rdap.test/com/domain/example.com").mock(
        return_value=httpx.Response(200, json=DOMAIN_RDAP))
    found = await RdapCollector().collect(DOMAIN, make_ctx())
    kinds = {o.kind: o.value for o in found.observations}
    assert kinds["rdap.registration"] == "1995-08-14T04:00:00Z"
    assert kinds["rdap.registrar"] == "RESERVED-IANA"
    assert kinds["rdap.dnssec"] is True
    # A personal registrant name must never be collected.
    assert kinds["rdap.registrant_redacted"] is True
    dumped = json.dumps([o.model_dump(mode="json") for o in found.observations])
    assert "Jane Doe" not in dumped and "jane@" not in dumped
    assert {e.value for e in found.entities.values()} >= {"a.iana-servers.net", "RESERVED-IANA"}
    # Evidence keeps the raw response, so a reviewer can verify the parse.
    assert all(o.evidence_id in found.evidence for o in found.observations)


@respx.mock
async def test_rdap_walks_up_to_registered_domain(make_ctx):
    respx.get("https://data.iana.org/rdap/dns.json").mock(
        return_value=httpx.Response(200, json=BOOTSTRAP_DNS))
    respx.get("https://rdap.test/com/domain/www.example.com").mock(
        return_value=httpx.Response(404))
    respx.get("https://rdap.test/com/domain/example.com").mock(
        return_value=httpx.Response(200, json=DOMAIN_RDAP))
    target = EntityRef(type=EntityType.DOMAIN, value="www.example.com")
    found = await RdapCollector().collect(target, make_ctx())
    assert any(r.type is RelationType.SUBDOMAIN_OF and r.target.value == "example.com"
               for r in found.relationships)


@respx.mock
async def test_rdap_ip_uses_most_specific_bootstrap_and_org_only(make_ctx):
    respx.get("https://data.iana.org/rdap/ipv4.json").mock(
        return_value=httpx.Response(200, json=BOOTSTRAP_V4))
    respx.get("https://rdap.specific.test/ip/1.1.1.1").mock(return_value=httpx.Response(200, json={
        "handle": "1.1.1.0 - 1.1.1.255", "name": "APNIC-LABS", "country": "AU",
        "startAddress": "1.1.1.0", "endAddress": "1.1.1.255",
        "entities": [{"roles": ["registrant"],
                      "vcardArray": vcard(["kind", {}, "text", "org"],
                                          ["fn", {}, "text", "APNIC Research and Development"])}],
    }))
    found = await RdapCollector().collect(EntityRef(type=EntityType.IP, value="1.1.1.1"),
                                          make_ctx())
    rels = {(r.source.value, r.type, r.target.value) for r in found.relationships}
    assert ("1.1.1.1", RelationType.BELONGS_TO_NETWORK, "1.1.1.0/24") in rels
    assert ("1.1.1.0/24", RelationType.OPERATED_BY, "APNIC Research and Development") in rels


def test_network_cidr_variants():
    assert network_cidr({"cidr0_cidrs": [{"v4prefix": "10.0.0.0", "length": 8}]}) == "10.0.0.0/8"
    assert network_cidr({"startAddress": "10.0.0.0", "endAddress": "10.0.0.255"}) == "10.0.0.0/24"
    assert network_cidr({"startAddress": "10.0.0.0", "endAddress": "10.0.0.2"}) == \
        "10.0.0.0-10.0.0.2"


CRT_ROWS = [
    {"id": 1, "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "example.com",
     "name_value": "example.com\nwww.example.com", "not_before": "2024-01-01T00:00:00",
     "not_after": "2024-04-01T00:00:00", "serial_number": "aa", "entry_timestamp": "x"},
    {"id": 2, "issuer_name": 'C=US, O="DigiCert, Inc.", CN=DigiCert', "common_name":
     "*.api.example.com", "name_value": "*.api.example.com\nnot-a-domain at all\nother.org",
     "not_before": "2025-01-01T00:00:00", "not_after": "2026-01-01T00:00:00",
     "serial_number": "bb", "entry_timestamp": "y"},
]


@respx.mock
async def test_crtsh_subdomains_and_certificates(make_ctx):
    route = respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=CRT_ROWS))
    found = await CrtShCollector().collect(DOMAIN, make_ctx())
    assert route.calls[0].request.url.params["q"] == "%.example.com"
    subs = {o.value for o in found.observations if o.kind == "ct.subdomain"}
    assert subs == {"www.example.com", "api.example.com"}
    certs = [e for e in found.entities.values() if e.type is EntityType.CERTIFICATE]
    assert {c.value for c in certs} == {"crtsh:1", "crtsh:2"}
    issuers = {r.target.value for r in found.relationships if r.type is RelationType.ISSUED_BY}
    assert issuers == {"Let's Encrypt", "DigiCert, Inc."}


@respx.mock
async def test_crtsh_respects_subdomain_limit(make_ctx):
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, json=CRT_ROWS))
    settings = Settings()
    settings.collection.max_subdomains = 1
    found = await CrtShCollector().collect(DOMAIN, make_ctx(settings=settings))
    assert len([o for o in found.observations if o.kind == "ct.subdomain"]) == 1
    assert found.partial


@respx.mock
async def test_crtsh_html_error_page(make_ctx):
    respx.get("https://crt.sh/").mock(return_value=httpx.Response(200, text="<html>busy</html>"))
    with pytest.raises(FetchError, match="non-JSON"):
        await CrtShCollector().collect(DOMAIN, make_ctx())


def test_issuer_org():
    assert issuer_org("C=US, O=Google Trust Services, CN=WR1") == "Google Trust Services"
    assert issuer_org("CN=Only") is None


@respx.mock
async def test_wayback(make_ctx):
    respx.get("https://web.archive.org/cdx/search/cdx").mock(return_value=httpx.Response(
        200, json=[["timestamp", "statuscode", "original"],
                   ["19980101000000", "200", "http://example.com/"],
                   ["20240505120000", "200", "https://example.com/"]]))
    found = await WaybackCollector().collect(DOMAIN, make_ctx())
    kinds = {o.kind: o.value for o in found.observations}
    assert kinds["archive.first_capture"].startswith("1998-01-01")
    assert len(kinds["archive.yearly_captures"]) == 2


@pytest.fixture
def public_dns(monkeypatch):
    async def fake(host, port=443):
        if host.endswith(".internal"):
            raise UnsafeTargetError(f"{host} resolves to non-public address 10.0.0.1")
        return ["93.184.215.14"]
    monkeypatch.setattr("strxeye.collectors.website.ensure_public_host", fake)


@respx.mock
async def test_http_collector(make_ctx, public_dns):
    respx.get("https://example.com/").mock(return_value=httpx.Response(
        200,
        headers=[("Server", "nginx"), ("Strict-Transport-Security", "max-age=1"),
                 ("cf-ray", "abc"), ("Set-Cookie", "sid=SECRETVALUE; Secure; HttpOnly")],
        html='<html><title>Example</title><meta name="generator" content="WordPress 6.5">'
             '<link href="/wp-content/x.css"></html>'))
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(
        200, text="User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml\n"))
    found = await HttpCollector().collect(DOMAIN, make_ctx())
    techs = {e.value for e in found.entities.values() if e.type is EntityType.TECHNOLOGY}
    assert {"nginx", "Cloudflare", "WordPress 6.5", "WordPress"} <= techs
    missing = {o.value for o in found.observations if o.kind == "http.security_header.missing"}
    assert "content-security-policy" in missing
    assert "strict-transport-security" not in missing
    cookie = next(o.value for o in found.observations if o.kind == "http.cookie")
    assert cookie == {"name": "sid", "secure": True, "httponly": True, "samesite": None}
    # Cookie values are never stored, not even in evidence.
    assert "SECRETVALUE" not in json.dumps([o.model_dump(mode="json") for o in found.observations])
    assert not any("SECRETVALUE" in e.content for e in found.evidence.values())
    assert any("sid=<redacted>; Secure; HttpOnly" in e.content for e in found.evidence.values())
    assert any(o.kind == "robots.sitemap" for o in found.observations)


@respx.mock
async def test_http_collector_refuses_redirect_into_private_network(make_ctx, public_dns):
    respx.get("https://example.com/").mock(return_value=httpx.Response(
        302, headers={"Location": "http://metadata.internal/latest/"}))
    with pytest.raises(UnsafeTargetError):
        await HttpCollector().collect(EntityRef(type=EntityType.URL,
                                                value="https://example.com/"), make_ctx())
