from conftest import FakeResolver
from strxeye.collectors.asn import AsnCollector, origin_query_name
from strxeye.collectors.dns_records import DnsCollector, ReverseDnsCollector
from strxeye.models import CollectionStatus, EntityRef, EntityType, RelationType

DOMAIN = EntityRef(type=EntityType.DOMAIN, value="example.com")


def kinds(found):
    return {(o.kind, str(o.value)) for o in found.observations}


async def test_dns_records_and_relationships(make_ctx):
    resolver = FakeResolver({
        ("example.com", "A"): ["93.184.215.14"],
        ("example.com", "AAAA"): ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "NS"): ["a.iana-servers.net.", "b.iana-servers.net."],
        ("example.com", "TXT"): ['"v=spf1 -all"', '"some-verification=abc"'],
        ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"'],
    })
    found = await DnsCollector().collect(DOMAIN, make_ctx(resolver))
    k = kinds(found)
    assert ("dns.a", "93.184.215.14") in k
    assert ("dns.txt.spf", "v=spf1 -all") in k
    assert ("dns.txt", "some-verification=abc") in k
    assert ("dns.dmarc", "v=DMARC1; p=reject") in k
    rels = {(r.type, r.target.value) for r in found.relationships}
    assert (RelationType.RESOLVES_TO, "93.184.215.14") in rels
    assert (RelationType.MAIL_HANDLED_BY, "mail.example.com") in rels
    assert (RelationType.USES_NAMESERVER, "a.iana-servers.net") in rels
    assert all(o.evidence_id for o in found.observations if o.kind == "dns.a")
    assert found.status is CollectionStatus.OK


async def test_missing_dmarc_and_null_mx(make_ctx):
    resolver = FakeResolver({
        ("example.com", "A"): ["93.184.215.14"],
        ("example.com", "MX"): ["0 ."],
    })
    found = await DnsCollector().collect(DOMAIN, make_ctx(resolver))
    k = kinds(found)
    assert ("dns.dmarc.missing", "True") in k
    assert ("dns.mx.null", "True") in k


async def test_nxdomain_is_no_data_not_error(make_ctx):
    found = await DnsCollector().collect(DOMAIN, make_ctx(FakeResolver(nxdomain={"example.com"})))
    assert found.status is CollectionStatus.NO_DATA
    assert "NXDOMAIN" in found.notes[0]


async def test_single_record_timeout_marks_partial(make_ctx):
    resolver = FakeResolver({("example.com", "A"): ["93.184.215.14"]},
                            timeouts={("example.com", "TXT")})
    found = await DnsCollector().collect(DOMAIN, make_ctx(resolver))
    assert found.status is CollectionStatus.PARTIAL
    assert any("TXT" in n for n in found.notes)


async def test_reverse_dns(make_ctx):
    resolver = FakeResolver({("1.1.1.1.in-addr.arpa", "PTR"): ["one.one.one.one."]})
    found = await ReverseDnsCollector().collect(EntityRef(type=EntityType.IP, value="1.1.1.1"),
                                                make_ctx(resolver))
    assert found.relationships[0].target.value == "one.one.one.one"
    assert found.relationships[0].confidence < 1


def test_cymru_query_names():
    assert origin_query_name("1.2.3.4") == "4.3.2.1.origin.asn.cymru.com"
    assert origin_query_name("2001:db8::1").endswith(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com")


async def test_asn_collector(make_ctx):
    resolver = FakeResolver({
        ("1.1.1.1.origin.asn.cymru.com", "TXT"): ['"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"'],
        ("AS13335.asn.cymru.com", "TXT"): ['"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"'],
    })
    found = await AsnCollector().collect(EntityRef(type=EntityType.IP, value="1.1.1.1"),
                                         make_ctx(resolver))
    rels = {(r.source.value, r.type, r.target.value) for r in found.relationships}
    assert ("1.1.1.1", RelationType.BELONGS_TO_NETWORK, "1.1.1.0/24") in rels
    assert ("1.1.1.0/24", RelationType.ANNOUNCED_BY, "AS13335") in rels
    asn = found.entities[EntityRef(type=EntityType.ASN, value="AS13335")]
    assert asn.attributes["name"] == "CLOUDFLARENET, US"


async def test_asn_skips_private_addresses(make_ctx):
    found = await AsnCollector().collect(EntityRef(type=EntityType.IP, value="10.0.0.1"),
                                         make_ctx())
    assert found.empty
