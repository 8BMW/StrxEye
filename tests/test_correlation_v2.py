"""Correlation rules: what links, what is suppressed, and how signals combine."""

from strxeye.correlation import analyze
from strxeye.models import RelationType

R = RelationType


class G:
    """Tiny graph builder for correlation tests."""

    def __init__(self):
        self.nodes, self.edges, self.obs = {}, [], []
        self._ids = {}

    def node(self, type_, value, **attrs):
        key = (type_, value)
        if key not in self._ids:
            nid = len(self._ids) + 1
            self._ids[key] = nid
            self.nodes[nid] = {"id": nid, "type": type_, "value": value, "attributes": attrs,
                               "seed": False}
        return self._ids[key]

    def edge(self, a, rel, b):
        self.edges.append({"id": f"e{len(self.edges)}", "source": a, "target": b,
                           "type": rel.value, "inferred": False, "confidence": 1.0})

    def observe(self, nid, kind, value):
        self.obs.append({"entity_id": nid, "kind": kind, "value": value})

    def run(self):
        inferred, suppressed = analyze(self.nodes, self.edges, self.obs)
        links = {frozenset((self.nodes[e["source"]]["value"], self.nodes[e["target"]]["value"])): e
                 for e in inferred if e["type"] != R.HOSTED_BY}
        return links, suppressed


def resolve(g, domain, ip, asn=None, asn_name=None):
    d, i = g.node("domain", domain), g.node("ip", ip)
    g.edge(d, R.RESOLVES_TO, i)
    if asn:
        net = g.node("network", ip.rsplit(".", 1)[0] + ".0/24")
        a = g.node("asn", asn, name=asn_name)
        g.edge(i, R.BELONGS_TO_NETWORK, net)
        g.edge(net, R.ANNOUNCED_BY, a)
    return d


def test_shared_ip_on_cdn_is_suppressed_with_reason():
    g = G()
    resolve(g, "alpha.com", "104.16.1.1", "AS13335", "CLOUDFLARENET")
    resolve(g, "beta.org", "104.16.1.1", "AS13335", "CLOUDFLARENET")
    links, suppressed = g.run()
    assert not links
    assert suppressed == ["104.16.1.1: announced by AS13335 (CLOUDFLARENET)"]


def test_shared_ip_on_vps_network_still_links_weakly():
    g = G()
    resolve(g, "alpha.com", "203.0.113.5", "AS14061", "DIGITALOCEAN")
    resolve(g, "beta.org", "203.0.113.5", "AS14061", "DIGITALOCEAN")
    links, _ = g.run()
    edge = links[frozenset(("alpha.com", "beta.org"))]
    assert edge["type"] == "shares_infrastructure" and edge["confidence"] == 0.3
    assert "does not show that the domains have the same owner" in edge["explanation"]


def test_internetdb_cdn_tag_suppresses():
    g = G()
    resolve(g, "alpha.com", "203.0.113.5")
    resolve(g, "beta.org", "203.0.113.5")
    g.observe(g.node("ip", "203.0.113.5"), "scan.tags", ["cdn"])
    links, suppressed = g.run()
    assert not links and "Shodan InternetDB" in suppressed[0]


def test_tracking_id_is_strong_even_on_a_cdn():
    g = G()
    a = resolve(g, "alpha.com", "104.16.1.1", "AS13335")
    b = resolve(g, "beta.org", "104.16.1.2", "AS13335")
    for d in (a, b):
        g.observe(d, "http.tracking_id", {"type": "google_analytics", "id": "UA-1234-1"})
    links, _ = g.run()
    edge = links[frozenset(("alpha.com", "beta.org"))]
    assert edge["type"] == "likely_same_operator" and edge["confidence"] == 0.8
    assert "UA-1234-1" in edge["explanation"]


def test_signals_combine_without_reaching_certainty():
    g = G()
    a = resolve(g, "alpha.com", "203.0.113.5")
    b = resolve(g, "beta.org", "203.0.113.5")
    ns = g.node("domain", "ns1.alpha-infra.net")
    g.edge(a, R.USES_NAMESERVER, ns)
    g.edge(b, R.USES_NAMESERVER, ns)
    links, _ = g.run()
    edge = links[frozenset(("alpha.com", "beta.org"))]
    # 1 - (1 - 0.3)(1 - 0.6) = 0.72
    assert edge["confidence"] == 0.72 and edge["type"] == "likely_same_operator"
    assert len(edge["basis"]) == 2


def test_dns_providers_and_privacy_registrants_are_ignored():
    g = G()
    a, b = g.node("domain", "alpha.com"), g.node("domain", "beta.org")
    ns = g.node("domain", "kate.ns.cloudflare.com")
    g.edge(a, R.USES_NAMESERVER, ns)
    g.edge(b, R.USES_NAMESERVER, ns)
    for d in (a, b):
        g.observe(d, "rdap.registrant_org", "Domains By Proxy, LLC")
    links, _ = g.run()
    assert not links


def test_real_registrant_links():
    g = G()
    a, b = g.node("domain", "alpha.com"), g.node("domain", "beta.org")
    for d in (a, b):
        g.observe(d, "rdap.registrant_org", "Example Holdings Ltd")
    links, _ = g.run()
    assert links[frozenset(("alpha.com", "beta.org"))]["confidence"] == 0.65


def test_multi_tenant_certificate_is_suppressed():
    g = G()
    names = [f"site{i}.example{i}.com" for i in range(15)]
    cert = g.node("certificate", "sha256:" + "a" * 64, names=names)
    for d in ("alpha.com", "beta.org"):
        g.edge(g.node("domain", d), R.USES_CERTIFICATE, cert)
    links, suppressed = g.run()
    assert not links and "multi-tenant" in suppressed[0]


def test_subdomains_of_the_same_site_are_never_linked():
    g = G()
    a, b = g.node("domain", "www.alpha.com"), g.node("domain", "shop.alpha.com")
    for d in (a, b):
        g.observe(d, "http.tracking_id", {"type": "google_tag", "id": "G-ABCDEFGH1"})
    links, _ = g.run()
    assert not links
