"""Graph building, correlation, run comparison and reports."""

import csv
import io
import json

from conftest import StaticCollector
from strxeye.collectors.base import Findings
from strxeye.config import Settings
from strxeye.correlation import CROWDED, site_key
from strxeye.engine import Engine
from strxeye.graph import build_graph
from strxeye.history import diff_runs
from strxeye.models import CollectionStatus, EntityRef, EntityType, RelationType
from strxeye.reporting import render


class Scripted(StaticCollector):
    """Collector whose findings are built by a callback."""

    def __init__(self, name, build, accepts=(EntityType.DOMAIN,), error=None):
        super().__init__(name, accepts=set(accepts), error=error)
        self.build = build

    async def collect(self, target, ctx):
        if self.error:
            raise self.error
        found = Findings(self.name)
        self.build(found, target)
        return found


def ref(t, v):
    return EntityRef(type=t, value=v)


async def run(store, inv_id, target, *collectors):
    e = Engine(Settings(), store, collectors={c.name: c for c in collectors})
    return await e.run(target, investigation_id=inv_id)


def resolves(ip):
    def build(found, target):
        found.relate(target, RelationType.RESOLVES_TO, found.entity(EntityType.IP, ip))
        found.observe(target, "dns.a", ip, method="test")
    return build


async def test_shared_ip_is_inferred_but_not_for_same_site(store):
    inv = store.create_investigation("g")
    for domain in ("alpha.com", "www.alpha.com", "beta.org"):
        await run(store, inv.id, ref(EntityType.DOMAIN, domain),
                  Scripted("dns", resolves("198.51.100.7")))
    graph = build_graph(store, inv.id)
    names = {n["id"]: n["value"] for n in graph["nodes"]}
    inferred = [e for e in graph["edges"] if e["inferred"]]
    pairs = {frozenset((names[e["source"]], names[e["target"]])) for e in inferred}
    assert frozenset(("alpha.com", "beta.org")) in pairs
    assert frozenset(("alpha.com", "www.alpha.com")) not in pairs
    edge = inferred[0]
    assert edge["confidence"] < 0.5
    assert "does not show that the domains have the same owner" in edge["explanation"]
    observed = [e for e in graph["edges"] if not e["inferred"]]
    assert all(e["provenance"] for e in observed)


async def test_crowded_ip_produces_no_pairwise_links(store):
    inv = store.create_investigation("crowded")
    for i in range(CROWDED + 1):
        await run(store, inv.id, ref(EntityType.DOMAIN, f"site{i}.com"),
                  Scripted("dns", resolves("198.51.100.9")))
    assert not [e for e in build_graph(store, inv.id)["edges"] if e["inferred"]]


async def test_hosted_by_chain(store):
    inv = store.create_investigation("hosting")

    def build(found, target):
        ip = found.entity(EntityType.IP, "198.51.100.1")
        net = found.entity(EntityType.NETWORK, "198.51.100.0/24")
        org = found.entity(EntityType.ORGANIZATION, "Example Hosting")
        found.relate(target, RelationType.RESOLVES_TO, ip)
        found.relate(ip, RelationType.BELONGS_TO_NETWORK, net)
        found.relate(net, RelationType.OPERATED_BY, org)

    await run(store, inv.id, ref(EntityType.DOMAIN, "shop.com"), Scripted("x", build))
    hosted = [e for e in build_graph(store, inv.id)["edges"] if e["type"] == "hosted_by"]
    assert len(hosted) == 1 and hosted[0]["inferred"]
    assert "not necessarily the site operator" in hosted[0]["explanation"]


def test_site_key():
    assert site_key("a.b.example.co.uk") == "example.co.uk"
    assert site_key("www.example.com") == "example.com"


async def test_diff_ignores_collectors_that_failed_in_one_run(store):
    inv = store.create_investigation("diff")
    target = ref(EntityType.DOMAIN, "example.com")

    def subs(*names):
        def build(found, t):
            for n in names:
                found.observe(t, "ct.subdomain", n, method="test")
        return build

    first = await run(store, inv.id, target, Scripted("dns", resolves("192.0.2.1")),
                      Scripted("ct", subs("a.example.com", "b.example.com")))
    second = await run(store, inv.id, target, Scripted("dns", resolves("192.0.2.2")),
                       Scripted("ct", subs(), error=RuntimeError("down")))
    diff = diff_runs(store, inv.id, first.run_id, second.run_id)
    assert diff["compared_collectors"] == ["dns"]
    assert "ct" in diff["not_compared"]
    assert [a["value"] for a in diff["added"]] == ["192.0.2.2"]
    assert [r["value"] for r in diff["removed"]] == ["192.0.2.1"]


async def test_reports_escape_hostile_values_and_label_content(store):
    inv = store.create_investigation("<b>report</b>")

    def build(found, target):
        found.observe(target, "dns.txt", "<script>alert(1)</script>", method="test")
        found.observe(target, "dns.txt", "=HYPERLINK(\"http://x\")", method="test")
        found.observe(target, "dns.dmarc.missing", True, method="test")

    await run(store, inv.id, ref(EntityType.DOMAIN, "example.com"), Scripted("dns", build))
    html = render(store, inv.id, "html", Settings())
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;b&gt;report&lt;/b&gt;" in html
    assert "No DMARC policy published" in html
    assert "Interpretation" in html and "Observation" in html

    rows = list(csv.reader(io.StringIO(render(store, inv.id, "csv", Settings()))))
    values = [r[3] for r in rows[1:]]
    assert "'=HYPERLINK(\"http://x\")" in values

    data = json.loads(render(store, inv.id, "json", Settings()))
    assert data["interpretations"][0]["basis"][0]["kind"] == "dns.dmarc.missing"
    assert data["scope"]["direct_contact"] is False


async def test_report_lists_collector_failures(store):
    inv = store.create_investigation("limits")
    await run(store, inv.id, ref(EntityType.DOMAIN, "example.com"),
              Scripted("ct", lambda f, t: None, error=RuntimeError("down")))
    data = json.loads(render(store, inv.id, "json", Settings()))
    assert data["limitations"][0]["status"] == CollectionStatus.ERROR
