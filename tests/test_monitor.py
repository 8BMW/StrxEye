from datetime import timedelta

import pytest

from conftest import StaticCollector
from strxeye.collectors.base import Findings
from strxeye.config import Settings
from strxeye.engine import Engine
from strxeye.models import EntityRef, EntityType, utcnow
from strxeye.monitor import alerts_from_diff, parse_interval, run_due, run_watch

DOMAIN = EntityRef(type=EntityType.DOMAIN, value="example.com")


class Changing(StaticCollector):
    """Returns a different world on each run."""

    def __init__(self, name, worlds, fail_on=()):
        super().__init__(name)
        self.worlds = worlds
        self.fail_on = set(fail_on)
        self.calls = 0

    async def collect(self, target, ctx):
        world = self.worlds[min(self.calls, len(self.worlds) - 1)]
        self.calls += 1
        if self.calls in self.fail_on:
            raise RuntimeError("source down")
        found = Findings(self.name)
        for kind, value in world:
            found.observe(target, kind, value, method="t")
        return found


def test_parse_interval():
    assert parse_interval("6h") == 6 and parse_interval("2d") == 48
    with pytest.raises(ValueError):
        parse_interval("30m")
    with pytest.raises(ValueError):
        parse_interval("0.5h")


async def test_watch_produces_alerts_from_changes(store):
    inv = store.create_investigation("watch")
    dns = Changing("dns", [[("dns.a", "192.0.2.1"), ("dns.ns", "ns1.example.net")],
                           [("dns.a", "192.0.2.9"), ("dns.ns", "ns1.example.net")]])
    feeds = Changing("threatfeeds", [[("threat.not_listed", ["X"])],
                                     [("threat.listed", {"feed": "Feodo Tracker",
                                                         "severity": "high"})]])
    engine = Engine(Settings(), store, collectors={"dns": dns, "threatfeeds": feeds},
                    secret=lambda n: None)
    watch_id = store.add_watch(inv.id, DOMAIN, 24, {"expand": False})

    first = await run_watch(engine, store, store.get_watch(watch_id))
    assert first["alerts"] == 0  # nothing to compare with yet
    second = await run_watch(engine, store, store.get_watch(watch_id))
    assert second["alerts"] == 2

    alerts = store.list_alerts()
    assert [a["severity"] for a in alerts] == ["high", "medium"]
    assert alerts[0]["title"] == "example.com: Listed in a threat feed"
    assert alerts[1]["detail"]["added"] == ["192.0.2.9"]
    assert alerts[1]["detail"]["removed"] == ["192.0.2.1"]
    assert store.unread_alert_count() == 2
    assert store.mark_alerts_read([alerts[0]["id"]]) == 1
    assert store.unread_alert_count() == 1

    watch = store.get_watch(watch_id)
    assert watch["last_run_id"] == second["run_id"]
    assert watch["next_run_at"] > utcnow().isoformat()


async def test_failed_source_does_not_create_false_alerts(store):
    inv = store.create_investigation("outage")
    ct = Changing("crtsh", [[("ct.subdomain", "a.example.com")]] * 3, fail_on={2})
    engine = Engine(Settings(), store, collectors={"crtsh": ct}, secret=lambda n: None)
    watch_id = store.add_watch(inv.id, DOMAIN, 1, {})
    await run_watch(engine, store, store.get_watch(watch_id))
    outcome = await run_watch(engine, store, store.get_watch(watch_id))
    assert outcome["alerts"] == 0
    assert "crtsh" in outcome["error"]
    assert store.list_alerts() == []


async def test_run_due_only_runs_due_and_enabled_watches(store):
    inv = store.create_investigation("due")
    engine = Engine(Settings(), store, collectors={"dns": StaticCollector("dns")},
                    secret=lambda n: None)
    due = store.add_watch(inv.id, DOMAIN, 24, {})
    later = store.add_watch(inv.id, EntityRef(type=EntityType.DOMAIN, value="later.example"),
                            24, {})
    off = store.add_watch(inv.id, EntityRef(type=EntityType.DOMAIN, value="off.example"), 24, {})
    store.record_watch_run(later, None, None, utcnow() + timedelta(hours=5))
    store.set_watch_enabled(off, False)
    results = await run_due(engine, store)
    assert [r["watch_id"] for r in results] == [due]
    assert await run_due(engine, store) == []  # rescheduled 24h ahead


def test_removed_listing_is_not_an_alert():
    diff = {"older": {"id": "a"}, "newer": {"id": "b", "target": "x"}, "not_compared": [],
            "added": [], "removed": [{"entity": "198.51.100.1", "entity_type": "ip",
                                      "kind": "threat.listed", "value": {"feed": "CINS"},
                                      "source": "threatfeeds"}]}
    alerts = alerts_from_diff(diff, "inv", None, "b")
    assert [a["severity"] for a in alerts] == ["info"]


async def test_newly_expanded_entities_are_not_reported_as_changes(store):
    """Run 1 resolves to one IP, run 2 to two. The new IP's expansion facts
    (ASN, ports) must not be alerts; the DNS change itself must be."""
    from strxeye.models import RelationType

    class Dns(StaticCollector):
        def __init__(self):
            super().__init__("dns")
            self.calls = 0

        async def collect(self, target, ctx):
            self.calls += 1
            found = Findings(self.name)
            for ip in ["192.0.2.1"] + (["192.0.2.2"] if self.calls > 1 else []):
                ref = found.entity(EntityType.IP, ip)
                found.observe(target, "dns.a", ip, method="t")
                found.relate(target, RelationType.RESOLVES_TO, ref)
            return found

    class Asn(StaticCollector):
        async def collect(self, target, ctx):
            found = Findings(self.name)
            found.observe(target, "bgp.origin_asn", "AS64500", method="t")
            return found

    from strxeye import engine as engine_mod
    inv = store.create_investigation("expand")
    engine = Engine(Settings(), store, collectors={
        "dns": Dns(), "asn": Asn("asn", accepts={EntityType.IP})}, secret=lambda n: None)
    original = engine_mod.EXPANSION
    engine_mod.EXPANSION = {EntityType.DOMAIN: {EntityType.IP: ("asn",)}}
    try:
        watch_id = store.add_watch(inv.id, DOMAIN, 1, {"expand": True})
        await run_watch(engine, store, store.get_watch(watch_id))
        await run_watch(engine, store, store.get_watch(watch_id))
    finally:
        engine_mod.EXPANSION = original
    titles = [a["title"] for a in store.list_alerts()]
    assert titles == ["example.com: A record changed"]
