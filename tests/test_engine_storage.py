import asyncio

import pytest

from conftest import StaticCollector
from strxeye.config import Settings
from strxeye.engine import Engine, EngineError, RunOptions
from strxeye.models import CollectionStatus, EntityRef, EntityType
from strxeye.net import FetchError
from strxeye.storage import NotFoundError, Store

DOMAIN = EntityRef(type=EntityType.DOMAIN, value="example.com")


def engine(store=None, settings=None, **collectors):
    return Engine(settings or Settings(), store, collectors=collectors)


async def test_failures_are_isolated_per_collector():
    e = engine(good=StaticCollector("good"),
               broken=StaticCollector("broken", error=RuntimeError("boom")),
               down=StaticCollector("down", error=FetchError("src.test returned HTTP 503")))
    report = await e.run(DOMAIN)
    status = {r.collector: r for r in report.results}
    assert status["good"].status is CollectionStatus.OK
    assert status["broken"].status is CollectionStatus.ERROR
    assert "RuntimeError: boom" in status["broken"].error
    assert status["down"].error == "src.test returned HTTP 503"
    assert report.status == "completed"


async def test_collector_timeout():
    settings = Settings()
    settings.collection.collector_timeout = 0.05
    report = await engine(settings=settings, slow=StaticCollector("slow", delay=5)).run(DOMAIN)
    assert report.results[0].status is CollectionStatus.TIMEOUT


async def test_cancellation_keeps_finished_results(store):
    inv = store.create_investigation("cancel test")
    cancel = asyncio.Event()
    e = engine(store, fast=StaticCollector("fast"), slow=StaticCollector("slow", delay=5))

    def on_event(event):
        if event.kind == "finished" and event.collector == "fast":
            cancel.set()

    report = await e.run(DOMAIN, investigation_id=inv.id, on_event=on_event, cancel=cancel)
    assert report.status == "cancelled"
    by_name = {r.collector: r.status for r in report.results}
    assert by_name == {"fast": CollectionStatus.OK, "slow": CollectionStatus.CANCELLED}
    run = store.get_run(report.run_id)
    assert run["status"] == "cancelled"
    assert store.find_entity(inv.id, EntityRef(type=EntityType.IP, value="203.0.113.10"))


async def test_direct_collectors_need_permission():
    e = engine(passive=StaticCollector("passive"), web=StaticCollector("web", direct=True))
    assert [c.name for c in e.select(DOMAIN, RunOptions())] == ["passive"]
    assert len(e.select(DOMAIN, RunOptions(direct=True))) == 2
    with pytest.raises(EngineError, match="--direct"):
        e.select(DOMAIN, RunOptions(collectors=["web"]))


async def test_unknown_and_unsupported_collectors():
    e = engine(dom=StaticCollector("dom"))
    with pytest.raises(EngineError, match="unknown collector"):
        e.select(DOMAIN, RunOptions(collectors=["nope"]))
    with pytest.raises(EngineError, match="no collectors support"):
        await e.run(EntityRef(type=EntityType.HASH, value="a" * 32))


async def test_expansion_runs_ip_collectors_on_discovered_addresses():
    ip_collector = StaticCollector("asn", ips=(), accepts={EntityType.IP})
    e = engine(dns=StaticCollector("dns", ips=("203.0.113.1", "203.0.113.2")), asn=ip_collector)
    report = await e.run(DOMAIN, RunOptions(expand=True))
    expanded = sorted(r.target.value for r in report.results if r.collector == "asn")
    assert expanded == ["203.0.113.1", "203.0.113.2"]


def test_store_crud_and_prefix_lookup(store):
    inv = store.create_investigation("Case A", "desc")
    assert store.get_investigation(inv.id[:6]).name == "Case A"
    with pytest.raises(NotFoundError):
        store.get_investigation("zzzzzz")
    with pytest.raises(ValueError):
        store.create_investigation("   ")
    store.rename_investigation(inv.id, "Case B")
    assert store.list_investigations()[0]["name"] == "Case B"


async def test_store_persists_and_deletes(store):
    inv = store.create_investigation("persist")
    report = await engine(store, s=StaticCollector("s")).run(DOMAIN, investigation_id=inv.id)
    ents = store.entities(inv.id)
    assert {(e["type"], e["value"]) for e in ents} == {("domain", "example.com"),
                                                        ("ip", "203.0.113.10")}
    domain_id = store.find_entity(inv.id, DOMAIN)
    detail = store.entity_detail(inv.id, domain_id)
    assert detail["observations"][0]["evidence_id"]
    assert detail["relationships"][0]["other_value"] == "203.0.113.10"
    assert store.get_run(report.run_id)["collectors"][0]["status"] == "ok"
    assert store.get_investigation(inv.id).seeds == [DOMAIN]

    store.delete_investigation(inv.id)
    assert store.list_investigations() == []
    assert store._query("SELECT COUNT(*) FROM observations")[0][0] == 0
    assert store._query("SELECT COUNT(*) FROM evidence")[0][0] == 0
    actions = [a["action"] for a in store.audit_log()]
    assert actions[:2] == ["investigation.delete", "run.start"]


def test_store_refuses_newer_schema(tmp_path):
    path = tmp_path / "x.db"
    Store(path).close()
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 999")
    conn.close()
    with pytest.raises(RuntimeError, match="newer"):
        Store(path)


def test_interrupted_runs_are_marked(store):
    inv = store.create_investigation("x")
    run_id = store.start_run(inv.id, DOMAIN, {})
    assert store.fail_interrupted_runs() == 1
    assert store.get_run(run_id)["status"] == "interrupted"
