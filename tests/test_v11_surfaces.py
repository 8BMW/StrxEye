"""API and CLI for monitoring, alerts, the malware view and plugins."""

import json

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from conftest import StaticCollector
from strxeye import plugins
from strxeye.cli import main as cli
from strxeye.collectors.base import Findings
from strxeye.config import Settings, load_settings
from strxeye.engine import Engine
from strxeye.models import EntityType, RelationType
from strxeye.server import create_app


class Infra(StaticCollector):
    """An IP tied to a malware family that is attributed to an actor."""

    async def collect(self, target, ctx):
        found = Findings(self.name)
        fam = found.entity(EntityType.MALWARE, "Emotet")
        actor = found.entity(EntityType.THREAT_ACTOR, "MUMMY SPIDER")
        found.relate(target, RelationType.ASSOCIATED_WITH, fam, confidence=0.9)
        found.relate(fam, RelationType.ATTRIBUTED_TO, actor, confidence=0.6)
        found.observe(fam, "malware.profile", {"aliases": ["Geodo"]}, method="t")
        found.observe(target, "dns.a", f"192.0.2.{self.counter()}", method="t")
        return found

    _n = 0

    @classmethod
    def counter(cls):
        cls._n += 1
        return cls._n


@pytest.fixture
def api(store):
    app = create_app(store, "t", run_scheduler=False, engine_factory=lambda s: Engine(
        Settings(), s, collectors={"x": Infra("x", accepts={EntityType.DOMAIN, EntityType.IP})},
        secret=lambda n: None))
    with TestClient(app, headers={"Authorization": "Bearer t"}) as client:
        yield client


def test_watch_lifecycle_and_alerts(api):
    inv = api.post("/api/investigations", json={"name": "watched"}).json()
    assert api.post(f"/api/investigations/{inv['id']}/watches",
                    json={"target": "example.com", "every": "30m"}).status_code == 400
    watch = api.post(f"/api/investigations/{inv['id']}/watches",
                     json={"target": "example.com", "every": "12h"}).json()
    assert watch["interval_hours"] == 12 and watch["enabled"]

    first = api.post("/api/watches/run-due").json()
    assert first[0]["alerts"] == 0 and first[0]["run_id"]  # first run: nothing to compare
    assert api.post("/api/watches/run-due").json() == []  # rescheduled 12 h ahead

    paused = api.patch(f"/api/watches/{watch['id']}", json={"enabled": False}).json()
    assert paused["enabled"] is False
    assert api.delete(f"/api/watches/{watch['id']}").status_code == 204
    assert api.get("/api/watches").json() == []


def test_alert_endpoints(api, store):
    inv = api.post("/api/investigations", json={"name": "alerts"}).json()
    store.add_alerts([{"investigation_id": inv["id"], "severity": "high", "title": "x: listed"},
                      {"investigation_id": inv["id"], "severity": "low", "title": "x: cert"}])
    assert api.get("/api/alerts/unread-count").json() == {"unread": 2}
    alerts = api.get("/api/alerts", params={"unread": True}).json()
    assert [a["severity"] for a in alerts] == ["high", "low"]
    assert api.post("/api/alerts/read", json={"ids": [alerts[0]["id"]]}).json() == {"marked": 1}
    assert api.post("/api/alerts/read", json={}).json() == {"marked": 1}
    assert api.get("/api/alerts/unread-count").json() == {"unread": 0}


def test_malware_view(api):
    inv = api.post("/api/investigations", json={"name": "malware"}).json()
    run = api.post(f"/api/investigations/{inv['id']}/runs", json={"target": "198.51.100.7"})
    import time
    for _ in range(100):
        if api.get(f"/api/runs/{run.json()['run_id']}").json()["status"] != "running":
            break
        time.sleep(0.05)
    families = api.get(f"/api/investigations/{inv['id']}/malware").json()
    assert families[0]["name"] == "Emotet"
    assert families[0]["profile"] == {"aliases": ["Geodo"]}
    assert [a["value"] for a in families[0]["actors"]] == ["MUMMY SPIDER"]
    assert families[0]["infrastructure"][0]["value"] == "198.51.100.7"


class FakeDist:
    def __init__(self, version):
        self.version = version
        self.metadata = {"Name": "strxeye-plugin-demo", "Summary": "Demo plugin"}

    def get_all(self, _):
        return []


class FakeEP:
    name = "demo"
    value = "demo_mod:DemoCollector"

    def __init__(self, version="1.0.0"):
        self.dist = FakeDist(version)
        self.dist.metadata = {"Name": "strxeye-plugin-demo", "Summary": "Demo plugin"}

    def load(self):
        raise AssertionError("listing or trusting must not import the plugin")


@pytest.fixture
def fake_plugin(monkeypatch):
    class Meta(dict):
        def get_all(self, _):
            return []

    ep = FakeEP()
    ep.dist.metadata = Meta(ep.dist.metadata)
    monkeypatch.setattr(plugins, "entry_points", lambda group: [ep])
    return ep


def test_plugin_trust_through_api(api, fake_plugin):
    listed = api.get("/api/plugins").json()
    assert listed == [{"name": "demo", "package": "strxeye-plugin-demo", "version": "1.0.0",
                       "entry_point": "demo_mod:DemoCollector", "summary": "Demo plugin",
                       "homepage": None, "trusted": False, "trust_key": "demo==1.0.0"}]
    # Trusting a version other than the one shown is refused.
    assert api.post("/api/plugins/demo/trust", json={"version": "0.9"}).status_code == 409
    assert api.post("/api/plugins/demo/trust", json={"version": "1.0.0"}).json() == {
        "trusted": "demo==1.0.0"}
    assert load_settings().plugins.trusted == ["demo==1.0.0"]
    assert api.delete("/api/plugins/demo/trust").status_code == 204
    assert load_settings().plugins.trusted == []


runner = CliRunner()


def test_cli_monitor_and_alerts(monkeypatch, store):
    monkeypatch.setattr(cli, "make_engine", lambda s=None: Engine(
        load_settings(), s, collectors={"x": Infra("x")}, secret=lambda n: None))
    inv = json.loads(runner.invoke(cli.app, ["investigate", "create", "m", "--json"]).stdout)["id"]
    assert runner.invoke(cli.app, ["monitor", "add", inv, "example.com", "--every", "5m"]
                         ).exit_code == 2
    added = runner.invoke(cli.app, ["monitor", "add", inv, "example.com", "--every", "6h"])
    assert added.exit_code == 0 and "every 6h" in added.stdout
    ran = runner.invoke(cli.app, ["monitor", "run"])
    assert ran.exit_code == 0 and "example.com: run" in ran.stdout
    assert "No watches are due" in runner.invoke(cli.app, ["monitor", "run"]).stdout
    listing = json.loads(runner.invoke(cli.app, ["monitor", "list", "--json"]).stdout)
    assert listing[0]["target_value"] == "example.com"
    assert runner.invoke(cli.app, ["alerts"]).exit_code == 0
    assert runner.invoke(cli.app, ["monitor", "remove", str(listing[0]["id"])]).exit_code == 0


def test_cli_plugins_new(tmp_path):
    result = runner.invoke(cli.app, ["plugins", "new", "my_source", "--dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    pkg = tmp_path / "strxeye-plugin-my-source"
    assert (pkg / "src" / "strxeye_plugin_my_source" / "__init__.py").exists()
    assert 'my_source = "strxeye_plugin_my_source:MySourceCollector"' in (
        pkg / "pyproject.toml").read_text()
    assert runner.invoke(cli.app, ["plugins", "new", "Bad Name", "--dir", str(tmp_path)]
                         ).exit_code == 2
