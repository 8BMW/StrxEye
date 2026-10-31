import json

import pytest
from typer.testing import CliRunner

from conftest import StaticCollector
from strxeye.cli import main as cli
from strxeye.config import load_settings
from strxeye.engine import Engine
from strxeye.net import FetchError

runner = CliRunner()


@pytest.fixture
def fake_engine(monkeypatch):
    collectors = {"dns": StaticCollector("dns")}

    def make(store=None):
        return Engine(load_settings(), store, collectors=collectors)

    monkeypatch.setattr(cli, "make_engine", make)
    return collectors


def invoke(*args):
    return runner.invoke(cli.app, list(args))


def test_version():
    result = invoke("--version")
    assert result.exit_code == 0 and "strxeye" in result.stdout


def test_invalid_target_exits_2(fake_engine):
    result = invoke("domain", "not a domain")
    assert result.exit_code == 2
    assert "not a valid domain" in result.output


def test_domain_json_output(fake_engine):
    result = invoke("domain", "example.com", "--json")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["results"][0]["observations"][0]["value"] == "203.0.113.10"


def test_exit_codes_reflect_failures(fake_engine):
    fake_engine["down"] = StaticCollector("down", error=FetchError("HTTP 503"))
    assert invoke("domain", "example.com").exit_code == 1
    fake_engine.pop("dns")
    assert invoke("domain", "example.com").exit_code == 3


def test_investigation_workflow(fake_engine, tmp_path):
    created = json.loads(invoke("investigate", "create", "Case One", "--json").stdout)
    inv_id = created["id"]
    assert invoke("investigate", "run", inv_id[:6], "example.com").exit_code == 0

    listing = json.loads(invoke("investigate", "list", "--json").stdout)
    assert listing[0]["entity_count"] == 2

    shown = json.loads(invoke("investigate", "show", inv_id, "--json").stdout)
    assert shown["seeds"] == [{"type": "domain", "value": "example.com"}]

    ents = json.loads(invoke("investigate", "entities", inv_id, "--type", "ip", "--json").stdout)
    assert [e["value"] for e in ents] == ["203.0.113.10"]

    out = tmp_path / "graph.json"
    assert invoke("graph", "export", inv_id, "-o", str(out)).exit_code == 0
    assert json.loads(out.read_text())["format"] == "strxeye-graph"

    report = tmp_path / "r.html"
    assert invoke("report", inv_id, "--format", "html", "-o", str(report)).exit_code == 0
    assert "Case One" in report.read_text(encoding="utf-8")
    assert invoke("report", inv_id, "--format", "pdf").exit_code == 2

    assert invoke("investigate", "delete", inv_id, "--yes").exit_code == 0
    assert invoke("investigate", "show", inv_id).exit_code == 4


def test_unknown_investigation_exits_4(fake_engine):
    assert invoke("domain", "example.com", "--save", "abcdef").exit_code == 4


def test_config_set_and_show():
    assert invoke("config", "set", "network.timeout", "12.5").exit_code == 0
    shown = json.loads(invoke("config", "show", "--json").stdout)
    assert shown["settings"]["network"]["timeout"] == 12.5
    bad = invoke("config", "set", "network.bogus", "1")
    assert bad.exit_code == 2 and "unknown setting" in bad.output


def test_collectors_and_plugins_listing():
    names = {c["name"] for c in json.loads(invoke("collectors", "--json").stdout)}
    assert {"dns", "rdap", "crtsh", "asn", "reverse_dns", "wayback", "http", "tls"} <= names
    assert invoke("plugins", "list").exit_code == 0
    assert invoke("plugins", "trust", "nonexistent", "--yes").exit_code == 4
