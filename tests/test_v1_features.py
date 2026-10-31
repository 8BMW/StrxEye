"""Search, analytics, STIX export, keys, updater, and their API/CLI surfaces."""

import hashlib
import json
import sys

import httpx
import pytest
import respx
import stix2
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from conftest import StaticCollector
from strxeye import secrets, updater
from strxeye.analytics import communities, shortest_path, timeline
from strxeye.cli import main as cli
from strxeye.collectors.base import Findings
from strxeye.config import Settings
from strxeye.engine import Engine
from strxeye.graph import build_graph
from strxeye.models import EntityRef, EntityType, RelationType
from strxeye.reporting import render
from strxeye.server import create_app

DOMAIN = EntityRef(type=EntityType.DOMAIN, value="example.com")


class Scripted(StaticCollector):
    def __init__(self, name, build, accepts=(EntityType.DOMAIN,)):
        super().__init__(name, accepts=set(accepts))
        self.build = build

    async def collect(self, target, ctx):
        found = Findings(self.name)
        self.build(found, target)
        return found


def infrastructure(found, target):
    """example.com -> IP -> network -> AS; IP listed in a threat feed."""
    ev = found.add_evidence("test", "raw evidence mentioning evil-marker-123")
    ip = found.entity(EntityType.IP, "198.51.100.7")
    net = found.entity(EntityType.NETWORK, "198.51.100.0/24")
    asn = found.entity(EntityType.ASN, "AS64500", name="EXAMPLE-AS")
    lst = found.entity(EntityType.INDICATOR, "Spamhaus DROP (IPv4)", kind="threat list")
    mal = found.entity(EntityType.MALWARE, "QakBot")
    cert = found.entity(EntityType.CERTIFICATE, "sha256:" + "ab" * 32, serial="01",
                        not_before="2026-01-01T00:00:00", names=["example.com"])
    found.relate(target, RelationType.RESOLVES_TO, ip, evidence_id=ev)
    found.relate(ip, RelationType.BELONGS_TO_NETWORK, net, evidence_id=ev)
    found.relate(net, RelationType.ANNOUNCED_BY, asn, evidence_id=ev)
    found.relate(ip, RelationType.OBSERVED_IN, lst, evidence_id=ev)
    found.relate(ip, RelationType.ASSOCIATED_WITH, mal, evidence_id=ev)
    found.relate(cert, RelationType.CERTIFICATE_ISSUED_FOR, target, evidence_id=ev)
    found.observe(target, "rdap.registration", "1995-08-14T04:00:00Z", method="t", evidence_id=ev)
    found.observe(ip, "threat.listed", {"feed": "Spamhaus DROP (IPv4)", "severity": "high",
                                        "meaning": "listed"}, method="t", evidence_id=ev,
                  confidence=0.9)
    found.observe(target, "otx.pulse", {"name": "Campaign X", "created": "2026-02-01T00:00:00"},
                  method="t", confidence=0.5)


@pytest.fixture
async def populated(store):
    inv = store.create_investigation("v1 features")
    engine = Engine(Settings(), store, collectors={"x": Scripted("x", infrastructure)},
                    secret=lambda n: None)
    await engine.run(DOMAIN, investigation_id=inv.id)
    lonely = store.create_investigation("other case")
    await Engine(Settings(), store, collectors={"x": Scripted("x", lambda f, t: f.observe(
        t, "dns.txt", "unrelated", method="t"))}, secret=lambda n: None).run(
        EntityRef(type=EntityType.DOMAIN, value="other.org"), investigation_id=lonely.id)
    return inv.id


async def test_search_finds_entities_observations_and_evidence(store, populated):
    hits = store.search("198.51.100")
    assert {h["value"] for h in hits["entities"]} >= {"198.51.100.7", "198.51.100.0/24"}
    evidence = store.search("evil-marker-123")["evidence"]
    assert "[evil-marker-123]" in evidence[0]["snippet"]
    assert store.search("Campaign X")["observations"][0]["kind"] == "otx.pulse"
    # Scoped search excludes other investigations; quotes are literal.
    assert not store.search("other.org", populated)["entities"]
    assert store.search('he"llo') == {"entities": [], "observations": [], "evidence": []}
    with pytest.raises(ValueError):
        store.search("ab")
    store.delete_investigation(populated)
    assert not store.search("198.51.100")["entities"]


async def test_shortest_path_and_communities(store, populated):
    graph = build_graph(store, populated, include_inferred=False)
    ids = {n["value"]: n["id"] for n in graph["nodes"]}
    path = shortest_path(graph, ids["example.com"], ids["AS64500"])
    assert [n for n in path["nodes"]] == [ids[v] for v in
                                          ("example.com", "198.51.100.7", "198.51.100.0/24",
                                           "AS64500")]
    assert path["length"] == 3
    comm = communities(graph)
    # The seed keeps its own label; the infrastructure behind it forms one
    # cluster instead of everything collapsing into the seed's.
    infra = {comm[ids[v]] for v in ("198.51.100.7", "198.51.100.0/24", "AS64500", "QakBot")}
    assert len(infra) == 1 and comm[ids["example.com"]] not in infra


def test_shortest_path_unconnected():
    graph = {"nodes": [{"id": 1}, {"id": 2}], "edges": []}
    assert shortest_path(graph, 1, 2) is None
    with pytest.raises(ValueError):
        shortest_path(graph, 1, 99)


async def test_timeline(store, populated):
    events = timeline(store.all_observations(populated),
                      store.entities(populated, "certificate"))
    names = [e["event"] for e in events]
    assert names[0] == "Registered"
    assert "Certificate valid from" in names
    assert "Mentioned in OTX pulse (created)" in names
    assert [e["at"] for e in events] == sorted(e["at"] for e in events)


async def test_stix_bundle_is_valid_and_excludes_inferred(store, populated):
    data = json.loads(render(store, populated, "stix", Settings()))
    bundle = stix2.parse(data, allow_custom=False)
    types = {o.type for o in bundle.objects}
    assert {"identity", "domain-name", "ipv4-addr", "autonomous-system", "x509-certificate",
            "malware", "relationship", "indicator", "report"} <= types
    indicator = next(o for o in bundle.objects if o.type == "indicator")
    assert indicator.pattern == "[ipv4-addr:value = '198.51.100.7']"
    assert "malicious-activity" in indicator.indicator_types
    rel_types = {o.relationship_type for o in bundle.objects if o.type == "relationship"}
    assert "resolves-to" in rel_types and "shares-infrastructure" not in rel_types
    # Deterministic SCO IDs (STIX 2.1 section 2.9).
    domain = next(o for o in bundle.objects if o.type == "domain-name")
    assert domain.id == stix2.DomainName(value="example.com").id


class FakeKeyring:
    def __init__(self):
        self.data = {}

    def get_password(self, service, name):
        return self.data.get((service, name))

    def set_password(self, service, name, value):
        self.data[(service, name)] = value

    def delete_password(self, service, name):
        from keyring.errors import PasswordDeleteError

        if (service, name) not in self.data:
            raise PasswordDeleteError("missing")
        del self.data[(service, name)]


@pytest.fixture
def fake_keyring(monkeypatch):
    import keyring

    kr = FakeKeyring()
    for attr in ("get_password", "set_password", "delete_password"):
        monkeypatch.setattr(keyring, attr, getattr(kr, attr))
    monkeypatch.delenv("STRXEYE_KEY_VIRUSTOTAL", raising=False)
    return kr


def test_secrets_roundtrip(fake_keyring, monkeypatch):
    assert secrets.key_status()["virustotal"] is None
    secrets.set_key("virustotal", "  abc  ")
    assert secrets.get_key("virustotal") == "abc"
    assert secrets.key_status()["virustotal"] == "keychain"
    monkeypatch.setenv("STRXEYE_KEY_VIRUSTOTAL", "from-env")
    assert secrets.get_key("virustotal") == "from-env"
    assert secrets.key_status()["virustotal"] == "environment"
    assert secrets.delete_key("virustotal") is True
    assert secrets.delete_key("virustotal") is False
    with pytest.raises(KeyError):
        secrets.set_key("unknown", "x")


def test_cli_keys_never_echo_value(fake_keyring):
    runner = CliRunner()
    result = runner.invoke(cli.app, ["keys", "set", "virustotal"], input="supersecret\n")
    assert result.exit_code == 0, result.output
    assert "supersecret" not in result.output
    listing = runner.invoke(cli.app, ["keys", "list"])
    assert "keychain" in listing.output and "supersecret" not in listing.output


def test_version_compare():
    assert updater.is_newer("v1.0.1", "1.0.0")
    assert updater.is_newer("1.1", "1.0.9")
    assert not updater.is_newer("v1.0.0", "1.0")
    assert not updater.is_newer("0.9.9", "1.0.0")
    with pytest.raises(ValueError):
        updater.parse_version("latest")


RELEASE = {"tag_name": "v9.0.0", "html_url": "https://github.com/8BMW/StrxEye/releases/v9.0.0",
           "body": "notes", "assets": [
               {"name": "STRX-EYE-Setup-9.0.0.exe",
                "browser_download_url": "https://github.com/8BMW/StrxEye/releases/download/v9.0.0/STRX-EYE-Setup-9.0.0.exe"},
               {"name": "SHA256SUMS.txt",
                "browser_download_url": "https://github.com/8BMW/StrxEye/releases/download/v9.0.0/SHA256SUMS.txt"}]}


@respx.mock
async def test_update_check_and_verified_download(monkeypatch, tmp_path):
    monkeypatch.setattr(updater, "cache_dir", lambda: tmp_path)
    respx.get("https://api.github.com/repos/8BMW/StrxEye/releases/latest").mock(
        return_value=httpx.Response(200, json=RELEASE))
    payload = b"installer-bytes"
    respx.get(RELEASE["assets"][0]["browser_download_url"]).mock(
        return_value=httpx.Response(200, content=payload))
    sums = respx.get(RELEASE["assets"][1]["browser_download_url"]).mock(
        return_value=httpx.Response(200, text=f"{hashlib.sha256(payload).hexdigest()}  "
                                              "STRX-EYE-Setup-9.0.0.exe\n"))
    info = await updater.check(Settings())
    assert info.newer and info.latest == "9.0.0"
    path = await updater.download_installer(info, Settings())
    assert path.read_bytes() == payload

    sums.mock(return_value=httpx.Response(200, text="0" * 64 + "  STRX-EYE-Setup-9.0.0.exe\n"))
    with pytest.raises(updater.FetchError, match="does not match"):
        await updater.download_installer(info, Settings())


async def test_update_refuses_foreign_download_host():
    info = updater.UpdateInfo("1.0.0", "9.0.0", True, "", "", "STRX-EYE-Setup-9.0.0.exe",
                              "https://evil.example/setup.exe",
                              "https://github.com/8BMW/StrxEye/releases/download/v9/SHA256SUMS.txt",
                              False)
    with pytest.raises(updater.FetchError, match="unexpected location"):
        await updater.download_installer(info, Settings())


def test_self_install_only_in_frozen_windows_app(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    assert updater.can_self_install() is False
    with pytest.raises(RuntimeError):
        updater.launch_installer(updater.cache_dir() / "x.exe")


@pytest.fixture
def api(store, fake_keyring):
    app = create_app(store, "t", engine_factory=lambda s: Engine(
        Settings(), s, collectors={"x": Scripted("x", infrastructure)}, secret=lambda n: None))
    with TestClient(app, headers={"Authorization": "Bearer t"}) as client:
        yield client


async def test_api_v1_endpoints(api, store, populated):
    graph = api.get(f"/api/investigations/{populated}/graph").json()
    ids = {n["value"]: n["id"] for n in graph["nodes"]}
    path = api.get(f"/api/investigations/{populated}/path",
                   params={"source": ids["example.com"], "target": ids["QakBot"]}).json()
    assert path["length"] == 2
    analytics = api.get(f"/api/investigations/{populated}/analytics").json()
    assert analytics["communities"][0]["size"] >= 5
    assert api.get(f"/api/investigations/{populated}/timeline").json()[0]["event"] == "Registered"
    assert api.get("/api/search", params={"q": "QakBot"}).json()["entities"]
    assert api.get("/api/search", params={"q": "ab"}).status_code == 400
    stix = api.get(f"/api/investigations/{populated}/report", params={"format": "stix"})
    assert stix.headers["content-disposition"].endswith('.stix.json"')

    assert api.put("/api/keys/virustotal", json={"value": "zz-secret-zz"}).status_code == 204
    keys = api.get("/api/keys").json()
    assert {"name": "virustotal", "source": "keychain"}.items() <= keys[0].items()
    assert "zz-secret-zz" not in json.dumps(keys)
    assert api.put("/api/keys/nope", json={"value": "k"}).status_code == 404
    assert api.post("/api/update/install").status_code == 400
