import time

import pytest
from fastapi.testclient import TestClient

from conftest import StaticCollector
from strxeye.config import Settings
from strxeye.engine import Engine
from strxeye.server import create_app

TOKEN = "test-token"


@pytest.fixture
def client(store, tmp_path):
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<html>app</html>")
    (tmp_path / "secret.txt").write_text("do not serve")

    def engine_factory(s):
        return Engine(Settings(), s, collectors={
            "dns": StaticCollector("dns"),
            "slow": StaticCollector("slow", delay=10),
        })

    app = create_app(store, TOKEN, engine_factory=engine_factory, static_dir=ui)
    with TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"}) as c:
        yield c


def wait_for(client, run_id, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] != "running":
            return run
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_token_required(client):
    assert client.get("/api/investigations", headers={"Authorization": "Bearer nope"}
                      ).status_code == 401
    assert client.get("/api/investigations", headers={"Authorization": ""}).status_code == 401


def test_cookie_auth_flow(client):
    fresh = TestClient(client.app)
    assert fresh.get("/auth?token=wrong", follow_redirects=False).status_code == 401
    assert fresh.get(f"/auth?token={TOKEN}", follow_redirects=False).status_code == 303
    assert fresh.get("/api/investigations").status_code == 200


def test_foreign_host_header_rejected(client):
    response = client.get("/api/meta", headers={"Host": "attacker.example"})
    assert response.status_code == 400


def test_static_files_cannot_escape_ui_folder(client):
    response = client.get("/..%2fsecret.txt")
    assert "do not serve" not in response.text
    assert client.get("/some/route").text == "<html>app</html>"


def test_full_investigation_flow(client):
    inv = client.post("/api/investigations", json={"name": "API case"}).json()
    bad = client.post(f"/api/investigations/{inv['id']}/runs", json={"target": "not valid!"})
    assert bad.status_code == 400

    started = client.post(f"/api/investigations/{inv['id']}/runs",
                          json={"target": "example.com", "collectors": ["dns"]})
    assert started.status_code == 202
    run = wait_for(client, started.json()["run_id"])
    assert run["status"] == "completed"
    assert run["collectors"][0]["status"] == "ok"

    entities = client.get(f"/api/investigations/{inv['id']}/entities?type=ip").json()
    assert [e["value"] for e in entities] == ["203.0.113.10"]
    detail = client.get(f"/api/investigations/{inv['id']}/entities/{entities[0]['id']}").json()
    assert detail["relationships"][0]["type"] == "resolves_to"

    graph = client.get(f"/api/investigations/{inv['id']}/graph").json()
    assert len(graph["nodes"]) == 2 and len(graph["edges"]) == 1

    evidence = client.get(f"/api/investigations/{inv['id']}/evidence").json()
    raw = client.get(f"/api/investigations/{inv['id']}/evidence/{evidence[0]['id']}").json()
    assert raw["content"] == "raw"

    report = client.get(f"/api/investigations/{inv['id']}/report?format=csv")
    assert report.headers["content-disposition"].endswith('.csv"')
    assert client.get(f"/api/investigations/{inv['id']}/report?format=exe").status_code == 400

    assert client.delete(f"/api/investigations/{inv['id']}").status_code == 204
    assert client.get(f"/api/investigations/{inv['id']}").status_code == 404


def test_cancel_run(client):
    inv = client.post("/api/investigations", json={"name": "cancel"}).json()
    run_id = client.post(f"/api/investigations/{inv['id']}/runs",
                         json={"target": "example.com", "collectors": ["slow"]}).json()["run_id"]
    time.sleep(0.1)
    assert client.get(f"/api/runs/{run_id}").json()["active"] == ["slow:example.com"]
    assert client.post(f"/api/runs/{run_id}/cancel").json() == {"cancelling": True}
    run = wait_for(client, run_id)
    assert run["status"] == "cancelled"
    assert run["collectors"][0]["status"] == "cancelled"


def test_settings_whitelist(client):
    ok = client.patch("/api/settings", json={"key": "collection.allow_direct", "value": "true"})
    assert ok.status_code == 200 and ok.json()["collection"]["allow_direct"] is True
    denied = client.patch("/api/settings", json={"key": "plugins.trusted", "value": "evil==1"})
    assert denied.status_code == 400
