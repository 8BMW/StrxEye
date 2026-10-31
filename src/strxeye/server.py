"""Local HTTP API used by the desktop app.

Security model: the server binds to 127.0.0.1 only and every /api request
must carry the per-launch token, either as a bearer header (the Tauri shell
and the dev proxy) or as an HttpOnly cookie set by visiting the /auth link
printed at start-up (browser use, same pattern as Jupyter). The Host header
is restricted to loopback names, which blocks DNS-rebinding attacks from
web pages the analyst has open in a browser.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from . import __version__, analytics, updater
from . import secrets as keystore
from .collectors import registry
from .config import database_path, load_settings, save_settings, set_value
from .engine import Engine, EngineError, RunEvent, RunOptions
from .graph import build_graph
from .history import diff_runs
from .reporting import FORMATS, render
from .storage import NotFoundError, Store
from .targets import TargetError, parse_target

COOKIE = "strxeye_token"
log = logging.getLogger(__name__)
EDITABLE_SETTINGS = {
    "updates.check_on_start",
    "collection.allow_direct", "collection.collector_timeout", "collection.max_subdomains",
    "collection.max_certificates", "collection.max_expansions", "network.timeout",
    "network.retries", "dns.nameservers",
}


class NewInvestigation(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)


class InvestigationUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)


class NewRun(BaseModel):
    target: str = Field(min_length=1, max_length=2000)
    collectors: list[str] | None = None
    direct: bool = False
    expand: bool = False


class SettingChange(BaseModel):
    key: str
    value: str = Field(max_length=2000)


class KeyValue(BaseModel):
    value: str = Field(min_length=1, max_length=500)


@dataclass
class ActiveRun:
    task: asyncio.Task
    cancel: asyncio.Event
    running: set[str] = field(default_factory=set)


def create_app(store: Store, token: str, engine_factory=None,
               static_dir: Path | None = None, exit_after_update=None) -> FastAPI:
    active: dict[str, ActiveRun] = {}
    update_cache: dict[str, object] = {}

    def make_engine() -> Engine:
        if engine_factory:
            return engine_factory(store)
        return Engine(load_settings(), store)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        store.fail_interrupted_runs()
        yield
        for run in active.values():
            run.cancel.set()
        await asyncio.gather(*(r.task for r in active.values()), return_exceptions=True)

    app = FastAPI(title="STRX EYE local API", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"])

    @app.middleware("http")
    async def require_token(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            header = request.headers.get("authorization", "")
            supplied = header[7:] if header.lower().startswith("bearer ") else \
                request.cookies.get(COOKIE, "")
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                return JSONResponse({"detail": "missing or invalid API token"}, status_code=401)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.exception_handler(NotFoundError)
    async def not_found(_: Request, exc: NotFoundError):
        return JSONResponse({"detail": str(exc).strip("'\"")}, status_code=404)

    @app.exception_handler(ValueError)
    async def bad_value(_: Request, exc: ValueError):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.get("/auth")
    def auth(token_: str = Query(alias="token")):
        if not hmac.compare_digest(token_.encode(), token.encode()):
            raise HTTPException(401, "invalid token")
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict")
        return response

    # Meta and settings ---------------------------------------------------

    @app.get("/api/meta")
    def meta() -> dict[str, Any]:
        settings = load_settings()
        return {
            "version": __version__,
            "database": str(store.path),
            "collectors": [c.describe() for c in registry(settings).values()],
            "settings": settings.model_dump(),
            "editable_settings": sorted(EDITABLE_SETTINGS),
        }

    @app.patch("/api/settings")
    def change_setting(change: SettingChange) -> dict[str, Any]:
        if change.key not in EDITABLE_SETTINGS:
            raise HTTPException(400, f"'{change.key}' cannot be changed from the app")
        try:
            settings = set_value(load_settings(), change.key, change.value)
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc).strip("'\"")) from None
        save_settings(settings)
        store.audit("settings.change", None, {"key": change.key, "value": change.value})
        return settings.model_dump()

    @app.get("/api/keys")
    def keys():
        status = keystore.key_status()
        return [{"name": n, "description": d, "source": status[n]}
                for n, d in keystore.KNOWN_KEYS.items()]

    @app.put("/api/keys/{name}", status_code=204)
    def set_key(name: str, body: KeyValue):
        try:
            keystore.set_key(name, body.value)
        except KeyError as exc:
            raise HTTPException(404, str(exc).strip("'\"")) from None
        except keystore.SecretStoreError as exc:
            raise HTTPException(500, str(exc)) from None
        store.audit("key.set", None, {"name": name})
        return Response(status_code=204)

    @app.delete("/api/keys/{name}", status_code=204)
    def delete_key(name: str):
        try:
            keystore.delete_key(name)
        except KeyError as exc:
            raise HTTPException(404, str(exc).strip("'\"")) from None
        store.audit("key.delete", None, {"name": name})
        return Response(status_code=204)

    @app.get("/api/update")
    async def update_check(force: bool = False):
        cached = update_cache.get("info")
        if cached and not force and time.time() - update_cache["at"] < 3600:  # type: ignore[operator]
            return cached
        try:
            info = (await updater.check(load_settings())).as_dict()
        except updater.FetchError as exc:
            raise HTTPException(502, str(exc)) from None
        update_cache.update(info=info, at=time.time())
        return info

    @app.post("/api/update/install")
    async def update_install():
        if not updater.can_self_install():
            raise HTTPException(400, "automatic installation is only available in the Windows "
                                     "app; pip users run: pip install -U strxeye")
        settings = load_settings()
        try:
            info = await updater.check(settings)
            if not info.newer:
                raise HTTPException(400, f"already up to date ({info.current})")
            path = await updater.download_installer(info, settings)
        except updater.FetchError as exc:
            raise HTTPException(502, str(exc)) from None
        store.audit("update.install", None, {"version": info.latest})
        updater.launch_installer(path)
        if exit_after_update:
            asyncio.get_running_loop().call_later(1.5, exit_after_update)
        return {"installing": info.latest}

    @app.get("/api/search")
    def search(q: str = Query(min_length=1, max_length=200), investigation: str | None = None,
               limit: int = Query(50, ge=1, le=500)):
        inv_id = store.resolve_investigation_id(investigation) if investigation else None
        return store.search(q, inv_id, limit)

    @app.get("/api/audit")
    def audit(limit: int = Query(200, ge=1, le=2000)):
        return store.audit_log(limit)

    # Investigations ---------------------------------------------------------

    @app.get("/api/investigations")
    def list_investigations():
        return store.list_investigations()

    @app.post("/api/investigations", status_code=201)
    def create_investigation(body: NewInvestigation):
        return store.create_investigation(body.name, body.description).model_dump(mode="json")

    @app.get("/api/investigations/{inv_id}")
    def get_investigation(inv_id: str):
        inv = store.get_investigation(inv_id)
        return {**inv.model_dump(mode="json"), "counts": store.counts(inv.id),
                "runs": store.list_runs(inv.id)}

    @app.patch("/api/investigations/{inv_id}")
    def update_investigation(inv_id: str, body: InvestigationUpdate):
        inv = store.get_investigation(inv_id)
        store.rename_investigation(inv.id, body.name, body.description)
        return store.get_investigation(inv.id).model_dump(mode="json")

    @app.delete("/api/investigations/{inv_id}", status_code=204)
    async def delete_investigation(inv_id: str):
        inv = store.get_investigation(inv_id)
        for run_id, run in list(active.items()):
            if store.get_run(run_id)["investigation_id"] == inv.id:
                run.cancel.set()
                await asyncio.gather(run.task, return_exceptions=True)
        store.delete_investigation(inv.id)
        return Response(status_code=204)

    # Runs -------------------------------------------------------------------

    @app.post("/api/investigations/{inv_id}/runs", status_code=202)
    async def start_run(inv_id: str, body: NewRun):
        inv = store.get_investigation(inv_id)
        try:
            target = parse_target(body.target)
        except TargetError as exc:
            raise HTTPException(400, str(exc)) from None
        engine = make_engine()
        options = RunOptions(collectors=body.collectors or None, direct=body.direct,
                             expand=body.expand)
        try:
            engine.select(target, options)
        except EngineError as exc:
            raise HTTPException(400, str(exc)) from None
        run_id = engine.prepare_run(inv.id, target, options)
        cancel = asyncio.Event()
        state = ActiveRun(task=None, cancel=cancel)  # type: ignore[arg-type]

        def on_event(event: RunEvent) -> None:
            label = f"{event.collector}:{event.target.value}"
            (state.running.add if event.kind == "started" else state.running.discard)(label)

        async def work():
            try:
                await engine.run(target, options, investigation_id=inv.id, on_event=on_event,
                                 cancel=cancel, run_id=run_id)
            except Exception:
                # The engine has already marked the run failed; log for debugging.
                log.exception("run %s failed", run_id)
            finally:
                active.pop(run_id, None)

        state.task = asyncio.create_task(work())
        active[run_id] = state
        return {"run_id": run_id, "target": target.model_dump(mode="json")}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str):
        run = store.get_run(run_id)
        state = active.get(run_id)
        run["active"] = sorted(state.running) if state else []
        return run

    @app.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str):
        store.get_run(run_id)
        state = active.get(run_id)
        if state:
            state.cancel.set()
        return {"cancelling": state is not None}

    # Entities, graph, evidence -----------------------------------------------

    @app.get("/api/investigations/{inv_id}/entities")
    def entities(inv_id: str, type: str | None = None, search: str | None = None,
                 limit: int = Query(500, ge=1, le=5000), offset: int = Query(0, ge=0)):
        inv = store.get_investigation(inv_id)
        return store.entities(inv.id, type, search, limit, offset)

    @app.get("/api/investigations/{inv_id}/entities/{entity_id}")
    def entity(inv_id: str, entity_id: int):
        return store.entity_detail(store.resolve_investigation_id(inv_id), entity_id)

    @app.get("/api/investigations/{inv_id}/graph")
    def graph(inv_id: str, inferred: bool = True):
        return build_graph(store, store.resolve_investigation_id(inv_id), inferred)

    @app.get("/api/investigations/{inv_id}/analytics")
    def graph_analytics(inv_id: str):
        data = build_graph(store, store.resolve_investigation_id(inv_id), False)
        result = analytics.summarize(data)
        result["membership"] = {str(k): v for k, v in result["membership"].items()}
        return result

    @app.get("/api/investigations/{inv_id}/path")
    def graph_path(inv_id: str, source: int, target: int, inferred: bool = False):
        data = build_graph(store, store.resolve_investigation_id(inv_id), inferred)
        path = analytics.shortest_path(data, source, target, inferred)
        if path is None:
            raise HTTPException(404, "these entities are not connected")
        return path

    @app.get("/api/investigations/{inv_id}/timeline")
    def timeline(inv_id: str):
        inv = store.resolve_investigation_id(inv_id)
        return analytics.timeline(store.all_observations(inv),
                                  store.entities(inv, "certificate", limit=100_000))

    @app.get("/api/investigations/{inv_id}/evidence")
    def evidence_list(inv_id: str):
        return store.list_evidence(store.resolve_investigation_id(inv_id))

    @app.get("/api/investigations/{inv_id}/evidence/{evidence_id}")
    def evidence(inv_id: str, evidence_id: str):
        return store.evidence(store.resolve_investigation_id(inv_id), evidence_id)

    @app.get("/api/investigations/{inv_id}/diff")
    def diff(inv_id: str, older: str, newer: str):
        return diff_runs(store, store.resolve_investigation_id(inv_id), older, newer)

    @app.get("/api/investigations/{inv_id}/report")
    def report(inv_id: str, format: str = "html"):
        if format not in FORMATS:
            raise HTTPException(400, f"format must be one of {', '.join(FORMATS)}")
        inv = store.get_investigation(inv_id)
        body = render(store, inv.id, format, load_settings())
        media = {"html": "text/html", "json": "application/json", "csv": "text/csv",
                 "stix": "application/stix+json"}[format]
        ext = "stix.json" if format == "stix" else format
        return Response(body, media_type=f"{media}; charset=utf-8", headers={
            "Content-Disposition": f'attachment; filename="strxeye-{inv.id}.{ext}"'})

    # Bundled web UI (when built) ---------------------------------------------

    if static_dir and (static_dir / "index.html").exists():
        root = static_dir.resolve()

        @app.get("/{path:path}", include_in_schema=False)
        def ui(path: str):
            candidate = (root / path).resolve()
            # Serve only files inside the UI folder; anything else falls
            # back to index.html for client-side routing.
            if path and candidate.is_file() and candidate.is_relative_to(root):
                return FileResponse(candidate)
            return FileResponse(root / "index.html")

    return app


def bundled_ui_dir() -> Path | None:
    candidate = Path(str(files("strxeye"))) / "web"
    return candidate if (candidate / "index.html").exists() else None


def run_server(port: int = 8765, token: str | None = None) -> None:
    import uvicorn

    token = token or secrets.token_urlsafe(24)
    store = Store(database_path())
    ui = bundled_ui_dir()
    app = create_app(store, token, static_dir=ui, exit_after_update=lambda: os._exit(0))
    print(f"STRX EYE {__version__} API on http://127.0.0.1:{port}")
    if ui:
        print(f"Open the app: http://127.0.0.1:{port}/auth?token={token}")
    else:
        print("Web UI not bundled in this install; API only.")
    print("Press Ctrl+C to stop.", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
