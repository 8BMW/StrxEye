"""Desktop launcher: runs the local API in-process and shows the UI in a
native window (Edge WebView2 on Windows, WebKit on macOS, GTK/Qt on Linux
through pywebview). Without pywebview it falls back to the default browser.

The server binds to a random free loopback port with a fresh token each
launch, so two copies of the app never collide and nothing else on the
machine can predict where the API is.
"""

from __future__ import annotations

import logging
import os
import secrets
import socket
import sys
import threading
import time
import webbrowser
from logging.handlers import RotatingFileHandler

import httpx

from . import __version__
from .config import data_dir, database_path

log = logging.getLogger("strxeye.desktop")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _setup_logging() -> None:
    # A windowed executable has no console, so errors would otherwise vanish.
    logs = data_dir() / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(logs / "desktop.log", maxBytes=1_000_000, backupCount=3,
                                  encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def start_server(token: str, port: int):
    import uvicorn

    from .server import bundled_ui_dir, create_app
    from .storage import Store

    store = Store(database_path())
    app = create_app(store, token, static_dir=bundled_ui_dir(),
                     exit_after_update=lambda: os._exit(0))
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, name="strxeye-api", daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise RuntimeError("the local engine did not start; see the log file")
        time.sleep(0.05)
    return server, thread


def self_test(token: str, port: int) -> int:
    """Start the engine, call the API once, exit. Used by CI on the built
    executable to prove the packaged app actually runs."""
    server, thread = start_server(token, port)
    try:
        response = httpx.get(f"http://127.0.0.1:{port}/api/meta",
                             headers={"Authorization": f"Bearer {token}"}, timeout=10)
        ok = response.status_code == 200 and response.json()["version"] == __version__
        ui = httpx.get(f"http://127.0.0.1:{port}/", timeout=10)
        ok = ok and ui.status_code == 200 and "<div id=\"root\">" in ui.text
        log.info("self-test %s (api %s, ui %s)", "passed" if ok else "failed",
                 response.status_code, ui.status_code)
        return 0 if ok else 1
    finally:
        server.should_exit = True
        thread.join(5)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    _setup_logging()
    token = secrets.token_urlsafe(24)
    port = _free_port()
    if "--self-test" in argv:
        return self_test(token, port)

    log.info("starting STRX EYE %s on port %s", __version__, port)
    try:
        server, thread = start_server(token, port)
    except Exception:
        log.exception("engine failed to start")
        raise
    url = f"http://127.0.0.1:{port}/auth?token={token}"
    try:
        import webview
    except ImportError:
        webview = None

    if webview is None:
        print(f"Opening {url.split('?')[0]} in your browser. Press Ctrl+C to quit.")
        webbrowser.open(url)
        try:
            while thread.is_alive():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
    else:
        webview.create_window("STRX EYE", url, width=1440, height=900, min_size=(1024, 640),
                              background_color="#0a0e16")
        # Persistent storage keeps the theme choice between launches; the
        # session cookie is re-issued on every start anyway.
        webview.start(private_mode=False, storage_path=str(data_dir() / "webview"))
    server.should_exit = True
    thread.join(5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
