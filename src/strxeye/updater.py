"""Update checks against GitHub Releases, and self-update for the Windows
app.

The check is one unauthenticated request to the GitHub API; nothing about
the user or their investigations is sent. Installation downloads the
release's Windows installer and refuses to run it unless its SHA-256
matches the SHA256SUMS.txt published in the same release. That protects
against corrupted or tampered downloads in transit; it does not protect
against a compromised release itself, which would need signed releases.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx

from . import __version__
from .config import Settings, cache_dir
from .net import FetchError, fetch, make_client

INSTALLER = re.compile(r"^STRX-EYE-Setup-[\d.]+\.exe$")
CHECKSUMS = "SHA256SUMS.txt"


@dataclass
class UpdateInfo:
    current: str
    latest: str
    newer: bool
    release_url: str
    notes: str
    installer_name: str | None
    installer_url: str | None
    checksums_url: str | None
    can_self_install: bool

    def as_dict(self) -> dict:
        return asdict(self)


def parse_version(text: str) -> tuple[int, ...]:
    match = re.match(r"^v?(\d+(?:\.\d+)*)", text.strip())
    if not match:
        raise ValueError(f"unrecognised version '{text}'")
    return tuple(int(p) for p in match.group(1).split("."))


def is_newer(latest: str, current: str) -> bool:
    a, b = parse_version(latest), parse_version(current)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


def can_self_install() -> bool:
    """Only the packaged Windows app can replace itself; pip installs are
    updated with pip."""
    return sys.platform == "win32" and bool(getattr(sys, "frozen", False))


async def check(settings: Settings, client: httpx.AsyncClient | None = None) -> UpdateInfo:
    repo = settings.updates.repository
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    own = client is None
    client = client or make_client(settings.network)
    try:
        response = await fetch(client, url, headers={"Accept": "application/vnd.github+json"},
                               retries=1, allow_statuses=(404,))
    finally:
        if own:
            await client.aclose()
    if response.status_code == 404:
        raise FetchError(f"{repo} has no published releases yet")
    data = response.json()
    assets = {a["name"]: a["browser_download_url"] for a in data.get("assets", [])}
    installer = next((n for n in assets if INSTALLER.match(n)), None)
    tag = data.get("tag_name", "")
    return UpdateInfo(
        current=__version__,
        latest=tag.lstrip("v"),
        newer=is_newer(tag, __version__),
        release_url=data.get("html_url", f"https://github.com/{repo}/releases"),
        notes=(data.get("body") or "")[:5000],
        installer_name=installer,
        installer_url=assets.get(installer) if installer else None,
        checksums_url=assets.get(CHECKSUMS),
        can_self_install=can_self_install(),
    )


def _expected_hash(checksums: str, name: str) -> str:
    for line in checksums.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name:
            return parts[0].lower()
    raise FetchError(f"{CHECKSUMS} does not list {name}")


def _check_origin(url: str, repo: str) -> None:
    prefix = f"https://github.com/{repo}/releases/download/"
    if not url.startswith(prefix):
        raise FetchError(f"refusing to download update from unexpected location {url}")


async def download_installer(info: UpdateInfo, settings: Settings,
                             client: httpx.AsyncClient | None = None) -> Path:
    if not (info.installer_url and info.checksums_url and info.installer_name):
        raise FetchError("the latest release has no Windows installer with checksums")
    repo = settings.updates.repository
    for url in (info.installer_url, info.checksums_url):
        _check_origin(url, repo)
    own = client is None
    client = client or make_client(settings.network)
    try:
        sums = await fetch(client, info.checksums_url, retries=1)
        expected = _expected_hash(sums.text, info.installer_name)
        target = cache_dir() / "updates" / info.installer_name
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        partial = target.with_suffix(".part")
        async with client.stream("GET", info.installer_url) as response:
            if not response.is_success:
                raise FetchError(f"installer download failed: HTTP {response.status_code}")
            with partial.open("wb") as fh:
                async for chunk in response.aiter_bytes():
                    digest.update(chunk)
                    fh.write(chunk)
    finally:
        if own:
            await client.aclose()
    if digest.hexdigest() != expected:
        partial.unlink(missing_ok=True)
        raise FetchError("downloaded installer does not match the published SHA-256; "
                         "update aborted")
    partial.replace(target)
    return target


def launch_installer(path: Path) -> None:
    if not can_self_install():
        raise RuntimeError("self-update is only available in the Windows app")
    # The installer closes the running app (CloseApplications in the .iss),
    # upgrades in place and restarts it.
    subprocess.Popen([str(path), "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART",  # noqa: S603
                      "/RESTARTAPPLICATIONS"], close_fds=True)
