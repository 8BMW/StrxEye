"""HTTP plumbing shared by collectors: client factory, retries, rate limits
and the SSRF guard used before contacting any user-supplied host."""

from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import time
from collections.abc import Iterable
from urllib.parse import urlsplit

import httpx

from .config import NetworkSettings

RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_RETRY_AFTER = 30.0


class FetchError(Exception):
    """A remote source could not be reached or returned an unusable response."""


class UnsafeTargetError(Exception):
    """Refused to connect because the host resolves to a non-public address."""


def make_client(settings: NetworkSettings, **kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(settings.timeout, connect=min(10.0, settings.timeout)),
        headers={"User-Agent": settings.user_agent},
        follow_redirects=kwargs.pop("follow_redirects", True),
        **kwargs,
    )


class RateLimiter:
    """Minimum spacing between requests per key (usually a hostname).

    Public sources such as crt.sh and RDAP registries throttle aggressively;
    spacing requests out costs little and avoids being blocked mid-run.
    """

    def __init__(self, default_interval: float = 0.0):
        self.default_interval = default_interval
        self.intervals: dict[str, float] = {}
        self._next: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def set_interval(self, key: str, seconds: float) -> None:
        self.intervals[key] = seconds

    async def wait(self, key: str) -> None:
        interval = self.intervals.get(key, self.default_interval)
        if interval <= 0:
            return
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            now = time.monotonic()
            ready_at = self._next.get(key, now)
            if ready_at > now:
                await asyncio.sleep(ready_at - now)
            self._next[key] = max(now, ready_at) + interval


async def fetch(
    client: httpx.AsyncClient,
    url: str,
    *,
    retries: int = 2,
    limiter: RateLimiter | None = None,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    allow_statuses: Iterable[int] = (),
) -> httpx.Response:
    """GET with bounded retries on transient failures.

    Returns the response for 2xx and any status listed in ``allow_statuses``
    (RDAP uses 404 to mean "no such object", which is data, not an error).
    """
    allowed = set(allow_statuses)
    host = urlsplit(url).hostname or ""
    last_error = ""
    for attempt in range(retries + 1):
        if limiter:
            await limiter.wait(host)
        try:
            response = await client.get(url, headers=headers, params=params)
        except httpx.TimeoutException:
            last_error = f"timed out contacting {host}"
        except httpx.TransportError as exc:
            last_error = f"could not connect to {host}: {exc.__class__.__name__}"
        else:
            if response.is_success or response.status_code in allowed:
                return response
            last_error = f"{host} returned HTTP {response.status_code}"
            if response.status_code not in RETRY_STATUSES:
                break
            if attempt < retries:
                await asyncio.sleep(_retry_delay(response, attempt))
                continue
            break
        if attempt < retries:
            await asyncio.sleep(_backoff(attempt))
    raise FetchError(last_error)


async def post(
    client: httpx.AsyncClient,
    url: str,
    *,
    data: dict[str, str] | None = None,
    json_body: dict | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 2,
    limiter: RateLimiter | None = None,
) -> httpx.Response:
    """POST with the same retry rules as fetch(). Used by APIs that only
    accept form or JSON bodies (abuse.ch)."""
    host = urlsplit(url).hostname or ""
    last_error = ""
    for attempt in range(retries + 1):
        if limiter:
            await limiter.wait(host)
        try:
            response = await client.post(url, data=data, json=json_body, headers=headers)
        except httpx.TimeoutException:
            last_error = f"timed out contacting {host}"
        except httpx.TransportError as exc:
            last_error = f"could not connect to {host}: {exc.__class__.__name__}"
        else:
            if response.is_success:
                return response
            last_error = f"{host} returned HTTP {response.status_code}"
            if response.status_code not in RETRY_STATUSES:
                break
        if attempt < retries:
            await asyncio.sleep(_backoff(attempt))
    raise FetchError(last_error)


def _backoff(attempt: int) -> float:
    return min(8.0, 0.5 * 2**attempt) + random.uniform(0, 0.25)  # noqa: S311 - jitter, not crypto


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    header = response.headers.get("Retry-After", "")
    if header.isdigit():
        return min(float(header), MAX_RETRY_AFTER)
    return _backoff(attempt)


def is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def ensure_public_host(host: str, port: int = 443) -> list[str]:
    """Resolve ``host`` and refuse if any address is private, loopback,
    link-local or otherwise non-global.

    This stops investigation data (a domain pointing at 127.0.0.1 or a
    cloud metadata address) from turning direct collectors into a way to
    probe the analyst's own network. There is a small window between this
    check and the real connection in which DNS could change (rebinding);
    collectors that connect themselves should connect to one of the
    returned addresses rather than resolving again.
    """
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise FetchError(f"could not resolve {host}: {exc.strerror}") from None
        addresses = sorted({info[4][0] for info in infos})
    blocked = [a for a in addresses if not is_public_address(a)]
    if blocked:
        raise UnsafeTargetError(
            f"{host} resolves to non-public address {', '.join(blocked)}; "
            "direct collection is only allowed against public hosts"
        )
    return addresses
