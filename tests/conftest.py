from __future__ import annotations

import asyncio

import dns.exception
import dns.resolver
import dns.rrset
import httpx
import pytest

from strxeye.collectors.base import Collector, CollectorContext, Findings
from strxeye.config import Settings
from strxeye.models import EntityType, RelationType
from strxeye.net import RateLimiter
from strxeye.storage import Store


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Never touch the real user config or database from tests."""
    monkeypatch.setenv("STRXEYE_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "test.db")
    yield s
    s.close()


class FakeAnswer:
    def __init__(self, rrset):
        self.rrset = rrset


class FakeResolver:
    """Stands in for dns.asyncresolver.Resolver with canned records."""

    nameservers = ["192.0.2.53"]

    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None,
                 nxdomain: set[str] = frozenset(), timeouts: set[tuple[str, str]] = frozenset()):
        self.records = records or {}
        self.nxdomain = set(nxdomain)
        self.timeouts = set(timeouts)

    async def resolve(self, name, rdtype, raise_on_no_answer=True):
        name = str(name).rstrip(".")
        if (name, rdtype) in self.timeouts:
            raise dns.exception.Timeout()
        if name in self.nxdomain:
            raise dns.resolver.NXDOMAIN()
        values = self.records.get((name, rdtype))
        if not values:
            return FakeAnswer(None)
        return FakeAnswer(dns.rrset.from_text(name + ".", 300, "IN", rdtype, *values))

    async def resolve_address(self, address, raise_on_no_answer=True):
        import dns.reversename

        rev = dns.reversename.from_address(address).to_text().rstrip(".")
        return await self.resolve(rev, "PTR")


@pytest.fixture
async def make_ctx():
    clients = []

    def factory(resolver=None, settings=None):
        client = httpx.AsyncClient()
        clients.append(client)
        return CollectorContext(settings=settings or Settings(), client=client,
                                limiter=RateLimiter(0), resolver=resolver or FakeResolver())

    yield factory
    for client in clients:
        await client.aclose()


class StaticCollector(Collector):
    """Test collector producing a fixed set of findings."""

    title = "static"
    description = "test"
    accepts = frozenset({EntityType.DOMAIN})

    def __init__(self, name="static", ips=("203.0.113.10",), delay=0.0, error=None,
                 accepts=None, direct=False):
        self.name = name
        self.ips = ips
        self.delay = delay
        self.error = error
        self.direct = direct
        if accepts:
            self.accepts = frozenset(accepts)

    async def collect(self, target, ctx):
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        found = Findings(self.name)
        ev = found.add_evidence(f"static {target.value}", "raw")
        for ip in self.ips:
            ref = found.entity(EntityType.IP, ip)
            found.observe(target, "dns.a", ip, method="test", evidence_id=ev)
            found.relate(target, RelationType.RESOLVES_TO, ref, evidence_id=ev)
        return found
