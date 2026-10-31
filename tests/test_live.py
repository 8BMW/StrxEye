"""Checks against real public services. Not run by default because they
depend on the network and on third parties being up:

    pytest -m live
"""

import pytest

from strxeye.config import Settings
from strxeye.engine import Engine, RunOptions
from strxeye.models import CollectionStatus, EntityRef, EntityType

pytestmark = pytest.mark.live


async def collect(target, *names, direct=False):
    report = await Engine(Settings()).run(target, RunOptions(collectors=list(names),
                                                             direct=direct))
    return {r.collector: r for r in report.results}


async def test_dns_and_rdap_for_example_com():
    results = await collect(EntityRef(type=EntityType.DOMAIN, value="example.com"), "dns", "rdap")
    assert results["dns"].status is CollectionStatus.OK, results["dns"].error
    assert any(o.kind == "dns.a" for o in results["dns"].observations)
    assert results["rdap"].status is CollectionStatus.OK, results["rdap"].error
    assert any(o.kind == "rdap.registration" for o in results["rdap"].observations)


async def test_asn_and_rdap_for_1_1_1_1():
    results = await collect(EntityRef(type=EntityType.IP, value="1.1.1.1"), "asn", "rdap")
    assert any(o.value == "AS13335" for o in results["asn"].observations), results["asn"].error
    assert results["rdap"].status is CollectionStatus.OK, results["rdap"].error


async def test_direct_tls_and_http():
    results = await collect(EntityRef(type=EntityType.DOMAIN, value="example.com"),
                            "tls", "http", direct=True)
    assert results["tls"].status is CollectionStatus.OK, results["tls"].error
    assert any(o.kind == "tls.verified" and o.value for o in results["tls"].observations)
    assert results["http"].status in (CollectionStatus.OK, CollectionStatus.PARTIAL), \
        results["http"].error
