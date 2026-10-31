"""Built-in collectors and the registry that also admits trusted plugins."""

from __future__ import annotations

from ..config import Settings
from .asn import AsnCollector
from .base import Collector, CollectorContext, Findings
from .certspotter import CertSpotterCollector
from .crtsh import CrtShCollector
from .dns_records import DnsCollector, ReverseDnsCollector
from .gleif import GleifCollector
from .internetdb import InternetDbCollector
from .passive_dns import PassiveDnsCollector
from .rdap import RdapCollector
from .reputation import OtxCollector, VirusTotalCollector
from .threatfeeds import ThreatFeedCollector
from .wayback import WaybackCollector
from .website import HttpCollector, TlsCollector

BUILTIN: tuple[type[Collector], ...] = (
    DnsCollector,
    RdapCollector,
    CrtShCollector,
    CertSpotterCollector,
    PassiveDnsCollector,
    ReverseDnsCollector,
    AsnCollector,
    InternetDbCollector,
    ThreatFeedCollector,
    OtxCollector,
    VirusTotalCollector,
    GleifCollector,
    WaybackCollector,
    HttpCollector,
    TlsCollector,
)


def registry(settings: Settings) -> dict[str, Collector]:
    from ..plugins import load_trusted_collectors

    collectors: dict[str, Collector] = {cls.name: cls() for cls in BUILTIN}
    for plugin in load_trusted_collectors(settings):
        if plugin.name in collectors:
            raise ValueError(f"plugin collector '{plugin.name}' clashes with a built-in name")
        collectors[plugin.name] = plugin
    return collectors


__all__ = ["BUILTIN", "Collector", "CollectorContext", "Findings", "registry"]
