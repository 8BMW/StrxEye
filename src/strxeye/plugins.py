"""Third-party collector plugins.

Plugins are ordinary Python packages that declare an entry point in the
``strxeye.collectors`` group pointing at a ``Collector`` subclass.

Installing a package is not enough to run it: discovery only reads entry
point metadata (no plugin code is imported), and a plugin is loaded only
after the user explicitly trusts it by name with ``strxeye plugins trust``.
Trust is recorded together with the distribution version, so an upgraded
plugin has to be trusted again before it runs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from importlib.metadata import entry_points

from .collectors.base import Collector
from .config import Settings

GROUP = "strxeye.collectors"
SDK_VERSION = 1
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PluginInfo:
    name: str
    target: str
    distribution: str
    version: str

    @property
    def trust_key(self) -> str:
        return f"{self.name}=={self.version}"


class PluginError(Exception):
    pass


def discover() -> list[PluginInfo]:
    found = []
    for ep in entry_points(group=GROUP):
        dist = ep.dist
        found.append(PluginInfo(
            name=ep.name,
            target=ep.value,
            distribution=dist.metadata["Name"] if dist else "unknown",
            version=dist.version if dist else "0",
        ))
    return sorted(found, key=lambda p: p.name)


def is_trusted(info: PluginInfo, settings: Settings) -> bool:
    return info.trust_key in settings.plugins.trusted


def load_trusted_collectors(settings: Settings) -> list[Collector]:
    loaded: list[Collector] = []
    if not settings.plugins.trusted:
        return loaded
    eps = {ep.name: ep for ep in entry_points(group=GROUP)}
    for info in discover():
        if not is_trusted(info, settings):
            continue
        try:
            cls = eps[info.name].load()
        except Exception as exc:  # noqa: BLE001 - a broken plugin must not break the app
            log.warning("plugin %s failed to load: %s", info.name, exc)
            continue
        if not (isinstance(cls, type) and issubclass(cls, Collector)):
            log.warning("plugin %s does not provide a Collector subclass", info.name)
            continue
        required = getattr(cls, "sdk_version", SDK_VERSION)
        if required != SDK_VERSION:
            log.warning("plugin %s targets SDK v%s; this build provides v%s",
                        info.name, required, SDK_VERSION)
            continue
        loaded.append(cls())
    return loaded
