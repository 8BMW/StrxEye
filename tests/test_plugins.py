from dataclasses import dataclass

import pytest

from strxeye import plugins
from strxeye.collectors import registry
from strxeye.collectors.base import Collector, Findings
from strxeye.config import Settings
from strxeye.models import EntityType

LOADED: list[str] = []


class PluginCollector(Collector):
    name = "plug"
    title = "plug"
    description = "test plugin"
    accepts = frozenset({EntityType.DOMAIN})

    async def collect(self, target, ctx):
        return Findings(self.name)


class WrongSdk(PluginCollector):
    name = "oldsdk"
    sdk_version = 0


@dataclass
class FakeDist:
    version: str
    metadata: dict


class FakeEntryPoint:
    def __init__(self, name, obj, version="1.2.0"):
        self.name = name
        self.value = f"fake_module:{name}"
        self.dist = FakeDist(version, {"Name": f"strxeye-{name}"})
        self._obj = obj

    def load(self):
        LOADED.append(self.name)
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


@pytest.fixture
def fake_eps(monkeypatch):
    LOADED.clear()
    eps = [FakeEntryPoint("plug", PluginCollector), FakeEntryPoint("broken", ImportError("x")),
           FakeEntryPoint("oldsdk", WrongSdk), FakeEntryPoint("notacollector", object)]
    monkeypatch.setattr(plugins, "entry_points", lambda group: eps)
    return eps


def settings_trusting(*keys):
    s = Settings()
    s.plugins.trusted = list(keys)
    return s


def test_discovery_does_not_import_plugins(fake_eps):
    found = plugins.discover()
    assert [p.name for p in found] == ["broken", "notacollector", "oldsdk", "plug"]
    assert LOADED == []


def test_untrusted_plugins_never_load(fake_eps):
    assert plugins.load_trusted_collectors(Settings()) == []
    assert "plug" not in registry(Settings())
    assert LOADED == []


def test_trust_is_bound_to_version(fake_eps):
    assert plugins.load_trusted_collectors(settings_trusting("plug==1.1.0")) == []
    loaded = plugins.load_trusted_collectors(settings_trusting("plug==1.2.0"))
    assert [c.name for c in loaded] == ["plug"]
    assert "plug" in registry(settings_trusting("plug==1.2.0"))


def test_broken_or_incompatible_plugins_are_skipped(fake_eps):
    trusted = settings_trusting("broken==1.2.0", "oldsdk==1.2.0", "notacollector==1.2.0")
    assert plugins.load_trusted_collectors(trusted) == []


def test_plugin_cannot_replace_builtin(monkeypatch):
    class Impostor(PluginCollector):
        name = "dns"

    monkeypatch.setattr(plugins, "entry_points", lambda group: [FakeEntryPoint("dns", Impostor)])
    with pytest.raises(ValueError, match="clashes"):
        registry(settings_trusting("dns==1.2.0"))
