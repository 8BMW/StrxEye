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
import re
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path

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


def info_dict(info: PluginInfo, settings: Settings) -> dict:
    """What can be shown about a plugin without importing it: entry point,
    package metadata, and whether this exact version is trusted."""
    summary = homepage = None
    for ep in entry_points(group=GROUP):
        if ep.name == info.name and ep.dist is not None:
            summary = ep.dist.metadata.get("Summary")
            homepage = ep.dist.metadata.get("Home-page") or next(
                (u.split(",", 1)[1].strip() for u in ep.dist.metadata.get_all("Project-URL") or []
                 if "," in u), None)
    return {"name": info.name, "package": info.distribution, "version": info.version,
            "entry_point": info.target, "summary": summary, "homepage": homepage,
            "trusted": is_trusted(info, settings), "trust_key": info.trust_key}


SCAFFOLD_PYPROJECT = '''[build-system]
requires = ["hatchling>=1.24"]
build-backend = "hatchling.build"

[project]
name = "strxeye-plugin-{slug}"
version = "0.1.0"
description = "STRX EYE collector: {title}"
requires-python = ">=3.12"
dependencies = ["strxeye>=1.1"]

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-asyncio>=0.23"]

[project.entry-points."strxeye.collectors"]
{name} = "{module}:{cls}"

[tool.hatch.build.targets.wheel]
packages = ["src/{module}"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
pythonpath = ["src"]
'''

SCAFFOLD_MODULE = '''"""STRX EYE collector plugin: {title}.

This starting point works as generated: it reads the TXT records of a
domain through the resolver STRX EYE is configured with. Replace the body
of collect() with your own source. Keep the rules from docs/plugins.md:
report only what the source returned, store raw responses as evidence,
and set `direct = True` if you contact the target itself.
"""

from __future__ import annotations

import dns.resolver
from strxeye.collectors.base import Collector, CollectorContext, Findings
from strxeye.models import EntityRef, EntityType


class {cls}(Collector):
    name = "{name}"
    title = "{title}"
    description = "TXT records of a domain (replace with what your source provides)."
    version = "0.1.0"
    sdk_version = 1
    accepts = frozenset({{EntityType.DOMAIN}})
    sources = ("configured DNS resolver",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        try:
            answer = await ctx.resolver.resolve(target.value, "TXT", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return found  # "nothing found" is a result, not an error
        if answer.rrset is None:
            return found
        evidence = found.add_evidence(f"{{target.value}} TXT", answer.rrset.to_text())
        for rdata in answer.rrset:
            text = b"".join(rdata.strings).decode("utf-8", "replace")
            found.observe(target, "{name}.txt", text, method="DNS TXT query",
                          evidence_id=evidence)
        return found
'''

SCAFFOLD_TEST = '''import dns.rrset

from strxeye.collectors.base import CollectorContext
from strxeye.config import Settings
from strxeye.models import EntityRef, EntityType
from strxeye.net import RateLimiter
from {module} import {cls}


class Answer:
    def __init__(self, rrset):
        self.rrset = rrset


class Resolver:
    nameservers = ["192.0.2.53"]

    async def resolve(self, name, rdtype, raise_on_no_answer=True):
        return Answer(dns.rrset.from_text(name + ".", 300, "IN", "TXT", '"hello"'))


async def test_collects_txt_records():
    ctx = CollectorContext(settings=Settings(), client=None, limiter=RateLimiter(0),
                           resolver=Resolver())
    target = EntityRef(type=EntityType.DOMAIN, value="example.com")
    found = await {cls}().collect(target, ctx)
    assert [o.value for o in found.observations] == ["hello"]
    assert found.observations[0].evidence_id in found.evidence
'''


def scaffold(name: str, parent: Path) -> Path:
    """Create a ready-to-install plugin package for collector `name`."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,40}", name):
        raise PluginError("plugin names use lowercase letters, digits and underscores, "
                          "starting with a letter")
    slug = name.replace("_", "-")
    module = f"strxeye_plugin_{name}"
    cls = "".join(part.title() for part in name.split("_")) + "Collector"
    title = name.replace("_", " ").title()
    root = Path(parent) / f"strxeye-plugin-{slug}"
    if root.exists():
        raise PluginError(f"{root} already exists")
    values = {"slug": slug, "module": module, "cls": cls, "name": name, "title": title}
    (root / "src" / module).mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pyproject.toml").write_text(SCAFFOLD_PYPROJECT.format(**values), encoding="utf-8")
    (root / "src" / module / "__init__.py").write_text(SCAFFOLD_MODULE.format(**values),
                                                       encoding="utf-8")
    (root / "tests" / f"test_{name}.py").write_text(SCAFFOLD_TEST.format(**values),
                                                    encoding="utf-8")
    (root / "README.md").write_text(
        f"# strxeye-plugin-{slug}\n\nSTRX EYE collector plugin.\n\n"
        "```bash\npip install -e \".[dev]\"\npytest\nstrxeye plugins trust "
        f"{name}\nstrxeye collectors\n```\n", encoding="utf-8")
    return root
