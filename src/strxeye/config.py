"""User configuration.

Settings live in a small TOML file in the platform config directory. Set
``STRXEYE_HOME`` to keep config and data together in one folder instead
(useful for portable installs, tests and separate case workspaces).
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import platformdirs
from pydantic import BaseModel, Field

from . import __version__

APP_NAME = "strxeye"


class NetworkSettings(BaseModel):
    timeout: float = Field(default=20.0, gt=0, le=300)
    retries: int = Field(default=2, ge=0, le=5)
    user_agent: str = f"STRX-EYE/{__version__} (OSINT research tool)"


class DnsSettings(BaseModel):
    # Empty means "use the operating system resolver configuration".
    nameservers: list[str] = Field(default_factory=list)


class CollectionSettings(BaseModel):
    # Direct collectors (HTTP, TLS) connect to the target's own servers.
    # They are off by default so a fresh install only talks to third-party
    # public sources (DNS resolvers, RDAP registries, CT logs, archives).
    allow_direct: bool = False
    collector_timeout: float = Field(default=60.0, gt=0, le=600)
    max_subdomains: int = Field(default=500, ge=0, le=20000)
    max_certificates: int = Field(default=100, ge=0, le=5000)
    max_expansions: int = Field(default=25, ge=0, le=500)


class PluginSettings(BaseModel):
    trusted: list[str] = Field(default_factory=list)


class Settings(BaseModel):
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    dns: DnsSettings = Field(default_factory=DnsSettings)
    collection: CollectionSettings = Field(default_factory=CollectionSettings)
    plugins: PluginSettings = Field(default_factory=PluginSettings)


def home_override() -> Path | None:
    value = os.environ.get("STRXEYE_HOME")
    return Path(value).expanduser() if value else None


def config_dir() -> Path:
    return home_override() or Path(platformdirs.user_config_dir(APP_NAME, appauthor=False))


def data_dir() -> Path:
    return home_override() or Path(platformdirs.user_data_dir(APP_NAME, appauthor=False))


def config_path() -> Path:
    return config_dir() / "config.toml"


def database_path() -> Path:
    return data_dir() / "strxeye.db"


def load_settings(path: Path | None = None) -> Settings:
    path = path or config_path()
    if not path.exists():
        return Settings()
    with path.open("rb") as fh:
        raw = tomllib.load(fh)
    return Settings.model_validate(raw)


def save_settings(settings: Settings, path: Path | None = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_to_toml(settings.model_dump()), encoding="utf-8")
    return path


def set_value(settings: Settings, dotted_key: str, raw_value: str) -> Settings:
    """Return a copy of ``settings`` with one key changed, validated by pydantic."""
    section, _, key = dotted_key.partition(".")
    data = settings.model_dump()
    if section not in data or key not in data[section]:
        known = ", ".join(f"{s}.{k}" for s, keys in data.items() for k in keys)
        raise KeyError(f"unknown setting '{dotted_key}'. Known settings: {known}")
    current = data[section][key]
    if isinstance(current, bool):
        if raw_value.lower() not in ("true", "false", "1", "0", "yes", "no"):
            raise ValueError(f"'{dotted_key}' expects true or false")
        value: object = raw_value.lower() in ("true", "1", "yes")
    elif isinstance(current, list):
        value = [item.strip() for item in raw_value.split(",") if item.strip()]
    else:
        value = raw_value
    data[section][key] = value
    return Settings.model_validate(data)


def _to_toml(data: dict) -> str:
    # The settings schema is two levels of scalars and string lists, so a
    # tiny writer is enough and avoids another dependency.
    lines: list[str] = []
    for section, values in data.items():
        lines.append(f"[{section}]")
        for key, value in values.items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    return "\n".join(lines)


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
