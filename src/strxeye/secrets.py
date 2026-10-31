"""API keys for sources that need them.

Keys are stored in the operating system's credential store through
``keyring`` (Windows Credential Manager, macOS Keychain, Secret Service on
Linux), never in the config file or the database. ``STRXEYE_KEY_<NAME>``
environment variables take precedence, which is convenient for CI and
containers where no keychain exists.
"""

from __future__ import annotations

import os

SERVICE = "strxeye"

KNOWN_KEYS: dict[str, str] = {
    "virustotal": "VirusTotal API key (required by the virustotal collector)",
    "otx": "AlienVault OTX API key (optional; raises OTX rate limits)",
}


class SecretStoreError(Exception):
    pass


def _keyring():
    try:
        import keyring
        from keyring.errors import KeyringError
    except ImportError as exc:  # pragma: no cover - keyring is a hard dependency
        raise SecretStoreError("the keyring package is not installed") from exc
    return keyring, KeyringError


def _check(name: str) -> None:
    if name not in KNOWN_KEYS:
        raise KeyError(f"unknown key '{name}'; known keys: {', '.join(KNOWN_KEYS)}")


def get_key(name: str) -> str | None:
    env = os.environ.get(f"STRXEYE_KEY_{name.upper()}")
    if env:
        return env
    keyring, KeyringError = _keyring()
    try:
        return keyring.get_password(SERVICE, name)
    except KeyringError:
        # No usable backend (e.g. a headless Linux box): behave as "not set".
        return None


def set_key(name: str, value: str) -> None:
    _check(name)
    value = value.strip()
    if not value:
        raise ValueError("key is empty")
    keyring, KeyringError = _keyring()
    try:
        keyring.set_password(SERVICE, name, value)
    except KeyringError as exc:
        raise SecretStoreError(
            f"could not store the key in the system keychain ({exc}); "
            f"set STRXEYE_KEY_{name.upper()} instead") from None


def delete_key(name: str) -> bool:
    _check(name)
    keyring, KeyringError = _keyring()
    try:
        keyring.delete_password(SERVICE, name)
        return True
    except KeyringError:
        return False


def key_status() -> dict[str, str | None]:
    """Where each known key comes from: 'environment', 'keychain' or None.
    Never returns the key itself."""
    status: dict[str, str | None] = {}
    for name in KNOWN_KEYS:
        if os.environ.get(f"STRXEYE_KEY_{name.upper()}"):
            status[name] = "environment"
        else:
            status[name] = "keychain" if get_key(name) else None
    return status
