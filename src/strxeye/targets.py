"""Parse and normalise user-supplied targets.

Everything that reaches a collector goes through here first, so collectors
can assume they receive a canonical lowercase ASCII domain, a canonical IP
string, and so on. Anything that does not parse cleanly is rejected rather
than passed along "best effort".
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import idna

from .models import EntityRef, EntityType

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_ASN = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_HEX = re.compile(r"^[0-9a-f]+$")


class TargetError(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    value = raw.strip().rstrip(".").lower()
    if not value or len(value) > 253:
        raise TargetError(f"'{raw}' is not a valid domain name")
    try:
        # UTS46 mapping handles internationalised names (e.g. bücher.de).
        value = idna.encode(value, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise TargetError(f"'{raw}' is not a valid domain name: {exc}") from None
    labels = value.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise TargetError(f"'{raw}' is not a valid domain name")
    if labels[-1].isdigit():
        raise TargetError(f"'{raw}' looks like an IP address, not a domain")
    return value


def normalize_ip(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw.strip().strip("[]")))
    except ValueError:
        raise TargetError(f"'{raw}' is not a valid IPv4 or IPv6 address") from None


def normalize_asn(raw: str) -> str:
    match = _ASN.match(raw.strip())
    if not match or not 0 < int(match.group(1)) < 2**32:
        raise TargetError(f"'{raw}' is not a valid AS number")
    return f"AS{int(match.group(1))}"


def parse_target(raw: str, expected: EntityType | None = None) -> EntityRef:
    """Detect the type of ``raw`` and return a normalised reference.

    If ``expected`` is given the input must be of that type; this is what
    the type-specific CLI commands (``strxeye domain``, ``strxeye ip``) use.
    """
    text = raw.strip()
    if not text:
        raise TargetError("target is empty")

    if expected is EntityType.DOMAIN:
        return EntityRef(type=EntityType.DOMAIN, value=normalize_domain(_strip_url(text)))
    if expected is EntityType.IP:
        return EntityRef(type=EntityType.IP, value=normalize_ip(text))
    if expected is EntityType.ASN:
        return EntityRef(type=EntityType.ASN, value=normalize_asn(text))
    if expected is EntityType.ORGANIZATION:
        return EntityRef(type=EntityType.ORGANIZATION, value=normalize_org(text))
    if expected is EntityType.HASH:
        return EntityRef(type=EntityType.HASH, value=normalize_hash(text))
    if expected is not None and expected is not EntityType.URL:
        raise TargetError(f"direct input of type '{expected}' is not supported")

    if text.lower().startswith("org:"):
        return EntityRef(type=EntityType.ORGANIZATION, value=normalize_org(text[4:]))
    if "://" in text or expected is EntityType.URL:
        return EntityRef(type=EntityType.URL, value=normalize_url(text))

    try:
        return EntityRef(type=EntityType.IP, value=normalize_ip(text))
    except TargetError:
        pass
    if _ASN.match(text) and text.upper().startswith("AS"):
        return EntityRef(type=EntityType.ASN, value=normalize_asn(text))
    lowered = text.lower()
    if len(lowered) in _HASH_LENGTHS and _HEX.match(lowered):
        return EntityRef(type=EntityType.HASH, value=lowered)
    try:
        return EntityRef(type=EntityType.DOMAIN, value=normalize_domain(text))
    except TargetError:
        raise TargetError(
            f"could not recognise '{raw}' as a domain, IP address, AS number, URL or hash "
            "(prefix company names with org:)"
        ) from None


def normalize_org(raw: str) -> str:
    value = " ".join(raw.split())
    if len(value) < 2 or len(value) > 200:
        raise TargetError("organisation names must be 2 to 200 characters")
    return value


def normalize_hash(raw: str) -> str:
    value = raw.strip().lower()
    if len(value) not in _HASH_LENGTHS or not _HEX.match(value):
        raise TargetError(f"'{raw}' is not an MD5, SHA-1, SHA-256 or SHA-512 hash")
    return value


def normalize_url(raw: str) -> str:
    parts = urlsplit(raw.strip())
    if parts.scheme not in ("http", "https"):
        raise TargetError(f"'{raw}' must use http or https")
    if not parts.hostname:
        raise TargetError(f"'{raw}' has no host")
    if parts.username or parts.password:
        # Credentials in URLs end up in evidence and reports; refuse them.
        raise TargetError("URLs containing credentials are not accepted")
    try:
        host = normalize_ip(parts.hostname)
        host = f"[{host}]" if ":" in host else host
    except TargetError:
        host = normalize_domain(parts.hostname)
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{netloc}{path}{query}"


def host_of(ref: EntityRef) -> str:
    if ref.type is EntityType.URL:
        hostname = urlsplit(ref.value).hostname
        assert hostname is not None
        return hostname
    return ref.value


def parent_domain(domain: str) -> str | None:
    labels = domain.split(".")
    return ".".join(labels[1:]) if len(labels) > 2 else None


def _strip_url(text: str) -> str:
    if "://" in text:
        host = urlsplit(text).hostname
        if not host:
            raise TargetError(f"'{text}' has no host")
        return host
    return text
