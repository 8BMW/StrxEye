import pytest

from strxeye.models import EntityType
from strxeye.targets import TargetError, normalize_url, parent_domain, parse_target


@pytest.mark.parametrize("raw,type_,value", [
    ("Example.COM.", EntityType.DOMAIN, "example.com"),
    ("bücher.de", EntityType.DOMAIN, "xn--bcher-kva.de"),
    ("1.1.1.1", EntityType.IP, "1.1.1.1"),
    ("2606:4700:4700:0000::1111", EntityType.IP, "2606:4700:4700::1111"),
    ("[::1]", EntityType.IP, "::1"),
    ("AS13335", EntityType.ASN, "AS13335"),
    ("as 13335".replace(" ", ""), EntityType.ASN, "AS13335"),
    ("https://Example.com", EntityType.URL, "https://example.com/"),
    ("d41d8cd98f00b204e9800998ecf8427e", EntityType.HASH, "d41d8cd98f00b204e9800998ecf8427e"),
])
def test_detects_and_normalises(raw, type_, value):
    ref = parse_target(raw)
    assert ref.type is type_
    assert ref.value == value


@pytest.mark.parametrize("raw", [
    "", "localhost", "exa mple.com", "-bad.com", "a..b", "example.com/../etc",
    "999.1.1.1", "x" * 64 + ".com", "ftp://example.com", "javascript:alert(1)",
])
def test_rejects_invalid(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


def test_expected_type_is_enforced():
    with pytest.raises(TargetError):
        parse_target("example.com", EntityType.IP)
    assert parse_target("https://example.com/path", EntityType.DOMAIN).value == "example.com"


def test_url_with_credentials_is_refused():
    with pytest.raises(TargetError, match="credentials"):
        normalize_url("https://user:pass@example.com/")


def test_parent_domain():
    assert parent_domain("a.b.example.com") == "b.example.com"
    assert parent_domain("example.com") is None
