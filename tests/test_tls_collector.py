"""TLS collector without network: a generated certificate stands in for the
server, which also lets the SSLBL match be checked against a real SHA-1."""

from datetime import UTC, datetime, timedelta

import httpx
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from strxeye.collectors import website
from strxeye.collectors.website import SSLBL_URL, TlsCollector
from strxeye.models import EntityRef, EntityType, RelationType

DOMAIN = EntityRef(type=EntityType.DOMAIN, value="example.com")


def make_cert() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1234)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com"),
                                                        x509.DNSName("www.example.com")]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


@respx.mock
async def test_tls_collector_records_cert_and_sslbl_hit(make_ctx, monkeypatch, tmp_path):
    der = make_cert()
    sha1 = x509.load_der_x509_certificate(der).fingerprint(hashes.SHA1()).hex()  # noqa: S303

    async def public(host, port=443):
        return ["93.184.215.14"]

    async def handshake(self, address, port, host, context, limit):
        return der, "TLSv1.3", "TLS_AES_128_GCM_SHA256"

    monkeypatch.setattr(website, "ensure_public_host", public)
    monkeypatch.setattr(TlsCollector, "_handshake", handshake)
    monkeypatch.setattr(website, "cache_dir", lambda: tmp_path)
    respx.get(SSLBL_URL).mock(return_value=httpx.Response(
        200, text=f"# header\n2026-10-01 00:00:00,{sha1},Dridex C&C\n"))

    found = await TlsCollector().collect(DOMAIN, make_ctx())
    kinds = {o.kind: o.value for o in found.observations}
    assert kinds["tls.protocol"] == "TLSv1.3"
    assert kinds["tls.verified"] is True
    assert kinds["tls.days_until_expiry"] in (9, 10)
    cert = next(e for e in found.entities.values() if e.type is EntityType.CERTIFICATE)
    assert cert.attributes["names"] == ["example.com", "www.example.com"]
    assert kinds["threat.listed"]["feed"] == "abuse.ch SSLBL"
    rel = next(r for r in found.relationships if r.target.type is EntityType.MALWARE)
    assert rel.target.value == "Dridex" and rel.type is RelationType.ASSOCIATED_WITH


@respx.mock
async def test_tls_collector_without_sslbl_listing(make_ctx, monkeypatch, tmp_path):
    der = make_cert()

    async def public(host, port=443):
        return ["93.184.215.14"]

    async def handshake(self, address, port, host, context, limit):
        return der, "TLSv1.2", "ECDHE-ECDSA-AES128-GCM-SHA256"

    monkeypatch.setattr(website, "ensure_public_host", public)
    monkeypatch.setattr(TlsCollector, "_handshake", handshake)
    monkeypatch.setattr(website, "cache_dir", lambda: tmp_path)
    respx.get(SSLBL_URL).mock(return_value=httpx.Response(200, text="# empty\n"))
    found = await TlsCollector().collect(DOMAIN, make_ctx())
    assert not [o for o in found.observations if o.kind == "threat.listed"]
