"""Direct website collectors: HTTP response headers, technology hints,
robots.txt and the TLS certificate actually served.

These connect to the target's own servers, so they only run when direct
collection is enabled. They make the same requests a browser would make
when visiting the homepage; there is no crawling, path guessing or port
scanning. Every hop (including redirects) is checked against the SSRF
guard so a hostile domain cannot redirect us into a private network.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import ssl
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, ensure_public_host
from ..targets import TargetError, host_of, normalize_url
from .base import Collector, CollectorContext, Findings
from .crtsh import issuer_org

MAX_REDIRECTS = 5
MAX_BODY = 512 * 1024
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)
# Header-based hints. Each is a strong signal on its own because these
# headers are set by the platform itself.
HEADER_TECH = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-vercel-id": "Vercel",
    "x-github-request-id": "GitHub Pages",
    "x-fastly-request-id": "Fastly",
    "x-azure-ref": "Azure Front Door",
    "x-shopid": "Shopify",
}
BODY_TECH = (
    (re.compile(rb"/wp-content/|/wp-includes/"), "WordPress"),
    (re.compile(rb"/_next/static/"), "Next.js"),
    (re.compile(rb"cdn\.shopify\.com"), "Shopify"),
    (re.compile(rb"/sites/default/files/"), "Drupal"),
    (re.compile(rb"__NUXT__"), "Nuxt"),
)
_GENERATOR = re.compile(rb"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']{1,100})",
                        re.IGNORECASE)
_TITLE = re.compile(rb"<title[^>]*>([^<]{1,300})</title>", re.IGNORECASE)


def start_url(target: EntityRef) -> str:
    return target.value if target.type is EntityType.URL else f"https://{target.value}/"


def redact_cookie(header: str) -> str:
    """Keep a Set-Cookie header's name and attributes, drop its value."""
    first, _, attributes = header.partition(";")
    name = first.split("=", 1)[0].strip()
    return f"{name}=<redacted>" + (f";{attributes}" if attributes else "")


async def guarded_get(ctx: CollectorContext, url: str) -> tuple[httpx.Response, bytes, list[str]]:
    """GET ``url`` following redirects manually so each hop is SSRF-checked.
    Reads at most MAX_BODY bytes of the final body."""
    chain: list[str] = []
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise FetchError(f"refusing to follow redirect to {url}")
        await ensure_public_host(parts.hostname, parts.port or (443 if parts.scheme == "https"
                                                                else 80))
        chain.append(url)
        request = ctx.client.build_request("GET", url)
        try:
            response = await ctx.client.send(request, stream=True, follow_redirects=False)
        except httpx.TimeoutException:
            raise FetchError(f"timed out fetching {url}") from None
        except httpx.TransportError as exc:
            raise FetchError(f"could not fetch {url}: {exc.__class__.__name__}") from None
        try:
            if response.is_redirect and "location" in response.headers:
                url = urljoin(url, response.headers["location"])
                continue
            body = b""
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) >= MAX_BODY:
                    break
            return response, body[:MAX_BODY], chain
        finally:
            await response.aclose()
    raise FetchError(f"more than {MAX_REDIRECTS} redirects starting from {chain[0]}")


class HttpCollector(Collector):
    name = "http"
    title = "Website headers and technologies"
    description = (
        "Fetches the homepage once: status, redirects, security headers, cookie flags, "
        "technology hints and robots.txt."
    )
    accepts = frozenset({EntityType.DOMAIN, EntityType.URL})
    direct = True

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        url = start_url(target)
        try:
            response, body, chain = await guarded_get(ctx, url)
        except FetchError:
            if target.type is not EntityType.DOMAIN:
                raise
            # Some sites still serve plain HTTP only.
            url = f"http://{target.value}/"
            response, body, chain = await guarded_get(ctx, url)
            found.observe(target, "http.https_unavailable", True, method="HTTPS GET failed")

        method = "HTTP GET of homepage"
        header_text = "\n".join(
            f"{k}: {redact_cookie(v) if k.lower() == 'set-cookie' else v}"
            for k, v in response.headers.multi_items())
        evidence = found.add_evidence(
            f"GET {chain[-1]}", f"HTTP {response.status_code}\n{header_text}", "text/plain")
        obs = dict(method=method, evidence_id=evidence, source_url=chain[-1])

        found.observe(target, "http.status", response.status_code, **obs)
        found.observe(target, "http.final_url", chain[-1], **obs)
        if len(chain) > 1:
            found.observe(target, "http.redirect_chain", chain, **obs)
            try:
                final = found.entity(EntityType.URL, normalize_url(chain[-1]))
                found.relate(target, RelationType.ASSOCIATED_WITH, final, evidence_id=evidence)
            except TargetError:
                pass

        headers = {k.lower(): v for k, v in response.headers.items()}
        for name in SECURITY_HEADERS:
            if name in headers:
                found.observe(target, "http.security_header", {"name": name,
                                                                "value": headers[name]}, **obs)
            else:
                found.observe(target, "http.security_header.missing", name, **obs)

        for cookie in response.headers.get_list("set-cookie"):
            # Record the cookie name and flags only; values can be session
            # identifiers and have no investigative value.
            name = cookie.split("=", 1)[0].strip()
            flags = cookie.lower()
            found.observe(target, "http.cookie", {
                "name": name,
                "secure": "; secure" in flags,
                "httponly": "; httponly" in flags,
                "samesite": (re.search(r"samesite=(\w+)", flags) or [None, None])[1],
            }, **obs)

        techs: dict[str, str] = {}
        for header in ("server", "x-powered-by"):
            if headers.get(header):
                techs.setdefault(headers[header][:100], f"{header} header")
        for header, tech in HEADER_TECH.items():
            if header in headers:
                techs.setdefault(tech, f"{header} header")
        if (match := _GENERATOR.search(body)):
            techs.setdefault(match.group(1).decode("utf-8", "replace").strip(),
                             "meta generator tag")
        for pattern, tech in BODY_TECH:
            if pattern.search(body):
                techs.setdefault(tech, f"page markup matches {pattern.pattern.decode()!r}")
        for tech, reason in techs.items():
            ref = found.entity(EntityType.TECHNOLOGY, tech)
            found.observe(target, "http.technology", {"name": tech, "basis": reason}, **obs)
            found.relate(target, RelationType.USES_TECHNOLOGY, ref, evidence_id=evidence,
                         confidence=0.9 if "header" in reason else 0.7)

        if (match := _TITLE.search(body)):
            found.observe(target, "http.title",
                          match.group(1).decode("utf-8", "replace").strip(), **obs)

        await self._robots(found, target, ctx, chain[-1])
        return found

    async def _robots(self, found, target, ctx, base_url: str) -> None:
        robots_url = urljoin(base_url, "/robots.txt")
        try:
            response, body, chain = await guarded_get(ctx, robots_url)
        except FetchError as exc:
            found.notes.append(f"robots.txt not retrieved: {exc}")
            return
        if response.status_code != 200 or b"<html" in body[:500].lower():
            found.observe(target, "robots.absent", True, method="HTTP GET of /robots.txt")
            return
        text = body.decode("utf-8", "replace")
        evidence = found.add_evidence(f"GET {chain[-1]}", text)
        obs = dict(method="HTTP GET of /robots.txt", evidence_id=evidence, source_url=chain[-1])
        lines = [line.split("#", 1)[0].strip() for line in text.splitlines()]
        disallow = [ln.split(":", 1)[1].strip() for ln in lines
                    if ln.lower().startswith("disallow:") and ln.split(":", 1)[1].strip()]
        sitemaps = [ln.split(":", 1)[1].strip() for ln in lines
                    if ln.lower().startswith("sitemap:")]
        found.observe(target, "robots.disallow", disallow[:200], **obs)
        for sitemap in sitemaps[:20]:
            try:
                ref = found.entity(EntityType.URL, normalize_url(sitemap), role="sitemap")
            except TargetError:
                continue
            found.observe(target, "robots.sitemap", ref.value, **obs)
            found.relate(target, RelationType.ASSOCIATED_WITH, ref, evidence_id=evidence)


class TlsCollector(Collector):
    name = "tls"
    title = "Served TLS certificate"
    description = "Connects to port 443 and records the certificate and protocol actually served."
    accepts = frozenset({EntityType.DOMAIN, EntityType.URL})
    direct = True

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        host = host_of(target).strip("[]")
        port = 443
        if target.type is EntityType.URL:
            port = urlsplit(target.value).port or 443
        addresses = await ensure_public_host(host, port)
        # Connect to the address we just vetted (with SNI set to the host
        # name) rather than resolving again, closing the DNS rebinding gap.
        address = addresses[0]
        timeout = ctx.settings.network.timeout

        verify_error = None
        try:
            der, version, cipher = await self._handshake(address, port, host,
                                                         ssl.create_default_context(), timeout)
        except ssl.SSLCertVerificationError as exc:
            verify_error = exc.verify_message or str(exc)
            insecure = ssl.create_default_context()
            insecure.check_hostname = False
            insecure.verify_mode = ssl.CERT_NONE  # only to read the cert we already rejected
            der, version, cipher = await self._handshake(address, port, host, insecure, timeout)

        cert = x509.load_der_x509_certificate(der)
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        method = f"TLS handshake with {address}:{port} (SNI {host})"
        evidence = found.add_evidence(f"tls://{host}:{port}", _pem(cert), "application/x-pem-file")
        obs = dict(method=method, evidence_id=evidence)

        names = _san_names(cert)
        not_after = cert.not_valid_after_utc
        ref = found.entity(
            EntityType.CERTIFICATE,
            f"sha256:{fingerprint}",
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=not_after.isoformat(),
            names=names[:50],
            key=_key_description(cert),
            signature_algorithm=cert.signature_hash_algorithm.name
            if cert.signature_hash_algorithm else None,
        )
        found.relate(target, RelationType.USES_CERTIFICATE, ref, evidence_id=evidence)
        found.observe(target, "tls.certificate", ref.value, **obs)
        found.observe(target, "tls.protocol", version, **obs)
        found.observe(target, "tls.cipher", cipher, **obs)
        found.observe(target, "tls.verified", verify_error is None, **obs)
        if verify_error:
            found.observe(target, "tls.verify_error", verify_error, **obs)
        days = (not_after - datetime.now(UTC)).days
        found.observe(target, "tls.days_until_expiry", days, **obs)
        org = issuer_org(cert.issuer.rfc4514_string())
        if org:
            ca = found.entity(EntityType.ORGANIZATION, org, role="certificate authority")
            found.relate(ref, RelationType.ISSUED_BY, ca, evidence_id=evidence)
        return found

    async def _handshake(self, address, port, host, context, limit):
        async with asyncio.timeout(limit):
            reader, writer = await asyncio.open_connection(
                address, port, ssl=context, server_hostname=host)
        try:
            sslobj = writer.get_extra_info("ssl_object")
            der = sslobj.getpeercert(binary_form=True)
            if not der:
                raise FetchError("server did not present a certificate")
            return der, sslobj.version(), sslobj.cipher()[0]
        finally:
            writer.close()
            # Servers often drop the connection without a TLS close_notify.
            with contextlib.suppress(ssl.SSLError, ConnectionError):
                await writer.wait_closed()


def _san_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return sorted(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return [str(cn[0].value)] if cn else []


def _key_description(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name}"
    return type(key).__name__


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(Encoding.PEM).decode("ascii")
