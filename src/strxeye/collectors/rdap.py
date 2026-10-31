"""RDAP (the structured successor to WHOIS) for domains, IP blocks and ASNs.

Servers are chosen from the IANA bootstrap registry rather than a fixed
proxy, so queries go straight to the responsible registry or RIR.

Privacy: registration records can contain personal data. We keep the
registrar and organisation-level registrant names only, never contact
names, emails, phone numbers or postal addresses, and we skip values that
registries have redacted.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, fetch
from ..targets import TargetError, normalize_domain, parent_domain
from .base import Collector, CollectorContext, Findings

BOOTSTRAP = "https://data.iana.org/rdap/{kind}.json"
RDAP_HEADERS = {"Accept": "application/rdap+json, application/json"}
METHOD = "RDAP lookup (HTTPS)"
REDACTION_MARKERS = ("redacted", "privacy", "data protected", "not disclosed", "withheld")


async def bootstrap(ctx: CollectorContext, kind: str) -> list[tuple[list[str], list[str]]]:
    key = f"rdap-bootstrap-{kind}"
    if key not in ctx.cache:
        response = await fetch(ctx.client, BOOTSTRAP.format(kind=kind),
                               retries=ctx.settings.network.retries, limiter=ctx.limiter)
        ctx.cache[key] = [(entry[0], entry[1]) for entry in response.json()["services"]]
    return ctx.cache[key]


def pick_url(urls: list[str]) -> str:
    https = [u for u in urls if u.startswith("https://")]
    if not https:
        raise FetchError("registry only offers RDAP over plain HTTP; refusing")
    return https[0] if https[0].endswith("/") else https[0] + "/"


async def server_for_domain(ctx: CollectorContext, domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1]
    for suffixes, urls in await bootstrap(ctx, "dns"):
        if tld in suffixes:
            return pick_url(urls)
    return None


async def server_for_ip(ctx: CollectorContext, address: str) -> str | None:
    ip = ipaddress.ip_address(address)
    best: tuple[int, str] | None = None
    for prefixes, urls in await bootstrap(ctx, "ipv4" if ip.version == 4 else "ipv6"):
        for prefix in prefixes:
            net = ipaddress.ip_network(prefix)
            if ip in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, pick_url(urls))
    return best[1] if best else None


async def server_for_asn(ctx: CollectorContext, number: int) -> str | None:
    for ranges, urls in await bootstrap(ctx, "asn"):
        for item in ranges:
            low, _, high = item.partition("-")
            if int(low) <= number <= int(high or low):
                return pick_url(urls)
    return None


def vcard(entity: dict[str, Any]) -> dict[str, Any]:
    props: dict[str, Any] = {}
    array = entity.get("vcardArray")
    if isinstance(array, list) and len(array) == 2:
        for prop in array[1]:
            if isinstance(prop, list) and len(prop) >= 4:
                props.setdefault(prop[0], prop[3])
    return props


def is_redacted(value: Any) -> bool:
    return not value or any(marker in str(value).lower() for marker in REDACTION_MARKERS)


def org_name(entity: dict[str, Any]) -> str | None:
    """Organisation name from an RDAP entity, or None if it may be a person."""
    props = vcard(entity)
    org = props.get("org")
    if isinstance(org, list):
        org = " ".join(str(part) for part in org if part)
    if org and not is_redacted(org):
        return str(org).strip()
    # "fn" is only safe to keep when the vCard says this is an organisation.
    if props.get("kind") == "org" and not is_redacted(props.get("fn")):
        return str(props["fn"]).strip()
    return None


def entities_with_role(data: dict[str, Any], role: str) -> list[dict[str, Any]]:
    return [e for e in data.get("entities", []) if role in e.get("roles", [])]


def events(data: dict[str, Any]) -> dict[str, str]:
    return {
        e["eventAction"]: e["eventDate"]
        for e in data.get("events", [])
        if "eventAction" in e and "eventDate" in e
    }


class RdapCollector(Collector):
    name = "rdap"
    title = "RDAP registration data"
    description = (
        "Registrar, registration dates, status and nameservers for domains; "
        "network owner for IP addresses; holder of AS numbers."
    )
    accepts = frozenset({EntityType.DOMAIN, EntityType.IP, EntityType.ASN})
    sources = ("data.iana.org", "RDAP server of the responsible registry or RIR")

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        if target.type is EntityType.DOMAIN:
            await self._domain(found, target, ctx)
        elif target.type is EntityType.IP:
            await self._ip(found, target, ctx)
        else:
            await self._asn(found, target, ctx)
        return found

    async def _get(self, ctx: CollectorContext, url: str) -> dict[str, Any] | None:
        response = await fetch(ctx.client, url, headers=RDAP_HEADERS, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries, allow_statuses=(404,))
        if response.status_code == 404:
            return None
        try:
            return response.json()
        except json.JSONDecodeError:
            raise FetchError(f"{url} did not return JSON") from None

    async def _domain(self, found: Findings, target: EntityRef, ctx: CollectorContext) -> None:
        server = await server_for_domain(ctx, target.value)
        if server is None:
            found.notes.append(f"no RDAP service is registered for .{target.value.rsplit('.')[-1]}")
            return
        # RDAP only knows registered names. Walk up from a subdomain until
        # the registry recognises one (www.a.example.co.uk -> example.co.uk).
        name: str | None = target.value
        data = None
        while name:
            url = f"{server}domain/{name}"
            data = await self._get(ctx, url)
            if data is not None:
                break
            name = parent_domain(name)
        if data is None or name is None:
            found.notes.append("registry has no record for this name")
            return

        evidence = found.add_evidence(url, json.dumps(data, indent=2), "application/rdap+json")
        registered = target
        if name != target.value:
            registered = found.entity(EntityType.DOMAIN, name)
            found.relate(target, RelationType.SUBDOMAIN_OF, registered, evidence_id=evidence)
            found.observe(target, "rdap.registered_domain", name, method=METHOD,
                          evidence_id=evidence, source_url=url)

        obs = dict(method=METHOD, evidence_id=evidence, source_url=url)
        for action, date in events(data).items():
            if action in ("registration", "expiration", "last changed"):
                found.observe(registered, f"rdap.{action.replace(' ', '_')}", date, **obs)
        if data.get("status"):
            found.observe(registered, "rdap.status", data["status"], **obs)
        secure = data.get("secureDNS", {}).get("delegationSigned")
        if secure is not None:
            found.observe(registered, "rdap.dnssec", bool(secure), **obs)

        for ns in data.get("nameservers", []):
            try:
                host = normalize_domain(ns.get("ldhName", ""))
            except TargetError:
                continue
            ns_ref = found.entity(EntityType.DOMAIN, host)
            found.relate(registered, RelationType.USES_NAMESERVER, ns_ref, evidence_id=evidence)

        for registrar in entities_with_role(data, "registrar"):
            label = vcard(registrar).get("fn")
            if is_redacted(label):
                continue
            iana_id = next((p.get("identifier") for p in registrar.get("publicIds", [])
                            if "IANA" in p.get("type", "")), None)
            org = found.entity(EntityType.ORGANIZATION, str(label).strip(),
                               role="registrar", iana_id=iana_id)
            found.observe(registered, "rdap.registrar", org.value, **obs)
            found.relate(registered, RelationType.REGISTERED_THROUGH, org, evidence_id=evidence)

        for registrant in entities_with_role(data, "registrant"):
            org_label = org_name(registrant)
            if org_label:
                org = found.entity(EntityType.ORGANIZATION, org_label)
                found.observe(registered, "rdap.registrant_org", org_label, **obs)
                # Registrant data is self-reported by the registrant.
                found.relate(registered, RelationType.ASSOCIATED_WITH, org,
                             evidence_id=evidence, confidence=0.7)
            else:
                found.observe(registered, "rdap.registrant_redacted", True, **obs)

    async def _ip(self, found: Findings, target: EntityRef, ctx: CollectorContext) -> None:
        server = await server_for_ip(ctx, target.value)
        if server is None:
            found.notes.append("address is not covered by any RIR (reserved or special-use)")
            return
        url = f"{server}ip/{target.value}"
        data = await self._get(ctx, url)
        if data is None:
            return
        evidence = found.add_evidence(url, json.dumps(data, indent=2), "application/rdap+json")
        obs = dict(method=METHOD, evidence_id=evidence, source_url=url)

        cidr = network_cidr(data)
        net_ref = None
        if cidr:
            net_ref = found.entity(EntityType.NETWORK, cidr, name=data.get("name"),
                                   handle=data.get("handle"), country=data.get("country"))
            found.relate(target, RelationType.BELONGS_TO_NETWORK, net_ref, evidence_id=evidence)
        for field in ("name", "handle", "country", "type"):
            if data.get(field):
                found.observe(target, f"rdap.network_{field}", data[field], **obs)

        for role in ("registrant", "administrative"):
            names = [n for n in (org_name(e) for e in entities_with_role(data, role)) if n]
            if names:
                org = found.entity(EntityType.ORGANIZATION, names[0])
                found.observe(target, "rdap.network_owner", names[0], **obs)
                found.relate(net_ref or target, RelationType.OPERATED_BY, org,
                             evidence_id=evidence)
                break

    async def _asn(self, found: Findings, target: EntityRef, ctx: CollectorContext) -> None:
        number = int(target.value[2:])
        server = await server_for_asn(ctx, number)
        if server is None:
            found.notes.append("AS number is not delegated to any RIR")
            return
        url = f"{server}autnum/{number}"
        data = await self._get(ctx, url)
        if data is None:
            return
        evidence = found.add_evidence(url, json.dumps(data, indent=2), "application/rdap+json")
        obs = dict(method=METHOD, evidence_id=evidence, source_url=url)
        for field in ("name", "country"):
            if data.get(field):
                found.observe(target, f"rdap.asn_{field}", data[field], **obs)
        for event, date in events(data).items():
            if event == "registration":
                found.observe(target, "rdap.registration", date, **obs)
        for entity in entities_with_role(data, "registrant"):
            label = org_name(entity)
            if label:
                org = found.entity(EntityType.ORGANIZATION, label)
                found.observe(target, "rdap.asn_holder", label, **obs)
                found.relate(target, RelationType.OPERATED_BY, org, evidence_id=evidence)
                break


def network_cidr(data: dict[str, Any]) -> str | None:
    for item in data.get("cidr0_cidrs", []):
        prefix = item.get("v4prefix") or item.get("v6prefix")
        if prefix and item.get("length") is not None:
            return str(ipaddress.ip_network(f"{prefix}/{item['length']}", strict=False))
    start, end = data.get("startAddress"), data.get("endAddress")
    if start and end:
        try:
            nets = list(ipaddress.summarize_address_range(
                ipaddress.ip_address(start), ipaddress.ip_address(end)))
        except (ValueError, TypeError):
            return None
        # A range that is not one CIDR block is stored as "start-end".
        return str(nets[0]) if len(nets) == 1 else f"{start}-{end}"
    return None
