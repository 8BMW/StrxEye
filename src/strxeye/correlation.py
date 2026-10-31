"""Inferred relationships between domains, and hosting providers.

Everything here is a suggestion built from observed facts, never a fact
itself. Each inferred edge lists the observations it rests on and is
returned with ``inferred: True`` so the UI and reports show it apart from
what sources reported.

How a link between two domains is scored:

* Each *signal* has a fixed weight. Weak signals describe infrastructure
  anyone can share (an IP, a certificate); strong signals are things only
  the same operator would normally share (an analytics account ID, a
  self-hosted nameserver, a non-redacted registrant organisation).
* Independent signals combine as 1 - prod(1 - w): two weak signals add
  up, but never to certainty.
* Signals that are known to be meaningless are suppressed before scoring,
  and the explanation says so: IPs on CDN and cloud networks, IPs shared by
  many domains, multi-tenant certificates, big DNS providers, and privacy
  or proxy registrant names.

Only edges with at least one strong signal are typed
``likely_same_operator``; the rest stay ``shares_infrastructure``.
"""

from __future__ import annotations

import re
from collections import defaultdict
from itertools import combinations
from typing import Any

from .models import RelationType

CROWDED = 20
MULTI_TENANT_CERT = 10  # a certificate covering this many separate sites is shared
_SHORT_SLDS = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}

# ASNs of CDNs, large clouds and mass shared-hosting providers, where one IP
# serves thousands of unrelated customers. VPS providers are deliberately
# not listed: their IPs are normally assigned to a single customer, so a
# shared VPS IP is a meaningful signal.
CDN_CLOUD_ASNS = {
    13335, 209242,            # Cloudflare
    20940, 16625, 32787,      # Akamai
    54113,                    # Fastly
    16509, 14618, 8987,       # Amazon (CloudFront and load balancers share IPs)
    15169, 396982, 19527,     # Google
    8075, 8068,               # Microsoft
    46606,                    # Unified Layer (Bluehost, HostGator shared hosting)
    26347,                    # DreamHost
    47583,                    # Hostinger
}

# Managed DNS and registrar nameservers used by millions of domains.
DNS_PROVIDERS = (
    "cloudflare.com", "awsdns", "azure-dns", "googledomains.com", "google.com",
    "domaincontrol.com", "registrar-servers.com", "nsone.net", "ultradns", "dnsmadeeasy.com",
    "akam.net", "gandi.net", "ovh.net", "hostinger", "dynect.net", "name-services.com",
    "worldnic.com", "dns.com", "digitalocean.com", "linode.com", "hetzner.com", "vercel-dns",
    "netlify", "wixdns.net", "squarespacedns", "dnsimple.com", "zoneedit", "namecheaphosting",
    "bluehost.com", "dreamhost.com", "porkbun.com", "ionos", "afternic", "parkingcrew",
    "sedoparking", "bodis.com",
)
PRIVACY_ORG = re.compile(r"privacy|proxy|redacted|whoisguard|domains by proxy|withheld|"
                         r"contact privacy|perfect privacy|not disclosed|data protected|"
                         r"identity protect|private registration", re.I)

WEIGHTS = {
    "ip": 0.3,
    "certificate": 0.4,
    "nameserver": 0.6,
    "registrant": 0.65,
    "tracking_id": 0.8,
}
STRONG = {"nameserver", "registrant", "tracking_id"}

CAVEAT = ("Shared infrastructure is common with CDNs and hosting providers; on its own it "
          "does not show that the domains have the same owner.")


def site_key(domain: str) -> str:
    """Rough registrable-domain key, used to avoid linking a site to its own
    subdomains. Handles two-part suffixes like co.uk heuristically."""
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in _SHORT_SLDS and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_dns_provider(host: str) -> bool:
    return any(p in host for p in DNS_PROVIDERS)


class _Graph:
    def __init__(self, nodes, edges, observations):
        self.nodes = nodes
        self.out: dict[int, list[dict]] = defaultdict(list)
        for e in edges:
            if not e.get("inferred"):
                self.out[e["source"]].append(e)
        self.obs: dict[int, list[dict]] = defaultdict(list)
        for o in observations or []:
            self.obs[o["entity_id"]].append(o)

    def targets(self, node_id: int, relation: RelationType) -> list[int]:
        return [e["target"] for e in self.out[node_id] if e["type"] == relation]

    def ip_suppression(self, ip_id: int) -> str | None:
        """Why links through this IP should be ignored, or None."""
        for o in self.obs[ip_id]:
            if o["kind"] == "scan.tags" and {"cdn", "cloud"} & set(o["value"] or []):
                return "tagged as CDN/cloud by Shodan InternetDB"
            if o["kind"] == "greynoise.status" and (o["value"] or {}).get("riot"):
                return "a known business service per GreyNoise RIOT"
        for net in self.targets(ip_id, RelationType.BELONGS_TO_NETWORK):
            for asn_id in self.targets(net, RelationType.ANNOUNCED_BY):
                asn = self.nodes[asn_id]
                number = int(asn["value"][2:]) if asn["value"].startswith("AS") else -1
                if number in CDN_CLOUD_ASNS:
                    label = asn["attributes"].get("name") or "CDN/cloud"
                    return f"announced by {asn['value']} ({label})"
                if asn["attributes"].get("network_type") == "Content":
                    return f"on a content-delivery network ({asn['value']})"
        return None


def infer(nodes: dict[int, dict[str, Any]], edges: list[dict[str, Any]],
          observations: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    return analyze(nodes, edges, observations)[0]


def analyze(nodes: dict[int, dict[str, Any]], edges: list[dict[str, Any]],
            observations: list[dict[str, Any]] | None = None,
            ) -> tuple[list[dict[str, Any]], list[str]]:
    """Inferred edges, plus the shared infrastructure that was deliberately
    not turned into links (and why)."""
    g = _Graph(nodes, edges, observations)
    domains = [i for i, n in nodes.items() if n["type"] == "domain"]
    signals: dict[tuple[int, int], list[dict]] = defaultdict(list)
    suppressed: list[str] = []

    def pair_up(groups: dict[Any, set[int]], kind: str, label, check=None):
        for key, members in groups.items():
            if len(members) < 2:
                continue
            reason = check(key, members) if check else None
            if reason:
                suppressed.append(reason)
                continue
            for a, b in combinations(sorted(members), 2):
                if site_key(nodes[a]["value"]) != site_key(nodes[b]["value"]):
                    signals[(a, b)].append({"signal": kind, "detail": label(key)})

    # Shared IPs
    by_ip: dict[int, set[int]] = defaultdict(set)
    for d in domains:
        for ip in g.targets(d, RelationType.RESOLVES_TO):
            by_ip[ip].add(d)

    def ip_check(ip, members):
        if len(members) > CROWDED:
            return f"{nodes[ip]['value']}: shared by {len(members)} domains (shared hosting)"
        why = g.ip_suppression(ip)
        return f"{nodes[ip]['value']}: {why}" if why else None

    pair_up(by_ip, "ip", lambda ip: f"both resolve to {nodes[ip]['value']}", ip_check)

    # Shared served certificates (not CT entries, which list many names)
    by_cert: dict[int, set[int]] = defaultdict(set)
    for d in domains:
        for c in g.targets(d, RelationType.USES_CERTIFICATE):
            by_cert[c].add(d)

    def cert_check(cert, members):
        names = nodes[cert]["attributes"].get("names") or []
        sites = {site_key(n.lstrip("*.")) for n in names}
        if len(sites) > MULTI_TENANT_CERT:
            return f"certificate {nodes[cert]['value'][:20]}…: multi-tenant ({len(sites)} sites)"
        return None

    pair_up(by_cert, "certificate",
            lambda c: f"both serve certificate {nodes[c]['value'][:23]}…", cert_check)

    # Self-hosted nameservers
    by_ns: dict[int, set[int]] = defaultdict(set)
    for d in domains:
        for ns in g.targets(d, RelationType.USES_NAMESERVER):
            by_ns[ns].add(d)

    def ns_check(ns, members):
        host = nodes[ns]["value"]
        if _is_dns_provider(host):
            return None  # silently ignored: true for most domains on the internet
        if len(members) > CROWDED:
            return f"nameserver {host}: used by {len(members)} domains (DNS hosting)"
        return None

    pair_up({k: v for k, v in by_ns.items() if not _is_dns_provider(nodes[k]["value"])},
            "nameserver", lambda ns: f"both use the self-hosted nameserver {nodes[ns]['value']}",
            ns_check)

    # Registrant organisation and tracking IDs come from observations.
    by_registrant: dict[str, set[int]] = defaultdict(set)
    by_tracking: dict[str, set[int]] = defaultdict(set)
    for d in domains:
        for o in g.obs[d]:
            if o["kind"] == "rdap.registrant_org" and isinstance(o["value"], str):
                if not PRIVACY_ORG.search(o["value"]):
                    by_registrant[o["value"].strip().lower()].add(d)
            elif o["kind"] == "http.tracking_id" and isinstance(o["value"], dict):
                by_tracking[f"{o['value'].get('type')}:{o['value'].get('id')}"].add(d)
    pair_up(by_registrant, "registrant",
            lambda org: f"same registrant organisation in RDAP ({org})",
            lambda org, m: f"registrant '{org}': {len(m)} domains" if len(m) > CROWDED else None)
    pair_up(by_tracking, "tracking_id",
            lambda tid: f"same {tid.split(':', 1)[0].replace('_', ' ')} ID {tid.split(':', 1)[1]}")

    result = []
    for (a, b), sigs in signals.items():
        kinds = {s["signal"] for s in sigs}
        remaining = 1.0
        for kind in kinds:
            remaining *= 1 - WEIGHTS[kind]
        confidence = round(1 - remaining, 2)
        strong = bool(kinds & STRONG)
        reasons = "; ".join(s["detail"] for s in sigs[:6])
        explanation = (f"{nodes[a]['value']} and {nodes[b]['value']}: {reasons}. "
                       + ("Independent signals that the same operator runs both."
                          if strong else CAVEAT))
        result.append({
            "source": a, "target": b,
            "type": (RelationType.LIKELY_SAME_OPERATOR if strong
                     else RelationType.SHARES_INFRASTRUCTURE).value,
            "inferred": True, "confidence": confidence, "explanation": explanation,
            "basis": sigs,
        })
    result += _hosted_by(nodes, g)
    return result, sorted(set(suppressed))


def _hosted_by(nodes, g: _Graph):
    """domain -> ip -> network -> organisation becomes domain hosted_by org."""
    result = []
    seen = set()
    for domain_id, node in nodes.items():
        if node["type"] != "domain":
            continue
        for e1 in g.out[domain_id]:
            if e1["type"] != RelationType.RESOLVES_TO:
                continue
            for e2 in g.out[e1["target"]]:
                if e2["type"] != RelationType.BELONGS_TO_NETWORK:
                    continue
                for e3 in g.out[e2["target"]]:
                    if e3["type"] != RelationType.OPERATED_BY:
                        continue
                    key = (domain_id, e3["target"])
                    if key in seen:
                        continue
                    seen.add(key)
                    ip, net, org = (nodes[e1["target"]]["value"], nodes[e2["target"]]["value"],
                                    nodes[e3["target"]]["value"])
                    result.append({
                        "source": domain_id, "target": e3["target"],
                        "type": RelationType.HOSTED_BY.value, "inferred": True,
                        "confidence": 0.6,
                        "explanation": (
                            f"{node['value']} resolves to {ip}, which is in {net}, registered "
                            f"to {org}. The network holder is usually the hosting provider, "
                            "not necessarily the site operator."),
                        "basis": [{"relationship": e["type"], "edge": e["id"]}
                                  for e in (e1, e2, e3)],
                    })
    return result
