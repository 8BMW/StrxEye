"""Inferred relationships.

Everything here is a suggestion derived from observed facts, never a fact
itself. Each inferred edge says which observations it rests on and is
returned with ``inferred: True`` so the UI and reports can show it apart
from what sources reported directly.

Deliberate limits:

* Sharing an IP address or certificate is common (CDNs, shared hosting,
  multi-tenant certificates) and is not evidence of common ownership. The
  confidence values are kept low and the explanation says so.
* An IP shared by more than ``CROWDED`` domains in one investigation is
  treated as shared hosting and produces no pairwise links at all, which
  avoids flooding the graph with meaningless edges.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import combinations
from typing import Any

from .models import RelationType

CROWDED = 20
_SHORT_SLDS = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}

SHARED_CAVEAT = (
    "Shared infrastructure is common with CDNs and hosting providers; "
    "it does not show that the domains have the same owner."
)


def site_key(domain: str) -> str:
    """Rough registrable-domain key used to avoid linking a site to its own
    subdomains. Handles two-part public suffixes like co.uk heuristically;
    it is only used to suppress noise, never to assert anything."""
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in _SHORT_SLDS and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def infer(nodes: dict[int, dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return inferred edges for a graph of observed ``nodes`` and ``edges``
    (as produced by graph.build_graph before inference)."""
    out: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        out[edge["source"]].append(edge)
    inferred = []
    inferred += _shared(nodes, edges, RelationType.RESOLVES_TO, "IP address", 0.4)
    inferred += _shared(nodes, edges, RelationType.USES_CERTIFICATE, "served TLS certificate", 0.5)
    inferred += _hosted_by(nodes, out)
    return inferred


def _shared(nodes, edges, relation: RelationType, label: str, confidence: float):
    users: dict[int, set[int]] = defaultdict(set)
    for edge in edges:
        if edge["type"] == relation and nodes[edge["source"]]["type"] == "domain":
            users[edge["target"]].add(edge["source"])

    pairs: dict[tuple[int, int], list[int]] = defaultdict(list)
    for shared, domains in users.items():
        if len(domains) < 2 or len(domains) > CROWDED:
            continue
        for a, b in combinations(sorted(domains), 2):
            if site_key(nodes[a]["value"]) != site_key(nodes[b]["value"]):
                pairs[(a, b)].append(shared)

    result = []
    for (a, b), shared in pairs.items():
        values = ", ".join(nodes[s]["value"] for s in shared[:5])
        result.append({
            "source": a,
            "target": b,
            "type": RelationType.SHARES_INFRASTRUCTURE.value,
            "inferred": True,
            "confidence": confidence,
            "explanation": f"Both {nodes[a]['value']} and {nodes[b]['value']} use the same "
                           f"{label} ({values}). {SHARED_CAVEAT}",
            "basis": [{"relationship": relation.value, "via": s} for s in shared],
        })
    return result


def _hosted_by(nodes, out):
    """domain -> ip -> network -> organisation becomes domain hosted_by org."""
    result = []
    seen = set()
    for domain_id, node in nodes.items():
        if node["type"] != "domain":
            continue
        for e1 in out[domain_id]:
            if e1["type"] != RelationType.RESOLVES_TO:
                continue
            for e2 in out[e1["target"]]:
                if e2["type"] != RelationType.BELONGS_TO_NETWORK:
                    continue
                for e3 in out[e2["target"]]:
                    if e3["type"] != RelationType.OPERATED_BY:
                        continue
                    key = (domain_id, e3["target"])
                    if key in seen:
                        continue
                    seen.add(key)
                    ip, net, org = (nodes[e1["target"]]["value"], nodes[e2["target"]]["value"],
                                    nodes[e3["target"]]["value"])
                    result.append({
                        "source": domain_id,
                        "target": e3["target"],
                        "type": RelationType.HOSTED_BY.value,
                        "inferred": True,
                        "confidence": 0.6,
                        "explanation": (
                            f"{node['value']} resolves to {ip}, which is in {net}, registered "
                            f"to {org}. The network holder is usually the hosting provider, "
                            "not necessarily the site operator."),
                        "basis": [{"relationship": e["type"], "edge": e["id"]}
                                  for e in (e1, e2, e3)],
                    })
    return result
