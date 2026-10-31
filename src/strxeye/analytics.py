"""Graph analytics and the investigation timeline.

These work on the graph produced by graph.build_graph. They describe the
structure of what was collected; they do not add facts. Inferred edges
are excluded unless explicitly requested, so a path or cluster is never
built on STRX EYE's own guesses without the caller asking for that.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from typing import Any

# Observation kinds that carry a point in time worth placing on a timeline,
# mapped to a human label. Values are either an ISO date or a dict with
# the listed date fields.
TIMED_KINDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "rdap.registration": ("Registered", ()),
    "rdap.expiration": ("Registration expires", ()),
    "rdap.last_changed": ("Registration changed", ()),
    "archive.first_capture": ("First archived capture", ()),
    "archive.latest_yearly_capture": ("Latest archived capture", ()),
    "pdns.record": ("Passive DNS", ("first_seen", "last_seen")),
    "otx.pulse": ("Mentioned in OTX pulse", ("created",)),
    "threat.listed": ("Listed in threat feed", ("first_seen", "last_online")),
    "registry.candidate": ("Registered with GLEIF", ("registered_since",)),
}


def _adjacency(graph: dict[str, Any], include_inferred: bool) -> dict[int, list[tuple[int, dict]]]:
    adj: dict[int, list[tuple[int, dict]]] = defaultdict(list)
    for edge in graph["edges"]:
        if edge["inferred"] and not include_inferred:
            continue
        adj[edge["source"]].append((edge["target"], edge))
        adj[edge["target"]].append((edge["source"], edge))
    return adj


def shortest_path(graph: dict[str, Any], source: int, target: int,
                  include_inferred: bool = False) -> dict[str, Any] | None:
    """Breadth-first shortest path, ignoring edge direction (a path from a
    domain to an organisation through an IP is meaningful either way)."""
    ids = {n["id"] for n in graph["nodes"]}
    if source not in ids or target not in ids:
        raise ValueError("both entities must be in the investigation graph")
    adj = _adjacency(graph, include_inferred)
    previous: dict[int, tuple[int, dict] | None] = {source: None}
    queue = deque([source])
    while queue:
        node = queue.popleft()
        if node == target:
            break
        for neighbour, edge in sorted(adj[node], key=lambda x: x[0]):
            if neighbour not in previous:
                previous[neighbour] = (node, edge)
                queue.append(neighbour)
    if target not in previous:
        return None
    nodes, edges = [target], []
    while previous[nodes[-1]] is not None:
        parent, edge = previous[nodes[-1]]  # type: ignore[misc]
        edges.append(edge["id"])
        nodes.append(parent)
    nodes.reverse()
    edges.reverse()
    return {"nodes": nodes, "edges": edges, "length": len(edges)}


def communities(graph: dict[str, Any], max_rounds: int = 30) -> dict[int, int]:
    """Label propagation over observed edges. Deterministic: nodes are
    visited in ID order and ties go to the smallest label. Returns
    node ID -> community ID (the smallest node ID in the community)."""
    # Seeds connect to almost everything (that is how the graph was built),
    # so letting labels flow through them merges the whole investigation
    # into one cluster. Seeds keep their own label and do not propagate.
    seeds = {n["id"] for n in graph["nodes"] if n.get("seed")}
    adj = {node: [(n, e) for n, e in links if n not in seeds]
           for node, links in _adjacency(graph, include_inferred=False).items()
           if node not in seeds}
    labels = {n["id"]: n["id"] for n in graph["nodes"]}
    for _ in range(max_rounds):
        changed = False
        for node in sorted(labels):
            neighbours = [labels[n] for n, _ in adj.get(node, [])]
            if not neighbours:
                continue
            counts = Counter(neighbours)
            best = max(counts.values())
            choice = min(label for label, c in counts.items() if c == best)
            if choice != labels[node]:
                labels[node] = choice
                changed = True
        if not changed:
            break
    # Normalise community IDs to the smallest member ID.
    members: dict[int, list[int]] = defaultdict(list)
    for node, label in labels.items():
        members[label].append(node)
    return {node: min(group) for group in members.values() for node in group}


def summarize(graph: dict[str, Any]) -> dict[str, Any]:
    comm = communities(graph)
    nodes = {n["id"]: n for n in graph["nodes"]}
    sizes = Counter(comm.values())
    degree = Counter()
    for edge in graph["edges"]:
        if not edge["inferred"]:
            degree[edge["source"]] += 1
            degree[edge["target"]] += 1
    groups = []
    for cid, size in sizes.most_common():
        if size < 2:
            continue
        member_ids = [n for n, c in comm.items() if c == cid]
        hub = max(member_ids, key=lambda n: (degree[n], -n))
        groups.append({"id": cid, "size": size, "hub": nodes[hub]["value"],
                       "types": dict(Counter(nodes[m]["type"] for m in member_ids))})
    return {
        "communities": groups,
        "isolated": sum(1 for s in sizes.values() if s == 1),
        "most_connected": [{"id": n, "type": nodes[n]["type"], "value": nodes[n]["value"],
                            "degree": d} for n, d in degree.most_common(10)],
        "membership": comm,
    }


def timeline(observations: list[dict[str, Any]],
             entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Dated events from observations and certificate validity periods,
    oldest first. Each event points back to the observation it came from."""
    events = []
    for obs in observations:
        spec = TIMED_KINDS.get(obs["kind"])
        if not spec:
            continue
        label, fields = spec
        value = obs["value"]
        dates = [(label, value)] if not fields else [
            (f"{label} ({f.replace('_', ' ')})", value.get(f)) for f in fields
            if isinstance(value, dict)]
        for text, when in dates:
            if not when or not isinstance(when, str):
                continue
            detail = value if isinstance(value, dict) else None
            events.append({"at": when, "event": text, "entity": obs["entity_value"],
                           "entity_type": obs["entity_type"], "source": obs["source"],
                           "observation_id": obs["id"], "evidence_id": obs["evidence_id"],
                           "detail": _detail(obs["kind"], detail)})
    for ent in entities:
        if ent["type"] != "certificate":
            continue
        attrs = ent["attributes"]
        names = ", ".join((attrs.get("names") or [])[:3])
        for field, text in (("not_before", "Certificate valid from"),
                            ("not_after", "Certificate expires")):
            if attrs.get(field):
                events.append({"at": attrs[field], "event": text, "entity": ent["value"],
                               "entity_type": "certificate", "source": "certificate",
                               "observation_id": None, "evidence_id": None, "detail": names})
    # Re-running a target records the same fact again; show it once.
    unique: dict[tuple, dict[str, Any]] = {}
    for e in events:
        unique.setdefault((e["at"], e["event"], e["entity"], e["detail"]), e)
    return sorted(unique.values(), key=lambda e: e["at"])


def _detail(kind: str, value: dict | None) -> str | None:
    if not value:
        return None
    if kind == "pdns.record":
        return f"{value.get('query')} {value.get('rrtype', '').upper()} {value.get('answer')}"
    if kind == "otx.pulse":
        return value.get("name")
    if kind == "threat.listed":
        return value.get("feed")
    if kind == "registry.candidate":
        return value.get("legal_name")
    return None
