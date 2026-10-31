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


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def threats(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every threat-related signal in an investigation, one row per entity
    and signal, most severe first.

    Severity follows fixed, documented rules rather than a combined score:
    a block-list hit keeps the list's own severity, VirusTotal is high from
    5 malicious engine verdicts and medium from 1, OTX mentions are medium
    (info when OTX allow-lists the indicator), and banner-based CVE guesses
    are low because nothing was verified.
    """
    allowlisted = {(o["entity_type"], o["entity_value"]) for o in observations
                   if o["kind"] == "otx.allowlisted"}
    found: dict[tuple, dict[str, Any]] = {}
    cves: dict[tuple, tuple[dict[str, Any], set[str]]] = {}
    kev: dict[tuple, tuple[dict[str, Any], list[str]]] = {}

    def add(obs, category, severity, summary):
        key = (obs["entity_type"], obs["entity_value"], category, summary)
        if key in found:
            return
        found[key] = {"entity_type": obs["entity_type"], "entity": obs["entity_value"],
                      "entity_id": obs["entity_id"], "category": category,
                      "severity": severity, "summary": summary, "source": obs["source"],
                      "confidence": obs["confidence"], "collected_at": obs["collected_at"],
                      "evidence_id": obs["evidence_id"]}

    for obs in observations:
        kind, value = obs["kind"], obs["value"]
        if kind == "threat.listed" and isinstance(value, dict):
            extra = value.get("malware") or value.get("sblid") or ""
            add(obs, "block list", value.get("severity", "medium"),
                f"{value.get('feed')}{f' ({extra})' if extra else ''}")
        elif kind == "otx.pulse_count" and isinstance(value, int) and value > 0:
            listed = (obs["entity_type"], obs["entity_value"]) in allowlisted
            add(obs, "threat reports", "info" if listed else "medium",
                f"mentioned in {value} OTX pulse(s)"
                + (" (OTX allow-lists this indicator)" if listed else ""))
        elif kind == "vt.analysis_stats" and isinstance(value, dict):
            bad = int(value.get("malicious", 0))
            if bad:
                total = sum(int(v) for v in value.values() if isinstance(v, int))
                add(obs, "reputation", "high" if bad >= 5 else "medium",
                    f"{bad}/{total} VirusTotal engines flag it as malicious")
        elif kind in ("vt.threat_label",):
            add(obs, "malware", "high", f"VirusTotal threat label: {value}")
        elif kind == "scan.possible_vulnerability":
            cves.setdefault((obs["entity_type"], obs["entity_value"]), (obs, set()))[1].add(value)
        elif kind == "tls.verified" and value is False:
            add(obs, "exposure", "medium", "served TLS certificate fails validation")
        elif kind == "abuseipdb.report" and isinstance(value, dict):
            score = int(value.get("abuseConfidenceScore") or 0)
            if score >= 25:
                add(obs, "reputation", "high" if score >= 75 else "medium",
                    f"AbuseIPDB confidence {score}% from {value.get('totalReports')} reports")
        elif kind == "urlhaus.host" and isinstance(value, dict) and value.get("url_count"):
            add(obs, "malware", "high" if value.get("online") else "medium",
                f"{value['url_count']} malware URL(s) in URLhaus, {value.get('online', 0)} online")
        elif kind == "threatfox.ioc" and isinstance(value, dict):
            conf = int(value.get("confidence_level") or 0)
            add(obs, "malware", "high" if conf >= 75 else "medium",
                f"ThreatFox IOC: {value.get('malware_printable')} "
                f"({value.get('threat_type')}, confidence {conf}%)")
        elif kind == "malwarebazaar.sample" and isinstance(value, dict):
            add(obs, "malware", "high", "known malware sample in MalwareBazaar: "
                f"{value.get('signature') or 'unclassified'} ({value.get('file_type')})")
        elif kind == "vuln.kev" and isinstance(value, dict):
            kev.setdefault((obs["entity_type"], obs["entity_value"]), (obs, []))[1].append(
                value.get("cve", "?"))
        elif kind == "greynoise.status" and isinstance(value, dict):
            if value.get("classification") == "malicious":
                add(obs, "reputation", "medium", "GreyNoise classifies it as a malicious scanner")
            elif value.get("noise"):
                add(obs, "reputation", "low", "mass-scans the internet (GreyNoise)")
            elif value.get("riot"):
                add(obs, "reputation", "info",
                    f"known benign business service (GreyNoise RIOT: {value.get('name')})")
        elif (kind == "routing.rpki" and isinstance(value, dict)
              and value.get("status") == "invalid"):
            add(obs, "exposure", "medium",
                f"RPKI-invalid announcement of {value.get('prefix')} by {value.get('origin')} "
                "(possible hijack or misconfiguration)")
    # An old server can carry hundreds of banner-based CVE guesses; one row
    # per host keeps them from burying the signals that matter.
    for obs, ids in kev.values():
        listed = sorted(set(ids))
        add(obs, "exposure", "medium",
            f"{len(listed)} of the guessed CVEs are in CISA's known-exploited catalogue: "
            f"{', '.join(listed[:5])}{' …' if len(listed) > 5 else ''} (presence unverified)")
    for obs, ids in cves.values():
        listed = sorted(ids, reverse=True)
        more = f" and {len(listed) - 5} more" if len(listed) > 5 else ""
        add(obs, "exposure", "low",
            f"{len(listed)} possible CVE(s) guessed from service banners, unverified: "
            f"{', '.join(listed[:5])}{more}")
    return sorted(found.values(),
                  key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["entity"]))


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


def malware_view(graph: dict[str, Any], observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per malware family in the investigation: its profile, the
    actors it is attributed to, and the infrastructure linked to it, each
    link with the sources that reported it."""
    nodes = {n["id"]: n for n in graph["nodes"]}
    profiles: dict[int, dict] = {}
    for o in observations:
        if o["kind"] == "malware.profile":
            profiles[o["entity_id"]] = o["value"]
    families = []
    for node in graph["nodes"]:
        if node["type"] != "malware":
            continue
        actors, infrastructure = [], []
        for e in graph["edges"]:
            if node["id"] not in (e["source"], e["target"]):
                continue
            other = nodes[e["target"] if e["source"] == node["id"] else e["source"]]
            origins = sorted({p["origin"] for p in e.get("provenance", [])}) or ["correlation"]
            link = {"id": other["id"], "type": other["type"], "value": other["value"],
                    "relationship": e["type"], "confidence": e["confidence"],
                    "inferred": e["inferred"], "sources": origins}
            if other["type"] == "threat_actor":
                actors.append(link)
            else:
                infrastructure.append(link)
        families.append({
            "id": node["id"], "name": node["value"], "attributes": node["attributes"],
            "profile": profiles.get(node["id"]), "actors": actors,
            "infrastructure": sorted(infrastructure, key=lambda x: (-x["confidence"], x["value"])),
        })
    return sorted(families, key=lambda f: (-len(f["infrastructure"]), f["name"]))
