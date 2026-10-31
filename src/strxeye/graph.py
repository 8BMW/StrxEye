"""Builds the investigation graph from stored entities and relationships.

Observed relationships from several runs and sources are merged into one
edge per (source, target, type); the edge keeps every individual
observation as provenance so nothing is lost by the merge.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .correlation import analyze
from .models import utcnow
from .storage import Store


def build_graph(store: Store, inv_id: str, include_inferred: bool = True) -> dict[str, Any]:
    investigation = store.get_investigation(inv_id)
    seeds = {(s.type.value, s.value) for s in investigation.seeds}
    nodes: dict[int, dict[str, Any]] = {}
    for row in store.entities(inv_id, limit=1_000_000):
        nodes[row["id"]] = {
            "id": row["id"],
            "type": row["type"],
            "value": row["value"],
            "attributes": row["attributes"],
            "seed": (row["type"], row["value"]) in seeds,
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }

    merged: dict[tuple[int, int, str], dict[str, Any]] = {}
    for rel in store.all_relationships(inv_id):
        key = (rel["source_id"], rel["target_id"], rel["type"])
        edge = merged.get(key)
        if edge is None:
            edge = merged[key] = {
                "id": f"e{rel['id']}",
                "source": rel["source_id"],
                "target": rel["target_id"],
                "type": rel["type"],
                "inferred": False,
                "confidence": 0.0,
                "provenance": [],
            }
        edge["confidence"] = max(edge["confidence"], rel["confidence"])
        edge["provenance"].append({
            "origin": rel["origin"],
            "run_id": rel["run_id"],
            "collected_at": rel["collected_at"],
            "confidence": rel["confidence"],
            "evidence_id": rel["evidence_id"],
        })
    edges = list(merged.values())

    suppressed: list[str] = []
    if include_inferred:
        observations = store.all_observations(investigation.id)
        inferred, suppressed = analyze(nodes, edges, observations)
        for i, edge in enumerate(inferred):
            edges.append({"id": f"i{i}", **edge})

    return {
        "format": "strxeye-graph",
        "version": 1,
        "generator": f"STRX EYE {__version__}",
        "exported_at": utcnow().isoformat(),
        "investigation": {"id": investigation.id, "name": investigation.name},
        "nodes": list(nodes.values()),
        "edges": edges,
        # Shared infrastructure that was deliberately not linked, with reasons.
        "suppressed": suppressed,
    }
