"""Compare two runs: what appeared, what disappeared.

Only collectors that completed in *both* runs are compared. If crt.sh
timed out in the newer run, its subdomains would otherwise all show up as
"removed", which is exactly the kind of false change this guards against.
"""

from __future__ import annotations

import json
from typing import Any

from .storage import NotFoundError, Store

COMPARABLE = {"ok", "no_data", "partial"}


def _facts(store: Store, inv_id: str, run_id: str, collectors: set[str]) -> dict[tuple, dict]:
    facts = {}
    for obs in store.all_observations(inv_id, run_id):
        if obs["source"] not in collectors:
            continue
        key = (obs["entity_type"], obs["entity_value"], obs["kind"],
               json.dumps(obs["value"], sort_keys=True))
        facts[key] = {"entity_type": obs["entity_type"], "entity": obs["entity_value"],
                      "kind": obs["kind"], "value": obs["value"], "source": obs["source"]}
    return facts


def diff_runs(store: Store, inv_id: str, older: str, newer: str) -> dict[str, Any]:
    runs = {r["id"]: r for r in store.list_runs(inv_id)}
    for run_id in (older, newer):
        if run_id not in runs:
            raise NotFoundError(f"run '{run_id}' is not part of this investigation")
    a, b = store.get_run(older), store.get_run(newer)
    if a["started_at"] > b["started_at"]:
        a, b = b, a

    def completed(run):
        return {(c["collector"], c["target_value"]) for c in run["collectors"]
                if c["status"] in COMPARABLE}

    both = completed(a) & completed(b)
    collectors = {name for name, _ in both}
    skipped = sorted({c["collector"] for c in a["collectors"] + b["collectors"]} - collectors)

    old, new = _facts(store, inv_id, a["id"], collectors), _facts(store, inv_id, b["id"],
                                                                   collectors)
    return {
        "older": {"id": a["id"], "started_at": a["started_at"], "target": a["target_value"]},
        "newer": {"id": b["id"], "started_at": b["started_at"], "target": b["target_value"]},
        "compared_collectors": sorted(collectors),
        "not_compared": skipped,
        "added": [new[k] for k in sorted(new.keys() - old.keys())],
        "removed": [old[k] for k in sorted(old.keys() - new.keys())],
        "unchanged": len(new.keys() & old.keys()),
    }
