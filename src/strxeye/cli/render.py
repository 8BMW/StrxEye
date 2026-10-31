"""Terminal rendering for collection results."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..models import CollectionStatus, CollectorResult

STATUS_STYLE = {
    CollectionStatus.OK: "green",
    CollectionStatus.NO_DATA: "dim",
    CollectionStatus.PARTIAL: "yellow",
    CollectionStatus.ERROR: "red",
    CollectionStatus.TIMEOUT: "red",
    CollectionStatus.CANCELLED: "yellow",
    CollectionStatus.SKIPPED: "dim",
}
MAX_LIST_ITEMS = 8


def short(value: Any, width: int = 120) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, dict):
        text = ", ".join(f"{k}={v}" for k, v in value.items() if v not in (None, "", []))
    elif isinstance(value, list):
        items = [short(v, 60) for v in value[:MAX_LIST_ITEMS]]
        more = f" (+{len(value) - MAX_LIST_ITEMS} more)" if len(value) > MAX_LIST_ITEMS else ""
        text = "; ".join(items) + more
    else:
        text = json.dumps(value)
    return text if len(text) <= width else text[: width - 1] + "…"


def status_table(results: list[CollectorResult]) -> Table:
    table = Table(title="Collectors", title_justify="left", show_edge=False, pad_edge=False)
    table.add_column("collector")
    table.add_column("target")
    table.add_column("status")
    table.add_column("time", justify="right")
    table.add_column("detail", overflow="fold")
    for r in sorted(results, key=lambda r: (r.target.key, r.collector)):
        detail = r.error or "; ".join(r.notes) or f"{len(r.observations)} observations"
        table.add_row(r.collector, r.target.value,
                      Text(r.status.value, style=STATUS_STYLE[r.status]),
                      f"{r.duration_ms / 1000:.1f}s", detail)
    return table


def print_results(console: Console, results: list[CollectorResult], verbose: bool = False) -> None:
    grouped: dict[str, list] = defaultdict(list)
    seen: set[tuple] = set()
    for result in results:
        for obs in result.observations:
            # The same AS is described once per IP that maps to it; show it once.
            key = (obs.entity.key, obs.kind, json.dumps(obs.value, sort_keys=True), obs.source)
            if key not in seen:
                seen.add(key)
                grouped[obs.entity.key].append(obs)

    for entity, observations in grouped.items():
        table = Table(title=entity, title_justify="left", title_style="bold cyan",
                      show_edge=False, pad_edge=False, expand=False)
        table.add_column("kind", style="bold", no_wrap=True)
        table.add_column("value", overflow="fold")
        table.add_column("source", style="dim", no_wrap=True)
        # Collapse repeated kinds (e.g. 300 ct.subdomain rows) unless verbose.
        by_kind: dict[str, list] = defaultdict(list)
        for obs in observations:
            by_kind[obs.kind].append(obs)
        for kind, items in by_kind.items():
            sources = ", ".join(sorted({o.source for o in items}))
            if len(items) > MAX_LIST_ITEMS and not verbose:
                values = [short(o.value, 60) for o in items[:MAX_LIST_ITEMS]]
                table.add_row(kind, f"{len(items)} values: " + ", ".join(values) + ", …",
                              sources)
            else:
                for obs in items:
                    table.add_row(kind, short(obs.value, 400 if verbose else 120), obs.source)
        console.print(table)
        console.print()

    console.print(status_table(results))
