"""Continuous monitoring: scheduled re-collection and change alerts.

A watch re-runs collection on one target at a fixed interval. After each
run the result is compared with the previous completed run of the same
target (history.diff_runs, which leaves out collectors that failed in
either run), and the differences are turned into alerts by fixed rules.

Watches run while the desktop app or ``strxeye serve`` is open. For
monitoring without the app running, schedule ``strxeye monitor run`` with
Windows Task Scheduler, cron or a systemd timer.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import defaultdict
from datetime import timedelta
from typing import Any

from .engine import Engine, EngineError, RunOptions
from .history import diff_runs
from .models import EntityRef, EntityType, utcnow
from .storage import Store

log = logging.getLogger(__name__)

_INTERVAL = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([hd])\s*$", re.I)


def parse_interval(text: str) -> float:
    """'6h' or '2d' -> hours."""
    match = _INTERVAL.match(text)
    if not match:
        raise ValueError(f"'{text}' is not an interval like 6h or 2d")
    hours = float(match.group(1)) * (24 if match.group(2).lower() == "d" else 1)
    if hours < 1:
        raise ValueError("the shortest monitoring interval is 1 hour")
    return hours


# kind prefix -> (severity, label). Checked in order; first match wins.
RULES: list[tuple[str, str, str]] = [
    ("threat.listed", "high", "Listed in a threat feed"),
    ("vt.analysis_stats", "high", "VirusTotal verdicts changed"),
    ("threatfox.ioc", "high", "New ThreatFox indicator"),
    ("urlhaus.host", "high", "URLhaus listing changed"),
    ("abuseipdb.report", "medium", "AbuseIPDB reports changed"),
    ("otx.pulse_count", "medium", "OTX pulse count changed"),
    ("vuln.kev", "medium", "Known-exploited CVE now associated"),
    ("dns.a", "medium", "A record changed"),
    ("dns.aaaa", "medium", "AAAA record changed"),
    ("dns.ns", "medium", "Nameservers changed"),
    ("dns.mx", "medium", "Mail servers changed"),
    ("dns.cname", "medium", "CNAME changed"),
    ("rdap.registrar", "medium", "Registrar changed"),
    ("rdap.status", "medium", "Registration status changed"),
    ("rdap.expiration", "low", "Registration expiry changed"),
    ("routing.rpki", "medium", "RPKI validity changed"),
    ("bgp.origin_asn", "medium", "Announcing AS changed"),
    ("tls.certificate", "low", "Served certificate changed"),
    ("tls.verified", "high", "TLS validation result changed"),
    ("ct.subdomain", "low", "New subdomains in Certificate Transparency"),
    ("hackertarget.subdomain", "low", "Subdomain list changed"),
    ("scan.open_ports", "medium", "Open ports changed"),
    ("dns.dmarc", "low", "DMARC policy changed"),
    ("mail.", "low", "Email security records changed"),
    ("http.security_header", "low", "Security headers changed"),
    ("greynoise.status", "low", "GreyNoise status changed"),
]
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _rule(kind: str) -> tuple[str, str] | None:
    for prefix, severity, label in RULES:
        if kind == prefix or kind.startswith(prefix + ".") or (prefix.endswith(".")
                                                                 and kind.startswith(prefix)):
            return severity, label
    return None


def _short(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("feed", "cve", "status", "host", "ioc", "name"):
            if key in value:
                return str(value[key])
        return ", ".join(f"{k}={v}" for k, v in list(value.items())[:3])
    if isinstance(value, list):
        return ", ".join(str(v) for v in value[:5])
    return str(value)


def alerts_from_diff(diff: dict[str, Any], inv_id: str, watch_id: int | None,
                     run_id: str) -> list[dict[str, Any]]:
    """Group added/removed facts by (entity, rule) into readable alerts.
    New threat listings are reported, removals from threat lists are not
    alerts (lists rotate) but are kept in the 'other changes' summary."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    other = 0
    for direction, facts in (("added", diff["added"]), ("removed", diff["removed"])):
        for fact in facts:
            matched = _rule(fact["kind"])
            if matched is None or (direction == "removed" and fact["kind"] == "threat.listed"):
                other += 1
                continue
            severity, label = matched
            key = (fact["entity"], label)
            group = groups.setdefault(key, {"severity": severity, "label": label,
                                            "entity": fact["entity"],
                                            "entity_type": fact["entity_type"],
                                            "added": [], "removed": []})
            group[direction].append(_short(fact["value"]))

    alerts = []
    for g in groups.values():
        parts = []
        if g["added"]:
            parts.append("+ " + ", ".join(g["added"][:6])
                         + (f" (+{len(g['added']) - 6} more)" if len(g["added"]) > 6 else ""))
        if g["removed"]:
            parts.append("- " + ", ".join(g["removed"][:6])
                         + (f" (+{len(g['removed']) - 6} more)" if len(g["removed"]) > 6 else ""))
        alerts.append({
            "investigation_id": inv_id, "watch_id": watch_id, "run_id": run_id,
            "severity": g["severity"],
            "title": f"{g['entity']}: {g['label']}",
            "detail": {"entity": g["entity"], "entity_type": g["entity_type"],
                       "added": g["added"], "removed": g["removed"], "summary": "  ".join(parts),
                       "older_run": diff["older"]["id"], "newer_run": diff["newer"]["id"],
                       "not_compared": diff["not_compared"]},
        })
    if other and not alerts:
        alerts.append({
            "investigation_id": inv_id, "watch_id": watch_id, "run_id": run_id,
            "severity": "info", "title": f"{diff['newer']['target']}: {other} minor changes",
            "detail": {"summary": f"{other} observations changed that no alert rule covers.",
                       "older_run": diff["older"]["id"], "newer_run": diff["newer"]["id"],
                       "not_compared": diff["not_compared"]},
        })
    return sorted(alerts, key=lambda a: SEVERITY_ORDER[a["severity"]])


async def run_watch(engine: Engine, store: Store, watch: dict[str, Any]) -> dict[str, Any]:
    """Run one watch now. Returns {run_id, alerts, error}."""
    target = EntityRef(type=EntityType(watch["target_type"]), value=watch["target_value"])
    opts = watch["options"]
    options = RunOptions(collectors=opts.get("collectors"), direct=bool(opts.get("direct")),
                         expand=bool(opts.get("expand", True)))
    next_run = utcnow() + timedelta(hours=watch["interval_hours"])
    try:
        report = await engine.run(target, options, investigation_id=watch["investigation_id"])
    except EngineError as exc:
        store.record_watch_run(watch["id"], None, str(exc), next_run)
        return {"run_id": None, "alerts": 0, "error": str(exc)}
    alerts: list[dict[str, Any]] = []
    previous = store.previous_completed_run(watch["investigation_id"], target, report.run_id)
    if previous and report.status == "completed":
        diff = diff_runs(store, watch["investigation_id"], previous, report.run_id)
        alerts = alerts_from_diff(diff, watch["investigation_id"], watch["id"], report.run_id)
        store.add_alerts(alerts)
    failed = [r.collector for r in report.failed]
    error = f"failed collectors: {', '.join(sorted(set(failed)))}" if failed else None
    store.record_watch_run(watch["id"], report.run_id, error, next_run)
    return {"run_id": report.run_id, "alerts": len(alerts), "error": error}


async def run_due(engine: Engine, store: Store) -> list[dict[str, Any]]:
    results = []
    for watch in store.due_watches():
        log.info("monitor: running watch %s (%s)", watch["id"], watch["target_value"])
        try:
            outcome = await run_watch(engine, store, watch)
        except Exception as exc:  # noqa: BLE001 - one broken watch must not stop the rest
            log.exception("monitor: watch %s failed", watch["id"])
            store.record_watch_run(watch["id"], None, f"internal error: {exc}",
                                   utcnow() + timedelta(hours=watch["interval_hours"]))
            outcome = {"run_id": None, "alerts": 0, "error": str(exc)}
        results.append({"watch_id": watch["id"], "target": watch["target_value"], **outcome})
    return results


class Scheduler:
    """Checks for due watches once a minute inside a running server."""

    def __init__(self, engine_factory, store: Store, interval: float = 60.0):
        self.engine_factory = engine_factory
        self.store = store
        self.interval = interval
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    async def tick(self) -> list[dict[str, Any]]:
        async with self._lock:  # never run the same watch twice at once
            return await run_due(self.engine_factory(self.store), self.store)

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001
                log.exception("monitor: scheduler tick failed")
            await asyncio.sleep(self.interval)


def summarize_alerts(alerts: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for a in alerts:
        counts[a["severity"]] += 1
    return dict(counts)
