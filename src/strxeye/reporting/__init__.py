"""Investigation reports in HTML, JSON and CSV.

Reports separate three kinds of content and label each:

* Observations - what a source returned, with source, time and evidence.
* Inferred relationships - produced by the correlation step.
* Interpretations - fixed rules applied to observations (for example
  "no DMARC record published"). Each lists the observations it rests on.
"""

from __future__ import annotations

import csv
import io
import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from .. import __version__
from ..collectors import registry
from ..config import Settings
from ..graph import build_graph
from ..models import utcnow
from ..storage import Store

FORMATS = ("html", "json", "csv", "stix")


def interpretations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_entity: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for obs in observations:
        by_entity[obs["entity_value"]][obs["kind"]].append(obs)

    found = []

    def add(entity, severity, title, detail, recommendation, basis):
        found.append({"entity": entity, "severity": severity, "title": title, "detail": detail,
                      "recommendation": recommendation,
                      "basis": [{"kind": b["kind"], "source": b["source"],
                                 "collected_at": b["collected_at"]} for b in basis]})

    now = datetime.now(UTC)
    for entity, kinds in by_entity.items():
        if kinds.get("dns.dmarc.missing") and not kinds.get("dns.dmarc"):
            add(entity, "medium", "No DMARC policy published",
                f"No v=DMARC1 TXT record was found at _dmarc.{entity}.",
                "Publish a DMARC policy so receiving mail servers can reject spoofed mail.",
                kinds["dns.dmarc.missing"])
        if kinds.get("dns.mx") and not kinds.get("dns.txt.spf"):
            add(entity, "low", "Mail domain without SPF record",
                "The domain publishes MX records but no SPF (v=spf1) TXT record was observed.",
                "Publish an SPF record listing the servers allowed to send mail for the domain.",
                kinds["dns.mx"])
        missing = {o["value"]: o for o in kinds.get("http.security_header.missing", [])}
        if "strict-transport-security" in missing:
            add(entity, "low", "HSTS header not set",
                "The homepage response did not include Strict-Transport-Security.",
                "Send HSTS so browsers refuse to downgrade to plain HTTP.",
                [missing["strict-transport-security"]])
        if "content-security-policy" in missing:
            add(entity, "info", "No Content-Security-Policy",
                "The homepage response did not include a Content-Security-Policy header.",
                "Consider a CSP to limit the impact of script injection.",
                [missing["content-security-policy"]])
        for obs in kinds.get("tls.verified", []):
            if obs["value"] is False:
                errors = kinds.get("tls.verify_error", [])
                reason = errors[0]["value"] if errors else "unknown reason"
                add(entity, "high", "TLS certificate failed verification",
                    f"The served certificate did not validate: {reason}.",
                    "Replace the certificate with one issued for this name by a trusted CA.",
                    [obs, *errors])
        for obs in kinds.get("tls.days_until_expiry", []):
            if isinstance(obs["value"], int) and obs["value"] < 21:
                add(entity, "medium", "TLS certificate expires soon",
                    f"The served certificate expires in {obs['value']} days.",
                    "Renew the certificate.", [obs])
        for obs in kinds.get("rdap.expiration", []):
            try:
                expires = datetime.fromisoformat(str(obs["value"]).replace("Z", "+00:00"))
            except ValueError:
                continue
            if expires.tzinfo and (expires - now).days < 45:
                add(entity, "medium", "Domain registration expires soon",
                    f"The registry lists the expiration date as {obs['value']}.",
                    "Confirm the registration is set to renew.", [obs])
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(found, key=lambda f: (order[f["severity"]], f["entity"]))


def report_data(store: Store, inv_id: str, settings: Settings) -> dict[str, Any]:
    investigation = store.get_investigation(inv_id)
    observations = store.all_observations(investigation.id)
    graph = build_graph(store, investigation.id)
    nodes = {n["id"]: n for n in graph["nodes"]}
    runs = [store.get_run(r["id"]) for r in store.list_runs(investigation.id)]
    collectors = registry(settings)

    used = sorted({c["collector"] for run in runs for c in run["collectors"]})
    methodology = [collectors[name].describe() if name in collectors else {"name": name}
                   for name in used]
    problems = [
        {"run": run["id"], "collector": c["collector"], "target": c["target_value"],
         "status": c["status"], "error": c["error"], "notes": c["notes"]}
        for run in runs for c in run["collectors"]
        if c["status"] in ("error", "timeout", "cancelled", "partial") or c["notes"]
    ]

    def edge_row(edge):
        src, dst = nodes[edge["source"]], nodes[edge["target"]]
        return {"source": f"{src['type']}:{src['value']}", "type": edge["type"],
                "target": f"{dst['type']}:{dst['value']}", "confidence": edge["confidence"],
                "provenance": edge.get("provenance", []),
                "explanation": edge.get("explanation")}

    findings: dict[str, list[dict]] = defaultdict(list)
    for obs in observations:
        findings[f"{obs['entity_type']}:{obs['entity_value']}"].append(obs)

    return {
        "generator": f"STRX EYE {__version__}",
        "generated_at": utcnow().isoformat(),
        "investigation": investigation.model_dump(mode="json"),
        "summary": {
            "entities": store.counts(investigation.id),
            "observations": len(observations),
            "relationships": sum(1 for e in graph["edges"] if not e["inferred"]),
            "inferred_relationships": sum(1 for e in graph["edges"] if e["inferred"]),
            "runs": len(runs),
            "collector_problems": len(problems),
        },
        "scope": {
            "seeds": [s.model_dump(mode="json") for s in investigation.seeds],
            "runs": [{"id": r["id"], "target": f"{r['target_type']}:{r['target_value']}",
                      "started_at": r["started_at"], "finished_at": r["finished_at"],
                      "status": r["status"], "options": r["options"]} for r in runs],
            "direct_contact": any(r["options"].get("direct") for r in runs),
        },
        "methodology": methodology,
        "interpretations": interpretations(observations),
        "findings": dict(sorted(findings.items())),
        "relationships": [edge_row(e) for e in graph["edges"] if not e["inferred"]],
        "inferred": [edge_row(e) for e in graph["edges"] if e["inferred"]],
        "limitations": problems,
        "evidence": store.list_evidence(investigation.id),
    }


def render(store: Store, inv_id: str, fmt: str, settings: Settings) -> str:
    if fmt not in FORMATS:
        raise ValueError(f"unsupported report format '{fmt}'; choose one of {', '.join(FORMATS)}")
    if fmt == "stix":
        from .stix import export_stix

        inv = store.get_investigation(inv_id)
        store.audit("report.export", inv.id, {"format": fmt})
        return json.dumps(export_stix(store, inv.id), indent=2)
    data = report_data(store, inv_id, settings)
    store.audit("report.export", data["investigation"]["id"], {"format": fmt})
    if fmt == "json":
        return json.dumps(data, indent=2, default=str)
    if fmt == "csv":
        return _csv(data)
    env = Environment(loader=PackageLoader("strxeye.reporting", "templates"),
                      autoescape=select_autoescape(["html"]))
    env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=1, default=str)
    return env.get_template("report.html").render(**data)


def _csv(data: dict[str, Any]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["entity_type", "entity", "kind", "value", "source", "method",
                     "collected_at_utc", "confidence", "evidence_id", "source_url"])
    for rows in data["findings"].values():
        for o in rows:
            value = o["value"] if isinstance(o["value"], str) else json.dumps(o["value"])
            writer.writerow([o["entity_type"], o["entity_value"], o["kind"],
                             _csv_safe(value), o["source"], o["method"], o["collected_at"],
                             o["confidence"], o["evidence_id"] or "", o["source_url"] or ""])
    return buf.getvalue()


def _csv_safe(value: str) -> str:
    # Values come from remote sources (TXT records, page titles). Prefix
    # anything a spreadsheet would treat as a formula.
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value
