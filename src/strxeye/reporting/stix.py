"""STIX 2.1 export.

Entities become STIX Cyber-observable Objects (domain-name, ipv4-addr,
x509-certificate, ...) or domain objects (identity, malware,
vulnerability). Observed relationships become relationship objects; threat
list hits become indicators and OTX pulses become reports.

Inferred relationships are left out on purpose: STIX consumers treat
relationships as assertions, and STRX EYE's correlation output is a hint
for the analyst, not something to propagate into other platforms.

SCO identifiers are deterministic UUIDv5 values as defined in the STIX 2.1
specification (section 2.9), so the same domain exported twice, or by
another tool, gets the same ID.
"""

from __future__ import annotations

import ipaddress
import json
import uuid
from typing import Any

from .. import __version__
from ..graph import build_graph
from ..storage import Store

STIX_SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
# Namespace for STRX EYE's own SDO IDs (identity, malware, indicators).
STRXEYE_NAMESPACE = uuid.UUID("6b1f3c4e-2a59-5d1e-9c43-7d6a0e5b1f20")
HASH_NAMES = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
HIGH_SEVERITY = {"high"}


def _sco_id(type_: str, contributing: dict[str, Any]) -> str:
    canonical = json.dumps(contributing, sort_keys=True, separators=(",", ":"))
    return f"{type_}--{uuid.uuid5(STIX_SCO_NAMESPACE, canonical)}"


def _sdo_id(type_: str, key: str) -> str:
    return f"{type_}--{uuid.uuid5(STRXEYE_NAMESPACE, key)}"


def _ts(value: str | None) -> str:
    """STIX timestamps are RFC 3339 in UTC with a Z suffix."""
    if not value:
        return "1970-01-01T00:00:00Z"
    value = value.replace("+00:00", "")
    if "." in value:
        head, frac = value.split(".", 1)
        value = f"{head}.{frac[:3]}"
    return value if value.endswith("Z") else value + "Z"


def _object(node: dict[str, Any], created: str, identity: str) -> dict[str, Any] | None:
    t, v, attrs = node["type"], node["value"], node["attributes"]
    if t == "domain":
        return {"type": "domain-name", "spec_version": "2.1",
                "id": _sco_id("domain-name", {"value": v}), "value": v}
    if t in ("ip", "network"):
        first = v.split("-")[0].split("/")[0]
        try:
            version = ipaddress.ip_address(first).version
        except ValueError:
            return None
        if "-" in v:
            return None  # ranges that are not a CIDR block have no STIX form
        kind = "ipv4-addr" if version == 4 else "ipv6-addr"
        return {"type": kind, "spec_version": "2.1", "id": _sco_id(kind, {"value": v}),
                "value": v}
    if t == "asn":
        number = int(v[2:])
        obj = {"type": "autonomous-system", "spec_version": "2.1",
               "id": _sco_id("autonomous-system", {"number": number}), "number": number}
        if attrs.get("name"):
            obj["name"] = attrs["name"]
        return obj
    if t == "url":
        return {"type": "url", "spec_version": "2.1", "id": _sco_id("url", {"value": v}),
                "value": v}
    if t == "hash":
        name = HASH_NAMES.get(len(v))
        if not name:
            return None
        hashes = {name: v}
        return {"type": "file", "spec_version": "2.1", "id": _sco_id("file", {"hashes": hashes}),
                "hashes": hashes}
    if t == "certificate":
        obj: dict[str, Any] = {"type": "x509-certificate", "spec_version": "2.1"}
        if v.startswith("sha256:"):
            obj["hashes"] = {"SHA-256": v[7:]}
            obj["id"] = _sco_id("x509-certificate", {"hashes": obj["hashes"]})
        else:
            if not attrs.get("serial"):
                return None
            obj["serial_number"] = str(attrs["serial"])
            obj["id"] = _sco_id("x509-certificate", {"serial_number": obj["serial_number"]})
        for src, dst in (("issuer", "issuer"), ("subject", "subject"),
                         ("not_before", "validity_not_before"),
                         ("not_after", "validity_not_after")):
            if attrs.get(src):
                obj[dst] = _ts(attrs[src]) if dst.startswith("validity") else str(attrs[src])
        return obj
    if t == "technology":
        return {"type": "software", "spec_version": "2.1",
                "id": _sco_id("software", {"name": v}), "name": v}
    if t == "organization":
        return {"type": "identity", "spec_version": "2.1", "id": _sdo_id("identity", v),
                "created": created, "modified": created, "created_by_ref": identity,
                "name": v, "identity_class": "organization"}
    if t == "malware":
        return {"type": "malware", "spec_version": "2.1", "id": _sdo_id("malware", v),
                "created": created, "modified": created, "created_by_ref": identity,
                "name": v, "is_family": True}
    if t == "indicator" and attrs.get("kind") == "vulnerability":
        return {"type": "vulnerability", "spec_version": "2.1",
                "id": _sdo_id("vulnerability", v), "created": created, "modified": created,
                "created_by_ref": identity, "name": v,
                "external_references": [{"source_name": "cve", "external_id": v}]}
    return None  # threat lists and OTX pulses are exported as indicators/reports below


def export_stix(store: Store, inv_id: str) -> dict[str, Any]:
    graph = build_graph(store, inv_id, include_inferred=False)
    inv = graph["investigation"]
    created = _ts(graph["exported_at"])
    identity = _sdo_id("identity", "strxeye-tool")
    objects: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": identity, "created": created,
        "modified": created, "name": f"STRX EYE {__version__}", "identity_class": "system",
        "description": "Exported from a local STRX EYE investigation. Only relationships "
                       "observed by sources are included; inferred links are omitted.",
    }]
    ids: dict[int, str] = {}
    for node in graph["nodes"]:
        obj = _object(node, created, identity)
        if obj:
            ids[node["id"]] = obj["id"]
            objects.append(obj)

    for edge in graph["edges"]:
        src, dst = ids.get(edge["source"]), ids.get(edge["target"])
        if not src or not dst:
            continue
        first = min(p["collected_at"] for p in edge["provenance"])
        objects.append({
            "type": "relationship", "spec_version": "2.1",
            "id": _sdo_id("relationship", f"{inv['id']}:{edge['id']}"),
            "created": _ts(first), "modified": created, "created_by_ref": identity,
            "relationship_type": edge["type"].replace("_", "-"),
            "source_ref": src, "target_ref": dst,
            "confidence": round(edge["confidence"] * 100),
            "description": "Reported by " + ", ".join(sorted({p["origin"] for p in
                                                              edge["provenance"]})),
        })

    for obs in store.all_observations(inv_id):
        entity_ref = next((ids[n["id"]] for n in graph["nodes"]
                           if n["type"] == obs["entity_type"] and n["value"] == obs["entity_value"]
                           and n["id"] in ids), None)
        if entity_ref is None:
            continue
        if obs["kind"] == "threat.listed":
            objects.append(_indicator(obs, entity_ref, identity, inv["id"]))
        elif obs["kind"] == "otx.pulse":
            value = obs["value"]
            objects.append({
                "type": "report", "spec_version": "2.1",
                "id": _sdo_id("report", f"{inv['id']}:{obs['id']}"),
                "created": _ts(obs["collected_at"]), "modified": created,
                "created_by_ref": identity, "name": value.get("name") or "OTX pulse",
                "published": _ts(value.get("created")), "report_types": ["threat-report"],
                "object_refs": [entity_ref],
                "description": "Community threat report from AlienVault OTX that mentions "
                               "this indicator. Inclusion is not proof of malicious use.",
            })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _indicator(obs: dict[str, Any], entity_ref: str, identity: str, inv_id: str) -> dict:
    value = obs["value"]
    kind = entity_ref.split("--")[0]
    severity = value.get("severity")
    return {
        "type": "indicator", "spec_version": "2.1",
        "id": _sdo_id("indicator", f"{inv_id}:{obs['id']}"),
        "created": _ts(obs["collected_at"]), "modified": _ts(obs["collected_at"]),
        "created_by_ref": identity,
        "name": f"{obs['entity_value']} listed in {value.get('feed')}",
        "description": value.get("meaning", ""),
        "indicator_types": ["malicious-activity"] if severity in HIGH_SEVERITY
        else ["anonymization"],
        "pattern": f"[{kind}:value = '{obs['entity_value']}']",
        "pattern_type": "stix",
        "valid_from": _ts(obs["collected_at"]),
        "confidence": round(obs["confidence"] * 100),
    }
