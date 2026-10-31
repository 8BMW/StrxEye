"""Reputation services: AlienVault OTX and VirusTotal.

Both aggregate other people's judgements. OTX pulses are community
submissions, so appearing in one is a lead, not proof; VirusTotal verdicts
are counts of engines, and a handful of detections on a popular domain is
common noise. Observations keep the raw numbers so the analyst can judge.
"""

from __future__ import annotations

import json

from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, fetch
from .base import Collector, CollectorContext, Findings

OTX = "https://otx.alienvault.com/api/v1/indicators/"
VT = "https://www.virustotal.com/api/v3/"
MAX_PULSES = 25


def otx_section(target: EntityRef) -> str:
    if target.type is EntityType.DOMAIN:
        return f"domain/{target.value}"
    if target.type is EntityType.IP:
        return f"{'IPv6' if ':' in target.value else 'IPv4'}/{target.value}"
    return f"file/{target.value}"


class OtxCollector(Collector):
    name = "otx"
    title = "AlienVault OTX pulses"
    description = "Community threat reports (pulses) mentioning the indicator."
    accepts = frozenset({EntityType.DOMAIN, EntityType.IP, EntityType.HASH})
    sources = ("otx.alienvault.com",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        url = f"{OTX}{otx_section(target)}/general"
        key = ctx.secret("otx")
        headers = {"X-OTX-API-KEY": key} if key else None
        response = await fetch(ctx.client, url, headers=headers, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries, allow_statuses=(404,))
        if response.status_code == 404:
            return found
        try:
            data = response.json()
        except json.JSONDecodeError:
            raise FetchError("otx.alienvault.com did not return JSON") from None
        info = data.get("pulse_info") or {}
        pulses = info.get("pulses") or []
        # Keep the evidence small: the general endpoint embeds whole pulses.
        trimmed = {"indicator": data.get("indicator"), "reputation": data.get("reputation"),
                   "validation": data.get("validation"), "pulse_count": info.get("count"),
                   "pulses": [{k: p.get(k) for k in ("id", "name", "created", "modified",
                                                     "tags", "malware_families", "adversary",
                                                     "TLP", "author_name")}
                              for p in pulses[:MAX_PULSES]]}
        evidence = found.add_evidence(url, json.dumps(trimmed, indent=2, default=str),
                                      "application/json")
        obs = dict(method="OTX indicator lookup (HTTPS)", evidence_id=evidence, source_url=url)
        found.observe(target, "otx.pulse_count", info.get("count", 0), **obs)
        if data.get("validation"):
            # OTX marks well-known benign indicators (e.g. popular domains).
            found.observe(target, "otx.allowlisted",
                          [v.get("name") or v.get("message") for v in data["validation"]], **obs)
        for pulse in pulses[:MAX_PULSES]:
            ref = found.entity(EntityType.INDICATOR, f"OTX pulse {pulse.get('id')}",
                               kind="threat report", name=pulse.get("name"),
                               created=pulse.get("created"), tags=(pulse.get("tags") or [])[:10],
                               url=f"https://otx.alienvault.com/pulse/{pulse.get('id')}")
            found.observe(target, "otx.pulse", {"name": pulse.get("name"),
                                                "created": pulse.get("created"),
                                                "adversary": pulse.get("adversary") or None},
                          **obs, confidence=0.5)
            found.relate(target, RelationType.OBSERVED_IN, ref, evidence_id=evidence,
                         confidence=0.5)
            for family in pulse.get("malware_families") or []:
                label = family.get("display_name") if isinstance(family, dict) else family
                if label:
                    malware = found.entity(EntityType.MALWARE, str(label))
                    found.relate(ref, RelationType.ASSOCIATED_WITH, malware,
                                 evidence_id=evidence, confidence=0.5)
        if len(pulses) > MAX_PULSES:
            found.notes.append(f"{len(pulses)} pulses; kept {MAX_PULSES}")
        return found


class VirusTotalCollector(Collector):
    name = "virustotal"
    title = "VirusTotal reputation"
    description = "Engine verdicts, reputation, categories; threat label for hashes."
    accepts = frozenset({EntityType.DOMAIN, EntityType.IP, EntityType.HASH})
    sources = ("virustotal.com",)
    requires_key = "virustotal"

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        key = ctx.secret("virustotal")
        if not key:
            raise FetchError("no VirusTotal key; run: strxeye keys set virustotal")
        # Free keys allow 4 requests per minute.
        ctx.limiter.set_interval("www.virustotal.com", 15.0)
        path = {EntityType.DOMAIN: "domains", EntityType.IP: "ip_addresses",
                EntityType.HASH: "files"}[target.type]
        url = f"{VT}{path}/{target.value}"
        response = await fetch(ctx.client, url, headers={"x-apikey": key}, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries, allow_statuses=(404,))
        if response.status_code == 404:
            return found
        try:
            attrs = response.json()["data"]["attributes"]
        except (json.JSONDecodeError, KeyError):
            raise FetchError("virustotal.com returned an unexpected response") from None
        keep = ("last_analysis_stats", "reputation", "categories", "last_analysis_date",
                "meaningful_name", "type_description", "size", "names",
                "popular_threat_classification", "tags", "first_submission_date")
        trimmed = {k: attrs.get(k) for k in keep if attrs.get(k) is not None}
        evidence = found.add_evidence(url, json.dumps(trimmed, indent=2), "application/json")
        obs = dict(method="VirusTotal API v3 lookup", evidence_id=evidence,
                   source_url=f"https://www.virustotal.com/gui/search/{target.value}")
        stats = attrs.get("last_analysis_stats") or {}
        if stats:
            found.observe(target, "vt.analysis_stats", stats, **obs)
        if "reputation" in attrs:
            found.observe(target, "vt.reputation", attrs["reputation"], **obs)
        if attrs.get("categories"):
            found.observe(target, "vt.categories", sorted(set(attrs["categories"].values())),
                          **obs)
        if target.type is EntityType.HASH:
            for field in ("meaningful_name", "type_description", "size"):
                if attrs.get(field) is not None:
                    found.observe(target, f"vt.{field}", attrs[field], **obs)
            label = (attrs.get("popular_threat_classification") or {}).get(
                "suggested_threat_label")
            if label:
                malware = found.entity(EntityType.MALWARE, label)
                found.observe(target, "vt.threat_label", label, **obs, confidence=0.7)
                found.relate(target, RelationType.ASSOCIATED_WITH, malware, evidence_id=evidence,
                             confidence=0.7)
        return found
