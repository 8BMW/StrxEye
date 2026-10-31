"""Context for CVE identifiers: CISA's Known Exploited Vulnerabilities
catalogue (KEV) and FIRST's Exploit Prediction Scoring System (EPSS).

Used by collectors that report CVEs. The CVEs themselves usually come
from banner-based guesses, so this context says how serious a CVE would
be if present, not that it is present.
"""

from __future__ import annotations

import json
import time
from typing import Any

from ..config import cache_dir
from ..net import FetchError, fetch
from .base import CollectorContext

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_TTL = 24 * 3600


async def kev_catalog(ctx: CollectorContext) -> dict[str, dict[str, Any]]:
    if "kev" in ctx.cache:
        return ctx.cache["kev"]
    path = cache_dir() / "cisa-kev.json"
    if path.exists() and time.time() - path.stat().st_mtime < KEV_TTL:
        text = path.read_text(encoding="utf-8")
    else:
        response = await fetch(ctx.client, KEV_URL, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries)
        text = response.text
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    catalog = {
        v["cveID"].upper(): {
            "name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "ransomware": v.get("knownRansomwareCampaignUse"),
        }
        for v in json.loads(text).get("vulnerabilities", [])
    }
    ctx.cache["kev"] = catalog
    return catalog


async def epss_scores(ctx: CollectorContext, cves: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for i in range(0, len(cves), 100):  # the API accepts up to 100 CVEs per call
        batch = cves[i:i + 100]
        response = await fetch(ctx.client, EPSS_URL, params={"cve": ",".join(batch)},
                               limiter=ctx.limiter, retries=ctx.settings.network.retries)
        try:
            rows = response.json().get("data", [])
        except json.JSONDecodeError:
            raise FetchError("api.first.org did not return JSON") from None
        for row in rows:
            try:
                scores[row["cve"].upper()] = float(row["epss"])
            except (KeyError, ValueError):
                continue
    return scores
