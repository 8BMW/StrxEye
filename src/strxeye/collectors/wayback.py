from __future__ import annotations

import json
from datetime import UTC, datetime

from ..models import EntityRef, EntityType
from ..net import FetchError, fetch
from ..targets import host_of
from .base import Collector, CollectorContext, Findings

CDX = "https://web.archive.org/cdx/search/cdx"
METHOD = "Internet Archive CDX API"


def wayback_time(stamp: str) -> str:
    return datetime.strptime(stamp[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC).isoformat()


class WaybackCollector(Collector):
    name = "wayback"
    title = "Internet Archive snapshots"
    description = "First and latest archived capture of the site, one capture per year."
    accepts = frozenset({EntityType.DOMAIN, EntityType.URL})
    sources = ("web.archive.org",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        url_key = target.value if target.type is EntityType.URL else host_of(target)
        # collapse=timestamp:4 keeps the first capture of each year, which
        # keeps the response small for heavily archived sites.
        params = {"url": url_key, "output": "json", "fl": "timestamp,statuscode,original",
                  "collapse": "timestamp:4"}
        response = await fetch(ctx.client, CDX, params=params, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries)
        locator = str(response.request.url)
        try:
            rows = json.loads(response.text) if response.text.strip() else []
        except json.JSONDecodeError:
            raise FetchError("web.archive.org returned an unexpected response") from None
        captures = [dict(zip(rows[0], row, strict=False)) for row in rows[1:]] if rows else []
        if not captures:
            return found
        evidence = found.add_evidence(locator, response.text, "application/json")
        first, last = captures[0], captures[-1]
        obs = dict(method=METHOD, evidence_id=evidence, source_url=locator)
        found.observe(target, "archive.first_capture", wayback_time(first["timestamp"]), **obs)
        found.observe(target, "archive.latest_yearly_capture",
                      wayback_time(last["timestamp"]), **obs)
        found.observe(
            target,
            "archive.yearly_captures",
            [
                {
                    "year": c["timestamp"][:4],
                    "status": c.get("statuscode"),
                    "snapshot": f"https://web.archive.org/web/{c['timestamp']}/{c['original']}",
                }
                for c in captures
            ],
            **obs,
        )
        return found
