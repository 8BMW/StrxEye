"""Legal entities from the GLEIF LEI registry.

GLEIF is the official global register of Legal Entity Identifiers: it
covers companies, funds and other legal entities, with legal name,
jurisdiction, status and corporate parents. Searches are by name, so a
result is a *candidate* for the organisation you meant, not a confirmed
match; the relationship to the search term carries confidence 0.5.

Only organisation-level fields are kept (city and country, not street
addresses), which also avoids storing home addresses of sole traders.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import EntityRef, EntityType, RelationType
from ..net import FetchError, fetch
from .base import Collector, CollectorContext, Findings

API = "https://api.gleif.org/api/v1/lei-records"
METHOD = "GLEIF LEI registry search (HTTPS)"
MAX_RESULTS = 10
MAX_PARENT_LOOKUPS = 5


def summarize(record: dict[str, Any]) -> dict[str, Any]:
    attrs = record["attributes"]
    entity, reg = attrs["entity"], attrs["registration"]
    hq = entity.get("headquartersAddress") or {}
    return {
        "lei": attrs["lei"],
        "legal_name": entity["legalName"]["name"],
        "jurisdiction": entity.get("jurisdiction"),
        "status": entity.get("status"),
        "category": entity.get("category"),
        "hq_city": hq.get("city"),
        "hq_country": hq.get("country"),
        "registration_status": reg.get("status"),
        "registered_since": reg.get("initialRegistrationDate"),
    }


class GleifCollector(Collector):
    name = "gleif"
    title = "Company registry (GLEIF LEI)"
    description = "Legal entities matching a company name: jurisdiction, status, parent."
    accepts = frozenset({EntityType.ORGANIZATION})
    sources = ("api.gleif.org",)

    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings:
        found = Findings(self.name)
        params = {"filter[entity.legalName]": target.value, "page[size]": str(MAX_RESULTS)}
        response = await fetch(ctx.client, API, params=params, limiter=ctx.limiter,
                               retries=ctx.settings.network.retries)
        try:
            body = response.json()
        except json.JSONDecodeError:
            raise FetchError("api.gleif.org did not return JSON") from None
        records = body.get("data") or []
        if not records:
            return found
        locator = str(response.request.url)
        summaries = [summarize(r) for r in records]
        evidence = found.add_evidence(locator, json.dumps(summaries, indent=2),
                                      "application/json")
        total = body.get("meta", {}).get("pagination", {}).get("total", len(records))
        if total > MAX_RESULTS:
            found.notes.append(f"{total} matches; kept the first {MAX_RESULTS}. "
                               "Use a more specific name.")

        names = [s["legal_name"] for s in summaries]
        for i, info in enumerate(summaries):
            # Disambiguate same-named entities by jurisdiction.
            label = info["legal_name"]
            if names.count(label) > 1:
                label = f"{label} ({info['jurisdiction']})"
            org = found.entity(EntityType.ORGANIZATION, label, **info,
                               url=f"https://search.gleif.org/#/record/{info['lei']}")
            found.observe(target, "registry.candidate", info, method=METHOD,
                          evidence_id=evidence, source_url=locator, confidence=0.5)
            found.relate(target, RelationType.ASSOCIATED_WITH, org, evidence_id=evidence,
                         confidence=0.5)
            if i < MAX_PARENT_LOOKUPS:
                await self._parent(found, org, info["lei"], ctx)
        return found

    async def _parent(self, found: Findings, org: EntityRef, lei: str,
                      ctx: CollectorContext) -> None:
        url = f"{API}/{lei}/direct-parent"
        try:
            response = await fetch(ctx.client, url, limiter=ctx.limiter, retries=1,
                                   allow_statuses=(404,))
        except FetchError as exc:
            found.partial = True
            found.notes.append(f"parent lookup for {lei} failed: {exc}")
            return
        if response.status_code == 404:
            return  # no parent reported, or the entity reported an exception
        try:
            parent = summarize(response.json()["data"])
        except (json.JSONDecodeError, KeyError, TypeError):
            return
        evidence = found.add_evidence(url, json.dumps(parent, indent=2), "application/json")
        ref = found.entity(EntityType.ORGANIZATION, parent["legal_name"], **parent,
                           url=f"https://search.gleif.org/#/record/{parent['lei']}")
        # Parent relationships are reported to GLEIF and checked by the LOU.
        found.relate(org, RelationType.OPERATED_BY, ref, evidence_id=evidence, confidence=0.9)
        found.observe(org, "registry.direct_parent", parent["legal_name"], method=METHOD,
                      evidence_id=evidence, source_url=url, confidence=0.9)
