"""Collector interface.

A collector takes one normalised target and reports what one source says
about it. Collectors never write to storage and never raise for "nothing
found"; they return an empty ``Findings`` and the engine records NO_DATA.
Exceptions are reserved for real failures and become ERROR results.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

import dns.asyncresolver
import httpx

from ..config import Settings
from ..models import (
    CollectionStatus,
    Entity,
    EntityRef,
    EntityType,
    Evidence,
    Observation,
    Relationship,
    RelationType,
)
from ..net import RateLimiter


@dataclass
class CollectorContext:
    settings: Settings
    client: httpx.AsyncClient
    limiter: RateLimiter
    resolver: dns.asyncresolver.Resolver
    # Shared per-run cache for things like RDAP bootstrap files, so ten
    # collectors in one run do not download them ten times.
    cache: dict[str, Any] = field(default_factory=dict)
    # Looks up an API key by name (see strxeye.secrets). Injected so tests
    # and the engine control where keys come from.
    secret: Callable[[str], str | None] = lambda name: None


class Findings:
    """Accumulates the output of one collector run."""

    def __init__(self, collector: str):
        self.collector = collector
        self.entities: dict[EntityRef, Entity] = {}
        self.observations: list[Observation] = []
        self.relationships: list[Relationship] = []
        self.evidence: dict[str, Evidence] = {}
        self.notes: list[str] = []
        self.partial = False

    def entity(self, type: EntityType, value: str, **attributes: Any) -> EntityRef:
        ref = EntityRef(type=type, value=value)
        existing = self.entities.get(ref)
        if existing is None:
            self.entities[ref] = Entity(type=type, value=value, attributes=attributes)
        else:
            existing.attributes.update({k: v for k, v in attributes.items() if v is not None})
        return ref

    def add_evidence(self, locator: str, content: str, content_type: str = "text/plain") -> str:
        item = Evidence.from_content(self.collector, locator, content, content_type)
        self.evidence.setdefault(item.id, item)
        return item.id

    def observe(
        self,
        entity: EntityRef,
        kind: str,
        value: Any,
        *,
        method: str,
        evidence_id: str | None = None,
        source_url: str | None = None,
        confidence: float = 1.0,
    ) -> None:
        self.observations.append(
            Observation(
                entity=entity,
                kind=kind,
                value=value,
                source=self.collector,
                method=method,
                source_url=source_url,
                confidence=confidence,
                evidence_id=evidence_id,
            )
        )

    def relate(
        self,
        source: EntityRef,
        type: RelationType,
        target: EntityRef,
        *,
        evidence_id: str | None = None,
        confidence: float = 1.0,
    ) -> None:
        if source == target:
            return
        self.relationships.append(
            Relationship(
                source=source,
                target=target,
                type=type,
                origin=self.collector,
                confidence=confidence,
                evidence_id=evidence_id,
            )
        )

    @property
    def empty(self) -> bool:
        return not (self.observations or self.relationships)

    @property
    def status(self) -> CollectionStatus:
        if self.empty:
            return CollectionStatus.NO_DATA
        return CollectionStatus.PARTIAL if self.partial else CollectionStatus.OK


class Collector(ABC):
    name: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str]
    version: ClassVar[str] = "1.0"
    accepts: ClassVar[frozenset[EntityType]]
    # Third-party services this collector sends the target to. Shown to the
    # user so they know where their queries go.
    sources: ClassVar[tuple[str, ...]] = ()
    # True when the collector connects to the target's own infrastructure.
    direct: ClassVar[bool] = False
    # Name of an API key (strxeye.secrets) the collector cannot work without.
    requires_key: ClassVar[str | None] = None

    def supports(self, target: EntityRef) -> bool:
        return target.type in self.accepts

    @abstractmethod
    async def collect(self, target: EntityRef, ctx: CollectorContext) -> Findings: ...

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {
            "name": cls.name,
            "title": cls.title,
            "description": cls.description,
            "version": cls.version,
            "accepts": sorted(t.value for t in cls.accepts),
            "sources": list(cls.sources),
            "direct": cls.direct,
            "requires_key": cls.requires_key,
        }
