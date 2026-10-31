"""Data model shared by collectors, storage, the CLI and the local API.

The core distinction is between three things:

* ``Entity`` - something that exists (a domain, an IP, a certificate).
* ``Observation`` - a fact a source reported about one entity at one time.
* ``Relationship`` - a directed link between two entities, either observed
  directly by a source or inferred by the correlation step.

Every observation and relationship carries its source, a UTC timestamp, a
confidence and (where there was a raw response) a reference to the stored
evidence it was parsed from.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class EntityType(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    NETWORK = "network"
    ASN = "asn"
    ORGANIZATION = "organization"
    CERTIFICATE = "certificate"
    URL = "url"
    TECHNOLOGY = "technology"
    HASH = "hash"
    INDICATOR = "indicator"
    MALWARE = "malware"


class RelationType(StrEnum):
    RESOLVES_TO = "resolves_to"
    ALIAS_OF = "alias_of"
    USES_NAMESERVER = "uses_nameserver"
    MAIL_HANDLED_BY = "mail_handled_by"
    SUBDOMAIN_OF = "subdomain_of"
    REVERSE_DNS = "reverse_dns"
    REGISTERED_THROUGH = "registered_through"
    BELONGS_TO_NETWORK = "belongs_to_network"
    ANNOUNCED_BY = "announced_by"
    OPERATED_BY = "operated_by"
    USES_CERTIFICATE = "uses_certificate"
    CERTIFICATE_ISSUED_FOR = "certificate_issued_for"
    ISSUED_BY = "issued_by"
    USES_TECHNOLOGY = "uses_technology"
    HOSTED_BY = "hosted_by"
    ASSOCIATED_WITH = "associated_with"
    OBSERVED_IN = "observed_in"
    SHARES_INFRASTRUCTURE = "shares_infrastructure"


class CollectionStatus(StrEnum):
    OK = "ok"
    NO_DATA = "no_data"
    PARTIAL = "partial"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class EntityRef(BaseModel, frozen=True):
    type: EntityType
    value: str

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"

    def __str__(self) -> str:
        return self.key


class Entity(BaseModel):
    type: EntityType
    value: str
    attributes: dict[str, Any] = Field(default_factory=dict)

    @property
    def ref(self) -> EntityRef:
        return EntityRef(type=self.type, value=self.value)


class Evidence(BaseModel):
    """A raw response kept so every parsed fact can be traced back.

    ``id`` is the SHA-256 of the content, which deduplicates identical
    responses and lets a report reader verify the stored bytes.
    """

    id: str
    collector: str
    locator: str  # URL or query that produced the content
    content_type: str
    content: str
    collected_at: datetime = Field(default_factory=utcnow)

    @classmethod
    def from_content(
        cls, collector: str, locator: str, content: str, content_type: str = "text/plain"
    ) -> Evidence:
        digest = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
        return cls(
            id=digest,
            collector=collector,
            locator=locator,
            content_type=content_type,
            content=content,
        )


class Observation(BaseModel):
    entity: EntityRef
    kind: str  # namespaced, e.g. "dns.mx" or "http.header.missing"
    value: Any
    source: str
    method: str
    source_url: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_id: str | None = None
    collected_at: datetime = Field(default_factory=utcnow)


class Relationship(BaseModel):
    source: EntityRef
    target: EntityRef
    type: RelationType
    origin: str  # collector name, or "correlation" for inferred links
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_id: str | None = None
    inferred: bool = False
    explanation: str | None = None
    collected_at: datetime = Field(default_factory=utcnow)


class CollectorResult(BaseModel):
    collector: str
    target: EntityRef
    status: CollectionStatus
    started_at: datetime
    finished_at: datetime
    entities: list[Entity] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    error: str | None = None
    notes: list[str] = Field(default_factory=list)

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at - self.started_at).total_seconds() * 1000)


class Investigation(BaseModel):
    id: str
    name: str
    description: str = ""
    created_at: datetime
    updated_at: datetime
    seeds: list[EntityRef] = Field(default_factory=list)
