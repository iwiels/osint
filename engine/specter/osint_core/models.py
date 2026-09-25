"""
SpecterOSINT - Core Models
Definición de entidades, relaciones y esquemas de evidencia para investigación forense.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def current_utc_iso() -> str:
    return datetime.now(UTC).isoformat()


class EntityType(StrEnum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    ASN = "ASN"
    DNS_RECORD = "DNS_RECORD"
    SSL_CERTIFICATE = "SSL_CERTIFICATE"
    PERSON = "PERSON"
    ALIAS = "ALIAS"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    ORGANIZATION = "ORGANIZATION"
    FILE_ARTIFACT = "FILE_ARTIFACT"
    GEO_LOCATION = "GEO_LOCATION"


class RelationType(StrEnum):
    RESOLVES_TO = "RESOLVES_TO"
    SUBDOMAIN_OF = "SUBDOMAIN_OF"
    HOSTED_ON = "HOSTED_ON"
    REGISTERED_BY = "REGISTERED_BY"
    ADMINISTERS = "ADMINISTERS"
    USES_ALIAS = "USES_ALIAS"
    REGISTERED_WITH = "REGISTERED_WITH"
    CONTAINS_METADATA = "CONTAINS_METADATA"
    LOCATED_AT = "LOCATED_AT"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    CORRELATED_WITH = "CORRELATED_WITH"


class EntityNode(BaseModel):
    id: str = Field(description="Identificador único canonizado, e.g. 'domain:example.com'")
    type: EntityType
    value: str
    label: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    first_seen: str = Field(default_factory=current_utc_iso)
    last_seen: str = Field(default_factory=current_utc_iso)

    @classmethod
    def create(
        cls,
        type: EntityType,
        value: str,
        label: str | None = None,
        attributes: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ) -> "EntityNode":
        canonical_id = f"{type.value.lower()}:{value.strip().lower()}"
        return cls(
            id=canonical_id,
            type=type,
            value=value.strip(),
            label=label or value.strip(),
            attributes=attributes or {},
            confidence=confidence,
        )


class RelationEdge(BaseModel):
    source_id: str
    target_id: str
    relation_type: RelationType
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    first_seen: str = Field(default_factory=current_utc_iso)

    @property
    def edge_id(self) -> str:
        return f"{self.source_id}->{self.relation_type.value}->{self.target_id}"


class RawEvidence(BaseModel):
    id: str
    case_id: str
    collector: str
    source_url: str
    raw_payload: str
    payload_hash: str
    timestamp: str = Field(default_factory=current_utc_iso)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LedgerBlock(BaseModel):
    block_index: int
    case_id: str
    timestamp: str
    collector: str
    action: str
    evidence_id: str | None = None
    evidence_hash: str | None = None
    prev_hash: str
    block_hash: str


class CaseMetadata(BaseModel):
    case_id: str
    name: str
    description: str
    investigator: str
    created_at: str = Field(default_factory=current_utc_iso)
    status: str = "active"


class CollectorResult(BaseModel):
    collector_name: str
    source_target: str
    entities: list[EntityNode] = Field(default_factory=list)
    relations: list[RelationEdge] = Field(default_factory=list)
    raw_payload: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
