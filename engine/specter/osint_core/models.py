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
    DOCUMENT_ID = "DOCUMENT_ID"
    UNKNOWN = "UNKNOWN"


_SOCIAL_PLATFORMS = {
    "FACEBOOK",
    "TWITTER",
    "X",
    "INSTAGRAM",
    "TIKTOK",
    "LINKEDIN",
    "GITHUB",
    "TRELLO",
    "PINTEREST",
    "YOUTUBE",
    "REDDIT",
    "TELEGRAM",
    "WHATSAPP",
    "SNAPCHAT",
    "DISCORD",
    "SOCIAL",
    "SOCIAL_PROFILE",
}

_SOCIAL_DOMAINS = {
    "facebook.com",
    "fb.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "instagr.am",
    "tiktok.com",
    "linkedin.com",
    "github.com",
    "trello.com",
    "pinterest.com",
    "youtube.com",
    "youtu.be",
    "reddit.com",
    "telegram.org",
    "t.me",
    "telegram.me",
    "whatsapp.com",
    "snapchat.com",
    "discord.com",
    "discord.gg",
}

_ENTITY_TYPE_ALIASES = {
    "IP": EntityType.IP_ADDRESS,
    "IP_ADDRESS": EntityType.IP_ADDRESS,
    "DOMAIN": EntityType.DOMAIN,
    "SUBDOMAIN": EntityType.SUBDOMAIN,
    "SUB": EntityType.SUBDOMAIN,
    "ASN": EntityType.ASN,
    "DNS": EntityType.DNS_RECORD,
    "DNS_RECORD": EntityType.DNS_RECORD,
    "CERT": EntityType.SSL_CERTIFICATE,
    "SSL": EntityType.SSL_CERTIFICATE,
    "SSL_CERTIFICATE": EntityType.SSL_CERTIFICATE,
    "PERSON": EntityType.PERSON,
    "ALIAS": EntityType.ALIAS,
    "EMAIL": EntityType.EMAIL,
    "PHONE": EntityType.PHONE,
    "SOCIAL": EntityType.SOCIAL_PROFILE,
    "SOCIAL_PROFILE": EntityType.SOCIAL_PROFILE,
    "PROFILE": EntityType.SOCIAL_PROFILE,
    "ORG": EntityType.ORGANIZATION,
    "ORGANIZATION": EntityType.ORGANIZATION,
    "FILE": EntityType.FILE_ARTIFACT,
    "FILE_ARTIFACT": EntityType.FILE_ARTIFACT,
    "GEO": EntityType.GEO_LOCATION,
    "GEO_LOCATION": EntityType.GEO_LOCATION,
    "DOC": EntityType.DOCUMENT_ID,
    "DOCUMENT": EntityType.DOCUMENT_ID,
    "DOCUMENT_ID": EntityType.DOCUMENT_ID,
    "UNKNOWN": EntityType.UNKNOWN,
}


def parse_entity_type(raw: str | None, default: EntityType = EntityType.UNKNOWN) -> EntityType:
    if not raw:
        return default
    normalized = str(raw).strip().upper().replace("-", "_")
    if normalized in _SOCIAL_PLATFORMS:
        return EntityType.SOCIAL_PROFILE
    if normalized in _ENTITY_TYPE_ALIASES:
        return _ENTITY_TYPE_ALIASES[normalized]
    if normalized in EntityType.__members__:
        return EntityType[normalized]
    try:
        return EntityType(normalized)
    except (ValueError, KeyError):
        return default


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
    NAMED_ON_DOCUMENT = "NAMED_ON_DOCUMENT"
    HAS_DOCUMENT = "HAS_DOCUMENT"


def parse_relation_type(
    raw: str | None, default: RelationType = RelationType.ASSOCIATED_WITH
) -> RelationType:
    if not raw:
        return default
    normalized = str(raw).strip().upper().replace("-", "_").replace(" ", "_")
    if normalized in RelationType.__members__:
        return RelationType[normalized]
    try:
        return RelationType(normalized)
    except (ValueError, KeyError):
        return default


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

    @classmethod
    def from_node_id(
        cls,
        node_id: str,
        label: str | None = None,
        attributes: dict[str, Any] | None = None,
        confidence: float = 1.0,
        first_seen: str = "",
        last_seen: str = "",
    ) -> "EntityNode":
        cleaned_id = str(node_id).strip()
        etype = EntityType.UNKNOWN
        val = cleaned_id

        # Si el node_id es directamente una URL (http:// o https://)
        if cleaned_id.lower().startswith(("http://", "https://")):
            val = cleaned_id
            if any(domain in cleaned_id.lower() for domain in _SOCIAL_DOMAINS):
                etype = EntityType.SOCIAL_PROFILE
            else:
                etype = EntityType.UNKNOWN
        elif ":" in cleaned_id:
            raw_type, remainder = cleaned_id.split(":", 1)
            raw_type_clean = raw_type.strip().lower()
            remainder_clean = remainder.strip()

            if raw_type_clean in ("http", "https"):
                val = cleaned_id
                if any(domain in cleaned_id.lower() for domain in _SOCIAL_DOMAINS):
                    etype = EntityType.SOCIAL_PROFILE
                else:
                    etype = EntityType.UNKNOWN
            else:
                parsed = parse_entity_type(raw_type_clean, default=EntityType.UNKNOWN)
                if parsed != EntityType.UNKNOWN:
                    etype = parsed
                    val = remainder_clean or cleaned_id
                else:
                    if raw_type_clean.upper() in _SOCIAL_PLATFORMS or any(
                        domain in remainder_clean.lower() for domain in _SOCIAL_DOMAINS
                    ):
                        etype = EntityType.SOCIAL_PROFILE
                    else:
                        etype = EntityType.UNKNOWN
                    val = remainder_clean or cleaned_id
        else:
            if "@" in cleaned_id and " " not in cleaned_id:
                etype = EntityType.EMAIL
            elif any(domain in cleaned_id.lower() for domain in _SOCIAL_DOMAINS):
                etype = EntityType.SOCIAL_PROFILE
            else:
                etype = EntityType.UNKNOWN
            val = cleaned_id

        ts = first_seen or current_utc_iso()
        return cls(
            id=cleaned_id,
            type=etype,
            value=val,
            label=label or val,
            attributes=attributes or {},
            confidence=confidence,
            first_seen=ts,
            last_seen=last_seen or ts,
        )


def sanitize_node_dict(node_data: dict[str, Any], node_id: str | None = None) -> dict[str, Any]:
    nid = str(node_data.get("id") or node_id or "").strip()
    stub = EntityNode.from_node_id(
        nid,
        first_seen=str(node_data.get("first_seen") or ""),
        last_seen=str(node_data.get("last_seen") or ""),
    )
    raw_type = node_data.get("type")
    etype = parse_entity_type(raw_type, default=stub.type) if raw_type else stub.type
    val = str(node_data.get("value") or "").strip() or stub.value
    label = str(node_data.get("label") or val).strip() or val
    confidence = node_data.get("confidence")
    if confidence is None:
        confidence = 1.0
    else:
        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (ValueError, TypeError):
            confidence = 1.0
    attrs = node_data.get("attributes")
    if not isinstance(attrs, dict):
        attrs = {}
    first_seen = str(node_data.get("first_seen") or stub.first_seen)
    last_seen = str(node_data.get("last_seen") or stub.last_seen)

    return {
        "id": nid,
        "type": etype.value,
        "value": val,
        "label": label,
        "confidence": confidence,
        "attributes": attrs,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def sanitize_edge_dict(
    edge_data: dict[str, Any], source: str = "", target: str = ""
) -> dict[str, Any]:
    src = str(edge_data.get("source") or edge_data.get("source_id") or source or "").strip()
    tgt = str(edge_data.get("target") or edge_data.get("target_id") or target or "").strip()
    raw_rel = edge_data.get("relation_type")
    rel_type = parse_relation_type(raw_rel, default=RelationType.ASSOCIATED_WITH).value
    attrs = edge_data.get("attributes")
    if not isinstance(attrs, dict):
        attrs = {}
    conf = edge_data.get("confidence")
    if conf is None:
        conf = 1.0
    else:
        try:
            conf = max(0.0, min(1.0, float(conf)))
        except (ValueError, TypeError):
            conf = 1.0
    first_seen = str(edge_data.get("first_seen") or current_utc_iso())
    return {
        "source": src,
        "target": tgt,
        "relation_type": rel_type,
        "attributes": attrs,
        "confidence": conf,
        "first_seen": first_seen,
    }


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
    # Firma HMAC del block_hash (fase B): sin clave de firma queda en None y el
    # bloque sigue siendo verificable por la cadena SHA-256, pero no sellable.
    signature: str | None = None


class CaseMetadata(BaseModel):
    case_id: str
    name: str
    description: str
    investigator: str
    created_at: str = Field(default_factory=current_utc_iso)
    status: str = "active"


class AgentSession(BaseModel):
    """Una conversación del agente (estilo opencode session): qué se preguntó,
    con qué provider/modelo, cuántas iteraciones y tools consumió."""

    session_id: str
    case_id: str | None = None
    provider: str = ""
    model: str = ""
    status: str = "running"  # running | completed | error | cancelled
    started_at: str = Field(default_factory=current_utc_iso)
    ended_at: str | None = None
    iterations: int = 0
    tools_used: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    prompt: str = ""  # cabeza del mensaje del analista (para listados)
    summary: str = ""  # cabeza del mensaje final (para listados)


class AgentMessage(BaseModel):
    """Un mensaje de la transcripción: user | assistant | tool | system."""

    id: int = 0
    session_id: str
    seq: int = 0
    role: str
    content: str = ""
    tool: str | None = None
    call_id: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)
    ts: str = Field(default_factory=current_utc_iso)


class CollectorResult(BaseModel):
    collector_name: str
    source_target: str
    entities: list[EntityNode] = Field(default_factory=list)
    relations: list[RelationEdge] = Field(default_factory=list)
    raw_payload: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# ------------------------------------------------------------------
# Contrato motor <-> UI (fuente de verdad para el SDK generado y los
# response_model de FastAPI). Si una forma cambia aquí, el check de
# contrato y `npm run gen:sdk:check` fallan: la deriva se vuelve ruidosa
# en vez de silenciosa (canvas negro).
# ------------------------------------------------------------------


class GraphEdge(BaseModel):
    """Arista tal como la sirve el engine: extremos `source`/`target`."""

    source: str
    target: str
    relation_type: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    first_seen: str = ""


class GraphSubgraph(BaseModel):
    nodes: list[EntityNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0


class TimelineEvent(BaseModel):
    """Evento heterogéneo de la timeline: cada kind rellena sus campos."""

    timestamp: str
    kind: str  # entity | evidence | ledger | agent
    artifact_id: str
    type: EntityType | None = None
    value: str | None = None
    label: str | None = None
    confidence: float | None = None
    last_seen: str | None = None
    collector: str | None = None
    source_url: str | None = None
    payload_hash: str | None = None
    action: str | None = None
    block_index: int | None = None
    block_hash: str | None = None
    signed: bool | None = None
    prompt: str | None = None
    provider: str | None = None
    model: str | None = None
    status: str | None = None
    iterations: int | None = None
    tools_used: int | None = None


class TimelineBucket(BaseModel):
    bucket: str
    count: int = 0
    entities: int = 0
    evidences: int = 0
    ledger_blocks: int = 0
    agent: int = 0
    types: dict[str, int] = Field(default_factory=dict)


class TimelineBurst(BaseModel):
    bucket: str
    count: int = 0
    ratio_vs_average: float = 0.0


class TimelineReport(BaseModel):
    case_id: str
    bucket: str
    total_events: int = 0
    first_activity: str | None = None
    last_activity: str | None = None
    span_hours: float | None = None
    buckets: list[TimelineBucket] = Field(default_factory=list)
    bursts: list[TimelineBurst] = Field(default_factory=list)
    collectors: dict[str, int] = Field(default_factory=dict)
    events: list[TimelineEvent] = Field(default_factory=list)


class UsageRecord(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0


class ToolCallRecord(BaseModel):
    call_id: str
    tool: str
    result: str


class AgentRunResult(BaseModel):
    status: str
    provider: str
    model: str
    session_id: str
    iterations: int = 0
    tools_used: list[ToolCallRecord] = Field(default_factory=list)
    final_message: str = ""
    usage: UsageRecord = Field(default_factory=UsageRecord)


class CaseCreatedOut(BaseModel):
    status: str
    case_id: str
    name: str
    investigator: str
    genesis_hash: str
    message: str


class SessionsOut(BaseModel):
    sessions: list[AgentSession] = Field(default_factory=list)


class SessionDetailOut(BaseModel):
    session: AgentSession
    messages: list[AgentMessage] = Field(default_factory=list)


class HealthOut(BaseModel):
    status: str
    engine: str
    version: str
    mcp_tools: int = 0
    data_dir: str = ""
    reports_dir: str = ""
    build_hash: str = "unknown"
    started_at: str = ""
