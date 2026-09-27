/**
 * Tipos del dominio forense Specter.
 * Espejo tipado de los modelos Pydantic del engine (specter.osint_core.models).
 */

export type EntityType =
  | "DOMAIN"
  | "SUBDOMAIN"
  | "IP_ADDRESS"
  | "PERSON"
  | "EMAIL"
  | "SOCIAL_PROFILE"
  | "FILE_ARTIFACT"
  | "GEO_LOCATION"
  | "ORGANIZATION"
  | "ALIAS"
  | "PHONE"
  | (string & {});

export type RelationType =
  | "RESOLVES_TO"
  | "SUBDOMAIN_OF"
  | "USES_EMAIL"
  | "OWNS_PROFILE"
  | "MENTIONED_IN"
  | "AUTHORED"
  | "LOCATED_AT"
  | "WORKS_FOR"
  | "RELATED_TO"
  | (string & {});

export interface CaseMetadata {
  case_id: string;
  name: string;
  description: string;
  investigator: string;
  created_at: string;
  status: string;
}

export interface EntityNode {
  id: string;
  type: EntityType;
  value: string;
  label?: string | null;
  attributes: Record<string, unknown>;
  confidence: number;
  first_seen: string;
  last_seen: string;
}

export interface RelationEdge {
  edge_id?: string;
  source_id: string;
  target_id: string;
  relation_type: RelationType;
  attributes: Record<string, unknown>;
  confidence: number;
  first_seen: string;
}

export interface LedgerBlock {
  case_id: string;
  block_index: number;
  timestamp: string;
  collector: string;
  action: string;
  evidence_id?: string | null;
  evidence_hash?: string | null;
  prev_hash: string;
  block_hash: string;
  /** Firma HMAC-SHA256 del block_hash; null si el caso se recolectó sin clave. */
  signature?: string | null;
}

/** Estado de sellado de la cadena: la UI lo muestra tal cual, sin interpretar. */
export type SignatureStatus =
  | "SEALED"
  | "PARTIAL"
  | "UNSIGNED"
  | "INVALID"
  | "KEY_UNAVAILABLE";

export interface LedgerReport {
  case_id: string;
  blocks: LedgerBlock[];
  signature_status: SignatureStatus | null;
  key_id: string | null;
  valid: boolean;
}

export interface LedgerAttestation {
  case_id: string;
  sealed: boolean;
  algorithm: string | null;
  key_id: string | null;
  chain_valid: boolean;
  signature_status?: SignatureStatus | null;
  total_blocks: number;
  head?: {
    block_index: number;
    block_hash: string;
    signature: string | null;
    action: string;
    timestamp: string;
  };
  attestation?: { payload: string; signature: string | null };
  error?: string;
}

export interface TimelineBucket {
  bucket: string;
  count: number;
  entities: number;
  evidences: number;
  ledger_blocks: number;
  types: Record<string, number>;
}

export interface TimelineEvent {
  timestamp: string;
  kind: "entity" | "evidence" | "ledger" | "agent";
  artifact_id: string;
  type?: EntityType;
  value?: string;
  label?: string;
  confidence?: number;
  last_seen?: string;
  collector?: string;
  source_url?: string;
  payload_hash?: string;
  action?: string;
  block_index?: number;
  block_hash?: string;
  signed?: boolean;
  /** Solo kind="agent": cabeza de la pregunta del analista. */
  prompt?: string;
  provider?: string;
  model?: string;
  status?: string;
  iterations?: number;
  tools_used?: number;
}

export interface TimelineReport {
  case_id: string;
  bucket: "day" | "hour";
  total_events: number;
  first_activity: string | null;
  last_activity: string | null;
  span_hours: number | null;
  buckets: TimelineBucket[];
  bursts: Array<{ bucket: string; count: number; ratio_vs_average: number }>;
  collectors: Record<string, number>;
  events: TimelineEvent[];
}

export interface CrossCaseMatch {
  entity_id: string;
  type: EntityType;
  value: string;
  confidence: number;
  case_count: number;
  case_ids: string[];
  first_seen: string;
  last_seen: string;
}

export interface CrossCaseReport {
  anchor_case: string | null;
  total_shared_entities: number;
  cases_involved: string[];
  cases_involved_count: number;
  by_type: Record<string, number>;
  matches: CrossCaseMatch[];
}

export interface IdentityCandidate {
  score: number;
  reason: string;
  normalized_key: string;
  suggested_relation: RelationType;
  entities: Array<{
    entity_id: string;
    type: EntityType;
    value: string;
    label: string;
    confidence: number;
  }>;
}

export interface IdentityCandidatesReport {
  case_id: string;
  analyzed_entities: number;
  total_candidates: number;
  min_score: number;
  candidates: IdentityCandidate[];
}

export interface CaseCorrelations {
  case_id: string;
  cross_case: CrossCaseReport;
  identity_candidates: IdentityCandidatesReport;
}

export interface GraphSubgraph {
  nodes: EntityNode[];
  edges: GraphEdge[];
  total_nodes: number;
  total_edges: number;
}

/** Arista tal como la entrega el engine: extremos `source/target`. */
export interface GraphEdge {
  source: string;
  target: string;
  relation_type: string;
  attributes?: Record<string, unknown>;
  confidence?: number;
  first_seen?: string;
}

export interface GraphMetrics {
  total_nodes: number;
  total_edges: number;
  density: number;
  top_pagerank?: Array<{ node: string; score: number }>;
  articulation_points?: string[];
}

export interface ToolInfo {
  name: string;
  description: string;
  schema: Record<string, unknown>;
}

export interface CaseCreated {
  status: "CASE_CREATED";
  case_id: string;
  name: string;
  investigator: string;
  genesis_hash: string;
  message: string;
}

export interface EngineHealth {
  status: "ok";
  engine: "specter";
  version: string;
  mcp_tools: number;
  data_dir: string;
  reports_dir: string;
  build_hash: string;
  started_at: string;
}

/** Sesión de conversación del agente (qué se preguntó y qué se ejecutó). */
export interface AgentSession {
  session_id: string;
  case_id: string | null;
  provider: string;
  model: string;
  status: "running" | "completed" | "error" | string;
  started_at: string;
  ended_at: string | null;
  iterations: number;
  tools_used: number;
  input_tokens: number;
  output_tokens: number;
  prompt: string;
  summary: string;
}

export interface AgentSessionMessage {
  id: number;
  session_id: string;
  seq: number;
  role: "user" | "assistant" | "tool" | "system" | string;
  content: string;
  tool: string | null;
  call_id: string | null;
  extra: Record<string, unknown>;
  ts: string;
}
