/**
 * GENERADO por scripts/gen_sdk_types.py — no editar a mano.
 * Fuente de verdad: response_model de FastAPI en engine/http_server.py
 * (modelos en engine/specter/osint_core/models.py).
 * Regenerar con: npm run gen:sdk
 */

export interface AgentMessage {
  id?: number;
  session_id: string;
  seq?: number;
  role: string;
  content?: string;
  tool?: string | null;
  call_id?: string | null;
  extra?: Record<string, unknown>;
  ts?: string;
}

export interface AgentPermission {
  request_id: string;
  decision: string;
}

export interface AgentQuestionReply {
  request_id: string;
  answers?: string[][];
}

export interface AgentRunRequest {
  case_id?: string | null;
  session_id?: string | null;
  message: string;
  provider?: string;
  model?: string | null;
  api_key?: string | null;
  base_url?: string | null;
  max_iterations?: number;
  stream?: boolean;
  plan_first?: boolean;
  auto_approve?: boolean;
}

export interface AgentRunResult {
  status: string;
  provider: string;
  model: string;
  session_id: string;
  iterations?: number;
  tools_used?: ToolCallRecord[];
  final_message?: string;
  usage?: UsageRecord;
}

export interface AgentSession {
  session_id: string;
  case_id?: string | null;
  provider?: string;
  model?: string;
  status?: string;
  started_at?: string;
  ended_at?: string | null;
  iterations?: number;
  tools_used?: number;
  input_tokens?: number;
  output_tokens?: number;
  prompt?: string;
  summary?: string;
}

export interface CaseCreate {
  name: string;
  description: string;
  investigator?: string;
}

export interface CaseCreatedOut {
  status: string;
  case_id: string;
  name: string;
  investigator: string;
  genesis_hash: string;
  message: string;
}

export interface EntityNode {
  id: string;
  type: EntityType;
  value: string;
  label?: string | null;
  attributes?: Record<string, unknown>;
  confidence?: number;
  first_seen?: string;
  last_seen?: string;
}

export type EntityType = "DOMAIN" | "SUBDOMAIN" | "IP_ADDRESS" | "ASN" | "DNS_RECORD" | "SSL_CERTIFICATE" | "PERSON" | "ALIAS" | "EMAIL" | "PHONE" | "SOCIAL_PROFILE" | "ORGANIZATION" | "FILE_ARTIFACT" | "GEO_LOCATION" | "DOCUMENT_ID" | "CVE" | "BREACH" | "PORT" | "UNKNOWN";

export interface GraphEdge {
  source: string;
  target: string;
  relation_type: string;
  attributes?: Record<string, unknown>;
  confidence?: number;
  first_seen?: string;
}

export interface GraphSubgraph {
  nodes?: EntityNode[];
  edges?: GraphEdge[];
  total_nodes?: number;
  total_edges?: number;
}

export interface HTTPValidationError {
  detail?: ValidationError[];
}

export interface HealthOut {
  status: string;
  engine: string;
  version: string;
  mcp_tools?: number;
  data_dir?: string;
  reports_dir?: string;
  build_hash?: string;
  started_at?: string;
}

export interface RunsCancelRequest {
  session_id?: string | null;
}

export interface SecretUpsert {
  value: string;
}

export interface SessionDetailOut {
  session: AgentSession;
  messages?: AgentMessage[];
}

export interface SessionsOut {
  sessions?: AgentSession[];
}

export interface TimelineBucket {
  bucket: string;
  count?: number;
  entities?: number;
  evidences?: number;
  ledger_blocks?: number;
  agent?: number;
  types?: Record<string, number>;
}

export interface TimelineBurst {
  bucket: string;
  count?: number;
  ratio_vs_average?: number;
}

export interface TimelineEvent {
  timestamp: string;
  kind: string;
  artifact_id: string;
  type?: EntityType | null;
  value?: string | null;
  label?: string | null;
  confidence?: number | null;
  last_seen?: string | null;
  collector?: string | null;
  source_url?: string | null;
  payload_hash?: string | null;
  action?: string | null;
  block_index?: number | null;
  block_hash?: string | null;
  signed?: boolean | null;
  prompt?: string | null;
  provider?: string | null;
  model?: string | null;
  status?: string | null;
  iterations?: number | null;
  tools_used?: number | null;
}

export interface TimelineReport {
  case_id: string;
  bucket: string;
  total_events?: number;
  first_activity?: string | null;
  last_activity?: string | null;
  span_hours?: number | null;
  buckets?: TimelineBucket[];
  bursts?: TimelineBurst[];
  collectors?: Record<string, number>;
  events?: TimelineEvent[];
}

export interface ToolCallRecord {
  call_id: string;
  tool: string;
  result: string;
}

export interface ToolCallRequest {
  arguments?: Record<string, unknown>;
}

export interface UsageRecord {
  input_tokens?: number;
  output_tokens?: number;
}

export interface ValidationError {
  loc: string | number[];
  msg: string;
  type: string;
  input?: unknown;
  ctx?: Record<string, unknown>;
}
