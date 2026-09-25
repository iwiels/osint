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
}

export interface GraphSubgraph {
  nodes: EntityNode[];
  edges: RelationEdge[];
  total_nodes: number;
  total_edges: number;
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
}
