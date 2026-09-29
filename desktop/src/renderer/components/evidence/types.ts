/**
 * Tipos y constantes compartidos para la suite de componentes de evidencias
 * (Grafo, Timeline, Correlaciones, Custodia Forense).
 */

import type { EntityNode } from "@wraith/sdk";

export type CaseViewTab = "graph" | "timeline" | "correlations" | "ledger";

export interface FGraphNode {
  id: string;
  type: string;
  value: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  degree: number;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  isCluster?: boolean;
  clusterCount?: number;
  clusterParentId?: string;
  clusterChildIds?: string[];
}

export interface FGraphLink {
  source: string | FGraphNode;
  target: string | FGraphNode;
  relation_type: string;
}

/**
 * Arista tal como la entrega el engine (`source/target`) o en forma
 * RelationEdge (`source_id/target_id`): se aceptan ambas.
 */
export interface RawEdge {
  source_id?: string;
  target_id?: string;
  source?: string | { id: string };
  target?: string | { id: string };
  relation_type?: string;
}

export const idOf = (v: string | { id: string } | undefined): string =>
  typeof v === "object" && v !== null ? v.id : (v ?? "");

export interface ForceGraphMethods {
  zoomToFit: (ms?: number, px?: number, nodeFilter?: (node: any) => boolean) => void;
  zoom: (zoomLevel?: number, durationMs?: number) => number | void;
  centerAt: (x?: number, y?: number, ms?: number) => void;
  d3Force: (forceName: string, forceFn?: any) => any;
  d3ReheatSimulation: () => void;
}

export const TYPE_COLORS: Record<string, string> = {
  CLUSTER: "#38bdf8",
  DOMAIN: "#45c8ff",
  SUBDOMAIN: "#6dd5ff",
  IP_ADDRESS: "#b08cff",
  ASN: "#7aa7ff",
  DNS_RECORD: "#67e8f9",
  SSL_CERTIFICATE: "#f0abfc",
  PERSON: "#ff7ab8",
  EMAIL: "#ffb86b",
  SOCIAL_PROFILE: "#4ddbbe",
  FILE_ARTIFACT: "#d3d34d",
  GEO_LOCATION: "#7dff8a",
  ORGANIZATION: "#ff8f5e",
  DOCUMENT_ID: "#ff5252",
  ALIAS: "#9aa4b2",
  PHONE: "#5ed7ff",
};

export const FALLBACK_NODE_COLOR = "#9aa4b2";
export const LINK_COLOR = "rgba(56, 189, 248, 0.55)";
export const BG_COLOR = "transparent";

export const KIND_COLORS: Record<string, string> = {
  entity: "var(--brand)",
  evidence: "var(--success)",
  ledger: "var(--info)",
};

export const STATUS_TONE: Record<string, "success" | "warning" | "critical" | "neutral"> = {
  SEALED: "success",
  PARTIAL: "warning",
  UNSIGNED: "warning",
  INVALID: "critical",
  KEY_UNAVAILABLE: "neutral",
};

export const STATUS_LABEL: Record<string, string> = {
  SEALED: "sellado",
  PARTIAL: "sellado parcial",
  UNSIGNED: "sin firmar",
  INVALID: "firma inválida",
  KEY_UNAVAILABLE: "clave no disponible",
};
