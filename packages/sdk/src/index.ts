/**
 * @wraith/sdk - Cliente tipado del motor forense Wraith.
 * Uso:
 *   const wraith = new WraithClient({ baseUrl: "http://127.0.0.1:8787" });
 *   await wraith.health();
 *   await wraith.createCase({ name: "...", description: "..." });
 */

import {
  AgentSession,
  AgentSessionMessage,
  CaseCorrelations,
  CaseCreated,
  CaseMetadata,
  CrossCaseReport,
  EngineHealth,
  GraphSubgraph,
  LedgerAttestation,
  LedgerReport,
  TimelineReport,
  ToolInfo,
} from "./types";

export * from "./types";
export * from "./sse";

export interface WraithClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  defaultHeaders?: Record<string, string>;
}

export class WraithError extends Error {
  constructor(
    public status: number,
    public endpoint: string,
    message: string,
  ) {
    super(`[${status}] ${endpoint}: ${message}`);
    this.name = "WraithError";
  }
}

export class WraithClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly defaultHeaders: Record<string, string>;

  constructor(options: WraithClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    // `bind(globalThis)`: invocado como método de la clase, `fetch` pierde su
    // receptor (`window`) y Chromium lanza "Illegal invocation".
    this.fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
    this.defaultHeaders = options.defaultHeaders ?? {};
  }

  private async request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
    const headers: Record<string, string> = { ...this.defaultHeaders };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => res.statusText);
      throw new WraithError(res.status, path, detail);
      }
    return (await res.json()) as T;
  }

  // --- Engine ---------------------------------------------------------

  health(): Promise<EngineHealth> {
    return this.request("GET", "/health");
  }

  listTools(): Promise<{ tools: ToolInfo[] }> {
    return this.request("GET", "/tools");
  }

  callTool(tool: string, args: Record<string, unknown> = {}): Promise<{ tool: string; result: unknown }> {
    return this.request("POST", `/tools/${tool}/call`, { arguments: args });
  }

  // --- Casos ----------------------------------------------------------

  createCase(input: { name: string; description: string; investigator?: string }): Promise<CaseCreated> {
    return this.request("POST", "/cases", input);
  }

  listCases(): Promise<CaseMetadata[]> {
    return this.request("GET", "/cases");
  }

  getCase(caseId: string): Promise<CaseMetadata> {
    return this.request("GET", `/cases/${encodeURIComponent(caseId)}`);
  }

  caseGraph(caseId: string, opts: { maxDepth?: number; centerId?: string; searchTerm?: string; entityType?: string } = {}): Promise<GraphSubgraph> {
    const params = new URLSearchParams();
    if (opts.maxDepth != null) params.set("max_depth", String(opts.maxDepth));
    if (opts.centerId) params.set("center_id", opts.centerId);
    if (opts.searchTerm) params.set("search_term", opts.searchTerm);
    if (opts.entityType) params.set("entity_type", opts.entityType);
    const qs = params.toString();
    return this.request("GET", `/cases/${encodeURIComponent(caseId)}/graph${qs ? `?${qs}` : ""}`);
  }

  /** Cadena de custodia + estado de sellado (SEALED / UNSIGNED / KEY_UNAVAILABLE). */
  caseLedger(caseId: string): Promise<LedgerReport> {
    return this.request("GET", `/cases/${encodeURIComponent(caseId)}/ledger`);
  }

  /** Atestación firmada del estado del caso (verificable por terceros). */
  caseAttestation(caseId: string): Promise<LedgerAttestation> {
    return this.request("GET", `/cases/${encodeURIComponent(caseId)}/attestation`);
  }

  caseTimeline(caseId: string, bucket: "day" | "hour" = "day"): Promise<TimelineReport> {
    return this.request(
      "GET",
      `/cases/${encodeURIComponent(caseId)}/timeline?bucket=${bucket}`,
    );
  }

  /** Vínculos del caso con el resto del repositorio + candidatos de identidad. */
  caseCorrelations(caseId: string): Promise<CaseCorrelations> {
    return this.request("GET", `/cases/${encodeURIComponent(caseId)}/correlations`);
  }

  /** Barrido global: artefactos presentes en dos o más casos. */
  crossCaseIntelligence(): Promise<CrossCaseReport> {
    return this.request("GET", "/intelligence/cross-case");
  }

  // --- Agente ---------------------------------------------------------

  agentRun(input: {
    case_id?: string;
    session_id?: string;
    message: string;
    provider?: string;
    model?: string;
    api_key?: string;
    base_url?: string;
    max_iterations?: number;
    /** Streaming token a token vía SSE (por defecto true en el engine). */
    stream?: boolean;
    /** Turno previo del planificador que publica agent.plan (por defecto true). */
    plan_first?: boolean;
    /** Auto-aprobar herramientas sensibles sin pausas de diálogo (por defecto false). */
    auto_approve?: boolean;
  }, opts?: { signal?: AbortSignal }): Promise<AgentRunResult> {
    return this.request("POST", "/agent/run", input, opts?.signal);
  }

  agentPermissionRespond(requestId: string, decision: "allow" | "allow_session" | "deny"): Promise<{ status: string; decision: string }> {
    return this.request("POST", "/agent/permissions/respond", { request_id: requestId, decision });
  }

  agentQuestionRespond(requestId: string, answers: string[][]): Promise<{ status: string; answers: string[][] }> {
    return this.request("POST", "/agent/questions/respond", { request_id: requestId, answers });
  }

  /** Historial de conversaciones del agente, más recientes primero. */
  agentSessions(caseId?: string, limit = 50): Promise<{ sessions: AgentSession[] }> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (caseId) params.set("case_id", caseId);
    return this.request("GET", `/agent/sessions?${params.toString()}`);
  }

  /** Transcripción completa de una sesión del agente. */
  agentSession(sessionId: string): Promise<{ session: AgentSession; messages: AgentSessionMessage[] }> {
    return this.request("GET", `/agent/sessions/${encodeURIComponent(sessionId)}`);
  }

  /** Borra un caso con sus entidades, ledger y sesiones. */
  deleteCase(caseId: string): Promise<{ status: string; case_id: string }> {
    return this.request("DELETE", `/cases/${encodeURIComponent(caseId)}`);
  }

  /** Borra una sesión del historial y su transcripción. */
  deleteAgentSession(sessionId: string): Promise<{ status: string; session_id: string }> {
    return this.request("DELETE", `/agent/sessions/${encodeURIComponent(sessionId)}`);
  }

  /** Detiene runs en vuelo (botón Detener). Cooperativo: el loop lo observa. */
  cancelRuns(sessionId?: string): Promise<{ status: string; cancelled: number }> {
    return this.request("POST", "/agent/runs/cancel", { session_id: sessionId ?? null });
  }

  // --- Bóveda de API keys (Fase B: las fuentes con key solo viven si están aquí) ---

  /** Estado de la bóveda: nombres admitidos, enmascarado total, sin valores. */
  listSecrets(): Promise<{ secrets: SecretEntry[]; path: string }> {
    return this.request("GET", "/settings/secrets");
  }

  /** Guarda (o reemplaza) una key en la bóveda local del engine. */
  setSecret(name: string, value: string): Promise<{ status: string; secrets: SecretEntry[] }> {
    return this.request("PUT", `/settings/secrets/${encodeURIComponent(name)}`, { value });
  }

  /** Borra una key de la bóveda. */
  deleteSecret(name: string): Promise<{ status: string; removed: boolean; secrets: SecretEntry[] }> {
    return this.request("DELETE", `/settings/secrets/${encodeURIComponent(name)}`);
  }
}

export interface SecretEntry {
  name: string;
  env_var: string;
  configured: boolean;
  masked: string | null;
}

export interface AgentRunResult {
  status: string;
  provider: string;
  model: string;
  session_id: string;
  iterations: number;
  tools_used: Array<{ call_id: string; tool: string; result: string }>;
  final_message: string;
  /** Consumo acumulado del provider (0 si el gateway no lo reporta). */
  usage?: { input_tokens: number; output_tokens: number };
}
