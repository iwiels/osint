/**
 * @specter/sdk - Cliente tipado del motor forense Specter.
 * Uso:
 *   const specter = new SpecterClient({ baseUrl: "http://127.0.0.1:8787" });
 *   await specter.health();
 *   await specter.createCase({ name: "...", description: "..." });
 */

import {
  CaseCreated,
  CaseMetadata,
  EngineHealth,
  GraphMetrics,
  GraphSubgraph,
  LedgerBlock,
  ToolInfo,
} from "./types";

export * from "./types";
export * from "./sse";

export interface SpecterClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  defaultHeaders?: Record<string, string>;
}

export class SpecterError extends Error {
  constructor(
    public status: number,
    public endpoint: string,
    message: string,
  ) {
    super(`[${status}] ${endpoint}: ${message}`);
    this.name = "SpecterError";
  }
}

export class SpecterClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly defaultHeaders: Record<string, string>;

  constructor(options: SpecterClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.defaultHeaders = options.defaultHeaders ?? {};
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...this.defaultHeaders,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => res.statusText);
      throw new SpecterError(res.status, path, detail);
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

  caseGraph(caseId: string, opts: { maxDepth?: number; centerId?: string } = {}): Promise<GraphSubgraph> {
    const params = new URLSearchParams();
    if (opts.maxDepth != null) params.set("max_depth", String(opts.maxDepth));
    if (opts.centerId) params.set("center_id", opts.centerId);
    const qs = params.toString();
    return this.request("GET", `/cases/${encodeURIComponent(caseId)}/graph${qs ? `?${qs}` : ""}`);
  }

  caseLedger(caseId: string): Promise<{ case_id: string; blocks: LedgerBlock[] }> {
    return this.request("GET", `/cases/${encodeURIComponent(caseId)}/ledger`);
  }

  // --- Agente ---------------------------------------------------------

  agentRun(input: {
    case_id?: string;
    message: string;
    provider?: string;
    model?: string;
    api_key?: string;
    base_url?: string;
    max_iterations?: number;
  }): Promise<AgentRunResult> {
    return this.request("POST", "/agent/run", input);
  }

  agentPermissionRespond(requestId: string, decision: "allow" | "allow_session" | "deny"): Promise<{ status: string; decision: string }> {
    return this.request("POST", "/agent/permissions/respond", { request_id: requestId, decision });
  }
}

export interface AgentRunResult {
  status: string;
  provider: string;
  model: string;
  iterations: number;
  tools_used: Array<{ call_id: string; tool: string; result: string }>;
  final_message: string;
}
