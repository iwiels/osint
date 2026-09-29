/**
 * Cliente SSE para el event bus del engine (/events).
 * Eventos tipados: agent.*, tool.*, permission.*, case.*
 *
 * Fase C: el agente publica `agent.token` (streaming), `agent.plan` (planificador),
 * `agent.tools_parallel` (lote de tools) y `agent.stream_fallback` (provider sin SSE).
 */

export type WraithEventType =
  | "agent.started"
  | "agent.message"
  | "agent.token"
  | "agent.plan"
  | "agent.tools_parallel"
  | "agent.stream_fallback"
  | "agent.completed"
  | "agent.rate_limited"
  | "tool.started"
  | "tool.completed"
  | "permission.request"
  | "permission.granted"
  | "permission.timeout"
  | "question.asked"
  | "case.created"
  | "tool.called";

export interface WraithEvent<T = unknown> {
  seq: number;
  type: WraithEventType;
  payload: T;
  ts: string;
}

export interface PermissionRequestPayload {
  request_id: string;
  tool: string;
  arguments: Record<string, unknown>;
  session_id?: string;
  case_id?: string | null;
}

/** Payloads ligados a un expediente; `null` representa un run global. */
export interface CaseScopedPayload {
  case_id?: string | null;
}

/** Decide si un evento pertenece al contexto visible, aceptando motores antiguos sin `case_id`. */
export function isPayloadForActiveCase(
  payload: unknown,
  activeCaseId: string | null,
): boolean {
  if (typeof payload !== "object" || payload === null || !("case_id" in payload)) {
    return true;
  }
  const caseId = (payload as CaseScopedPayload).case_id;
  return caseId === activeCaseId;
}

/** Pregunta del agente al analista (tool ask_analyst, estilo opencode question). */
export interface QuestionOption {
  label: string;
  description?: string;
}

export interface AnalystQuestion {
  question: string;
  header?: string;
  options: QuestionOption[];
  multiple?: boolean;
  custom?: boolean;
}

export interface QuestionAskedPayload {
  request_id: string;
  questions: AnalystQuestion[];
  session_id?: string;
  case_id?: string | null;
}

export interface ToolEventPayload {
  call_id?: string;
  tool: string;
  arguments?: Record<string, unknown>;
  result?: string;
  case_id?: string | null;
}

export interface AgentMessagePayload {
  role: string;
  content: string | null;
  case_id?: string | null;
}

export interface RateLimitedPayload {
  attempt: number;
  wait_seconds: number;
  status: number;
  case_id?: string | null;
}

/** Fragmento de texto del modelo mientras se genera (streaming). */
export interface AgentTokenPayload {
  delta: string;
  case_id?: string | null;
}

export interface PlanStep {
  step: number;
  goal: string;
  tools: string[];
}

export interface AgentPlanPayload {
  steps: PlanStep[];
  total_steps?: number;
  source: "planner" | string;
  error?: string;
  case_id?: string | null;
}

export interface ToolsParallelPayload {
  count: number;
  tools: string[];
  case_id?: string | null;
}

export interface AgentUsage {
  input_tokens: number;
  output_tokens: number;
}

export interface AgentStartedPayload {
  provider: string;
  model: string;
  case_id: string | null;
  run_id?: string;
  streaming?: boolean;
  max_iterations?: number;
}

export interface AgentCompletedPayload {
  iterations: number;
  tools_used: number;
  usage?: AgentUsage;
  streaming?: boolean;
  case_id?: string | null;
  run_id?: string;
}

export type EventHandlers = {
  [K in WraithEventType]?: (payload: unknown, event: WraithEvent) => void;
};

export function connectEvents(
  baseUrl: string,
  handlers: EventHandlers,
  token?: string | null,
): () => void {
  // EventSource no manda headers: el token viaja como ?token= (el engine solo
  // lo acepta en /events). El resto de llamadas usan Authorization (ver SDK).
  const sep = baseUrl.includes("?") ? "&" : "?";
  const url = token
    ? `${baseUrl.replace(/\/$/, "")}/events${sep}token=${encodeURIComponent(token)}`
    : `${baseUrl.replace(/\/$/, "")}/events`;
  const source = new EventSource(url);

  const listenerFor = (type: WraithEventType) => (evt: Event) => {
    const raw = evt as MessageEvent;
    const handler = handlers[type];
    if (!handler) return;
    try {
      const parsed = JSON.parse(raw.data) as WraithEvent;
      handler(parsed.payload, parsed);
    } catch {
      // evento malformado: ignorar silenciosamente
    }
  };

  const bound: Array<[WraithEventType, EventListener]> = [];
  const types = Object.keys(handlers) as WraithEventType[];
  for (const type of types) {
    const listener = listenerFor(type);
    source.addEventListener(type, listener);
    bound.push([type, listener]);
  }

  return () => {
    for (const [type, listener] of bound) {
      source.removeEventListener(type, listener);
    }
    source.close();
  };
}
