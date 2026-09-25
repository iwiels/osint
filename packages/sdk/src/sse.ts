/**
 * Cliente SSE para el event bus del engine (/events).
 * Eventos tipados: agent.*, tool.*, permission.*, case.*
 */

export type SpecterEventType =
  | "agent.started"
  | "agent.message"
  | "agent.completed"
  | "tool.started"
  | "tool.completed"
  | "permission.request"
  | "permission.granted"
  | "case.created"
  | "tool.called";

export interface SpecterEvent<T = unknown> {
  seq: number;
  type: SpecterEventType;
  payload: T;
  ts: string;
}

export interface PermissionRequestPayload {
  request_id: string;
  tool: string;
  arguments: Record<string, unknown>;
  session_id?: string;
}

export interface ToolEventPayload {
  call_id?: string;
  tool: string;
  arguments?: Record<string, unknown>;
  result?: string;
}

export interface AgentMessagePayload {
  role: string;
  content: string | null;
}

export type EventHandlers = {
  [K in SpecterEventType]?: (payload: unknown, event: SpecterEvent) => void;
};

export function connectEvents(baseUrl: string, handlers: EventHandlers): () => void {
  const source = new EventSource(`${baseUrl.replace(/\/$/, "")}/events`);

  const listenerFor = (type: SpecterEventType) => (evt: Event) => {
    const raw = evt as MessageEvent;
    const handler = handlers[type];
    if (!handler) return;
    try {
      const parsed = JSON.parse(raw.data) as SpecterEvent;
      handler(parsed.payload, parsed);
    } catch {
      // evento malformado: ignorar silenciosamente
    }
  };

  const bound: Array<[SpecterEventType, EventListener]> = [];
  const types = Object.keys(handlers) as SpecterEventType[];
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
