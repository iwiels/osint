/**
 * Store central de la UI (Zustand).
 * Estado: casos, grafo, custodia, timeline, correlaciones, conversación del
 * agente (con streaming) y permisos pendientes.
 */

import { create } from "zustand";
import type {
  AgentSession,
  AgentSessionMessage,
  AgentUsage,
  CaseCorrelations,
  CaseMetadata,
  EngineHealth,
  GraphSubgraph,
  LedgerAttestation,
  LedgerReport,
  PermissionRequestPayload,
  PlanStep,
  QuestionAskedPayload,
  TimelineReport,
} from "@wraith/sdk";

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  tool?: string;
  callId?: string;
  args?: unknown;
  /**
   * `interrupted`: la llamada estaba en vuelo cuando el analista detuvo el run,
   * así que nunca llegó su `tool.completed`. No está `error` porque la tool
   * puede que no fallara; simplemente no se conoce el resultado.
   */
  status?: "running" | "completed" | "error" | "interrupted";
  ts: number;
  /** true mientras el texto llega token a token (fase C). */
  streaming?: boolean;
}

export interface ProviderSettings {
  provider: string;
  model: string;
  apiKey: string;
  baseUrl: string;
}

/** Paneles plegables: raíl de casos y panel de evidencias (el chat es central). */
export interface PanelState {
  sidebar: boolean;
  evidence: boolean;
}

export type MainTab = "graph" | "timeline" | "correlations" | "ledger";

/**
 * Umbral de ventana estrecha por panel: por debajo, el panel arranca plegado y
 * se pliega solo al cruzar el umbral (el analista puede reabrirlo con Ctrl+B /
 * Ctrl+J). El chat central nunca se estrangula entre los dos paneles.
 */
export const PANEL_BREAKPOINTS: Record<keyof PanelState, number> = {
  sidebar: 960,
  evidence: 768,
};

/** Estado inicial del armazón según el ancho de la ventana donde arrancamos. */
function initialPanels(): PanelState {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return { sidebar: true, evidence: true };
  }
  return {
    sidebar: !window.matchMedia(`(max-width: ${PANEL_BREAKPOINTS.sidebar}px)`).matches,
    evidence: !window.matchMedia(`(max-width: ${PANEL_BREAKPOINTS.evidence}px)`).matches,
  };
}

export interface RunOptions {
  /** Streaming token a token por SSE. */
  stream: boolean;
  /** Turno previo del planificador (publica agent.plan). */
  planFirst: boolean;
  /** Auto-aprobar herramientas sensibles sin pausas de confirmación. */
  autoApprove: boolean;
}

interface WraithState {
  // Armazón (ventana estrecha: plegar paneles libera el expediente)
  panels: PanelState;
  togglePanel: (panel: keyof PanelState) => void;
  setPanels: (panels: Partial<PanelState>) => void;

  // Conexión
  engineUrl: string;
  engineOnline: boolean;
  setEngineUrl: (url: string) => void;
  setEngineOnline: (online: boolean) => void;
  /** Bearer del engine (C1). Null = motor sin token (dev) o aún no cargado. */
  engineToken: string | null;
  setEngineToken: (t: string | null) => void;
  /** Último /health: versión + hash del código en ejecución (anti-staleness). */
  engineHealth: EngineHealth | null;
  setEngineHealth: (h: EngineHealth | null) => void;

  // Casos
  cases: CaseMetadata[];
  activeCaseId: string | null;
  activeTab: MainTab;
  setCases: (cases: CaseMetadata[]) => void;
  setActiveCase: (caseId: string | null) => void;
  setActiveTab: (tab: MainTab) => void;

  // Grafo, custodia, timeline y correlaciones
  graph: GraphSubgraph | null;
  ledger: LedgerReport | null;
  timeline: TimelineReport | null;
  correlations: CaseCorrelations | null;
  attestation: LedgerAttestation | null;
  setGraph: (g: GraphSubgraph | null) => void;
  setLedger: (report: LedgerReport | null) => void;
  setTimeline: (t: TimelineReport | null) => void;
  setCorrelations: (c: CaseCorrelations | null) => void;
  setAttestation: (a: LedgerAttestation | null) => void;

  // Agente
  chat: ChatMessage[];
  agentBusy: boolean;
  plan: PlanStep[] | null;
  usage: AgentUsage | null;
  provider: ProviderSettings;
  runOptions: RunOptions;
  pushMessage: (msg: Omit<ChatMessage, "id" | "ts">) => void;
  setAgentBusy: (busy: boolean) => void;
  setProvider: (p: Partial<ProviderSettings>) => void;
  setRunOptions: (o: Partial<RunOptions>) => void;
  /** Añade un fragmento del stream al mensaje del asistente en curso. */
  appendToken: (delta: string) => void;
  /** Fija el texto definitivo del turno (el evento agent.message es la verdad). */
  finalizeAssistant: (content: string) => void;
  closeStream: () => void;
  setPlan: (steps: PlanStep[] | null) => void;
  setUsage: (usage: AgentUsage | null) => void;
  setChat: (chat: ChatMessage[]) => void;
  clearChat: () => void;
  startToolCall: (callId: string, tool: string, args?: unknown) => void;
  completeToolCall: (callId: string, tool: string, result: string) => void;
  /** Cierra las tool calls en vuelo al detener el run: ya no recibirán su `tool.completed`. */
  interruptRunningTools: () => void;
  // Permisos: cola. El agente ejecuta los tool calls de un turno en paralelo
  // y cada tool sensible emite su propia `permission.request`; con un único
  // hueco la última petición tapaba a la anterior y esa nunca se respondía
  // (timeout de 300s). `pendingPermission` es la cabeza de la cola.
  pendingPermission: PermissionRequestPayload | null;
  permissionQueue: PermissionRequestPayload[];
  enqueuePermission: (p: PermissionRequestPayload) => void;
  /** Retira de la cola la petición con ese request_id (resuelta o caducada). */
  resolvePermission: (requestId: string) => void;
  clearPermissions: () => void;

  // Preguntas del agente al analista (tool ask_analyst)
  pendingQuestion: QuestionAskedPayload | null;
  setPendingQuestion: (q: QuestionAskedPayload | null) => void;

  // Historial de conversaciones del agente (persistido en el engine)
  activeSessionId: string | null;
  setActiveSessionId: (id: string | null) => void;
  startNewSession: () => void;
  agentSessions: AgentSession[];
  setAgentSessions: (s: AgentSession[]) => void;
  /** Transcripción en vista (null = chat en vivo). El chat vivo se conserva. */
  historyView: { session_id: string; messages: ChatMessage[] } | null;
  setHistoryView: (v: { session_id: string; messages: ChatMessage[] } | null) => void;
  /** Contador de versión de datos del caso (grafo, ledger, timeline, correlaciones). */
  caseDataVersion: number;
  bumpCaseData: () => void;
  /** Contador: el raíl recarga sesiones cuando cambia (tras cada run). */
  sessionsVersion: number;
  bumpSessions: () => void;
  /** Modal de ajustes del sistema (Ctrl+, o botón en cabecera/compositor). */
  settingsOpen: boolean;
  setSettingsOpen: (open: boolean) => void;
}

function newMessageId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Localiza la tarjeta de tool a la que pertenece un evento del motor.
 *
 * Con `callId` el emparejamiento es EXACTO y no se admite ningún fallback por
 * nombre: dos llamadas paralelas de la misma tool comparten nombre, así que el
 * fallback cruzaba las tarjetas (el resultado de una acababa en la de otra y la
 * segunda quedaba huérfana, sin parámetros y fuera de orden).
 *
 * Sin `callId` no hay forma de desambiguar, así que se empareja con la más
 * antigua en vuelo: es la que corresponde al primer `tool.completed` que llegue.
 */
function findToolCallIndex(chat: ChatMessage[], callId: string, tool: string): number {
  if (callId) return chat.findIndex((m) => m.role === "tool" && m.callId === callId);
  return chat.findIndex(
    (m) => m.role === "tool" && m.tool === tool && m.status === "running",
  );
}

function getInitialEngineUrl(): string {
  if (typeof window !== "undefined") {
    const params = new URLSearchParams(window.location.search);
    const engine = params.get("engine");
    if (engine) return engine;
  }
  return "http://127.0.0.1:8787";
}

function getInitialCaseId(): string | null {
  if (typeof window !== "undefined") {
    try {
      return localStorage.getItem("wraith:activeCaseId") || null;
    } catch {
      return null;
    }
  }
  return null;
}

export const useStore = create<WraithState>((set, get) => ({
  panels: initialPanels(),
  togglePanel: (panel) =>
    set((s) => ({ panels: { ...s.panels, [panel]: !s.panels[panel] } })),
  setPanels: (panels) => set((s) => ({ panels: { ...s.panels, ...panels } })),

  engineUrl: getInitialEngineUrl(),
  engineOnline: false,
  setEngineUrl: (url) => set({ engineUrl: url }),
  setEngineOnline: (online) => set({ engineOnline: online }),
  engineToken: null,
  setEngineToken: (t) => set({ engineToken: t }),
  engineHealth: null,
  setEngineHealth: (h) => set({ engineHealth: h }),

  cases: [],
  activeCaseId: getInitialCaseId(),
  activeTab: "graph",
  setCases: (cases) => set({ cases }),
  setActiveCase: (caseId) => {
    if (typeof window !== "undefined") {
      try {
        if (caseId) localStorage.setItem("wraith:activeCaseId", caseId);
        else localStorage.removeItem("wraith:activeCaseId");
      } catch {
        // ignore
      }
    }
    const current = get().activeCaseId;
    if (current === caseId && caseId !== null) {
      get().bumpCaseData();
      return;
    }
    set({
      activeCaseId: caseId,
      activeSessionId: null,
      graph: null,
      ledger: null,
      timeline: null,
      correlations: null,
      attestation: null,
      chat: [],
      historyView: null,
      plan: null,
      usage: null,
    });
    get().bumpCaseData();
  },
  setActiveTab: (tab) => set({ activeTab: tab }),

  graph: null,
  ledger: null,
  timeline: null,
  correlations: null,
  attestation: null,
  setGraph: (graph) => set({ graph }),
  setLedger: (ledger) => set({ ledger }),
  setTimeline: (timeline) => set({ timeline }),
  setCorrelations: (correlations) => set({ correlations }),
  setAttestation: (attestation) => set({ attestation }),

  chat: [],
  agentBusy: false,
  plan: null,
  usage: null,
  provider: { provider: "opencode", model: "space-bunny-free", apiKey: "", baseUrl: "" },
  // C4: el gate de permisos es opt-out. La demo lo activa a mano si la quiere.
  runOptions: { stream: true, planFirst: true, autoApprove: false },
  pushMessage: (msg) =>
    set((s) => ({ chat: [...s.chat, { ...msg, id: newMessageId(), ts: Date.now() }] })),
  setAgentBusy: (busy) => set({ agentBusy: busy }),
  setProvider: (p) => set((s) => ({ provider: { ...s.provider, ...p } })),
  setRunOptions: (o) => set((s) => ({ runOptions: { ...s.runOptions, ...o } })),

  appendToken: (delta) =>
    set((s) => {
      const last = s.chat.at(-1);
      if (last && last.role === "assistant" && last.streaming) {
        return { chat: [...s.chat.slice(0, -1), { ...last, content: last.content + delta }] };
      }
      return {
        chat: [
          ...s.chat,
          { id: newMessageId(), role: "assistant", content: delta, ts: Date.now(), streaming: true },
        ],
      };
    }),

  finalizeAssistant: (content) =>
    set((s) => {
      const last = s.chat.at(-1);
      if (last && last.role === "assistant" && last.streaming) {
        return { chat: [...s.chat.slice(0, -1), { ...last, content, streaming: false }] };
      }
      return {
        chat: [...s.chat, { id: newMessageId(), role: "assistant", content, ts: Date.now() }],
      };
    }),

  closeStream: () =>
    set((s) => ({
      chat: s.chat.map((m) => (m.streaming ? { ...m, streaming: false } : m)),
    })),
  setPlan: (plan) => set({ plan }),
  setUsage: (usage) => set({ usage }),
  setChat: (chat) => set({ chat }),
  clearChat: () =>
    set({
      chat: [],
      plan: null,
      usage: null,
      historyView: null,
      permissionQueue: [],
      pendingPermission: null,
      pendingQuestion: null,
    }),

  startToolCall: (callId, tool, args) =>
    set((s) => {
      // Deduplicación sólo por callId. Con el fallback por nombre, un segundo
      // `tool.started` de la misma tool en paralelo se descartaba y su tarjeta
      // nunca se creaba.
      if (callId && s.chat.some((m) => m.role === "tool" && m.callId === callId)) return s;
      return {
        chat: [
          ...s.chat,
          {
            id: callId || newMessageId(),
            callId,
            role: "tool",
            tool,
            status: "running",
            args,
            // `content` arranca VACÍO a propósito. Antes se sembraba con los
            // argumentos, y como la tarjeta se renderiza bajo un encabezado que
            // dice "Resultado", cualquier llamada que no llegara a completarse
            // (run cancelado) quedaba mostrando los parámetros de entrada como
            // si fueran el resultado de la tool.
            content: "",
            ts: Date.now(),
          },
        ],
      };
    }),

  completeToolCall: (callId, tool, result) =>
    set((s) => {
      let status: "completed" | "error" = "completed";
      try {
        const trimmed = result.trim();
        if (trimmed.startsWith("{")) {
          const parsed = JSON.parse(trimmed);
          if (parsed && (parsed.error || (parsed.detail && !parsed.result))) {
            status = "error";
          }
        }
      } catch {
        // no json
      }

      const idx = findToolCallIndex(s.chat, callId, tool);

      if (idx !== -1) {
        const updated = [...s.chat];
        updated[idx] = {
          ...updated[idx],
          status,
          content: result,
        };
        return { chat: updated };
      }
      return {
        chat: [
          ...s.chat,
          {
            id: callId || newMessageId(),
            callId,
            role: "tool",
            tool,
            status,
            content: result,
            // Sin `args`: sólo se llega aquí si la UI perdió el `tool.started`
            // (p. ej. se reconectó al stream a mitad de run). Antes esta tarjeta
            // nacía ya completada y sin parámetros, lo que la hacía
            // indistinguible de una tool sin argumentos de entrada.
            ts: Date.now(),
          },
        ],
      };
    }),

  /**
   * Cierra las llamadas que seguían en vuelo al detener el run: su
   * `tool.completed` ya no va a llegar porque el servidor canceló la iteración.
   * Sin esto quedaban en `running` para siempre, con el grupo de operaciones
   * marcado como vivo y el spinner girando para siempre.
   */
  interruptRunningTools: () =>
    set((s) => {
      if (!s.chat.some((m) => m.role === "tool" && m.status === "running")) return s;
      return {
        chat: s.chat.map((m) =>
          m.role === "tool" && m.status === "running"
            ? { ...m, status: "interrupted" as const }
            : m,
        ),
      };
    }),

  pendingPermission: null,
  permissionQueue: [],
  enqueuePermission: (p) =>
    set((s) => {
      if (s.permissionQueue.some((r) => r.request_id === p.request_id)) return s;
      const queue = [...s.permissionQueue, p];
      return { permissionQueue: queue, pendingPermission: queue[0] };
    }),
  resolvePermission: (requestId) =>
    set((s) => {
      const queue = s.permissionQueue.filter((r) => r.request_id !== requestId);
      return { permissionQueue: queue, pendingPermission: queue[0] ?? null };
    }),
  clearPermissions: () => set({ permissionQueue: [], pendingPermission: null }),

  pendingQuestion: null,
  setPendingQuestion: (q) => set({ pendingQuestion: q }),

  agentSessions: [],
  setAgentSessions: (s) => set({ agentSessions: s }),
  activeSessionId: null,
  setActiveSessionId: (activeSessionId) => set({ activeSessionId }),
  startNewSession: () =>
    set({
      activeSessionId: null,
      chat: [],
      plan: null,
      usage: null,
      historyView: null,
      permissionQueue: [],
      pendingPermission: null,
      pendingQuestion: null,
    }),
  historyView: null,
  setHistoryView: (v) => set({ historyView: v }),
  caseDataVersion: 0,
  bumpCaseData: () => set((s) => ({ caseDataVersion: s.caseDataVersion + 1 })),
  sessionsVersion: 0,
  bumpSessions: () => set((s) => ({ sessionsVersion: s.sessionsVersion + 1 })),
  settingsOpen: false,
  setSettingsOpen: (settingsOpen) => set({ settingsOpen }),
}));
