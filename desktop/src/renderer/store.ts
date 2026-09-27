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
} from "@specter/sdk";

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  tool?: string;
  callId?: string;
  args?: unknown;
  status?: "running" | "completed" | "error";
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

export type MainTab = "chat" | "graph" | "timeline" | "correlations" | "ledger";

/**
 * Umbral de ventana estrecha por panel: por debajo, el panel arranca plegado y
 * se pliega solo al cruzar el umbral (el analista puede reabrirlo con Ctrl+B /
 * Ctrl+J). El chat central nunca se estrangula entre los dos paneles.
 */
export const PANEL_BREAKPOINTS: Record<keyof PanelState, number> = {
  sidebar: 1100,
  evidence: 1280,
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

interface SpecterState {
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
  clearChat: () => void;
  startToolCall: (callId: string, tool: string, args?: unknown) => void;
  completeToolCall: (callId: string, tool: string, result: string) => void;

  // Permisos
  pendingPermission: PermissionRequestPayload | null;
  setPendingPermission: (p: PermissionRequestPayload | null) => void;

  // Preguntas del agente al analista (tool ask_analyst)
  pendingQuestion: QuestionAskedPayload | null;
  setPendingQuestion: (q: QuestionAskedPayload | null) => void;

  // Historial de conversaciones del agente (persistido en el engine)
  agentSessions: AgentSession[];
  setAgentSessions: (s: AgentSession[]) => void;
  /** Transcripción en vista (null = chat en vivo). El chat vivo se conserva. */
  historyView: { session_id: string; messages: ChatMessage[] } | null;
  setHistoryView: (v: { session_id: string; messages: ChatMessage[] } | null) => void;
  /** Contador: el raíl recarga sesiones cuando cambia (tras cada run). */
  sessionsVersion: number;
  bumpSessions: () => void;
}

function newMessageId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function getInitialEngineUrl(): string {
  if (typeof window !== "undefined") {
    const params = new URLSearchParams(window.location.search);
    const engine = params.get("engine");
    if (engine) return engine;
  }
  return "http://127.0.0.1:8787";
}

export const useStore = create<SpecterState>((set) => ({
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
  activeCaseId: null,
  activeTab: "chat",
  setCases: (cases) => set({ cases }),
  setActiveCase: (caseId) =>
    set({
      activeCaseId: caseId,
      graph: null,
      ledger: null,
      timeline: null,
      correlations: null,
      attestation: null,
    }),
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
  clearChat: () =>
    set({
      chat: [],
      plan: null,
      usage: null,
      historyView: null,
      pendingPermission: null,
      pendingQuestion: null,
    }),

  startToolCall: (callId, tool, args) =>
    set((s) => {
      // Si ya existe el callId en running, no duplicamos
      const existing = s.chat.find(
        (m) =>
          (callId && m.callId === callId) ||
          (m.role === "tool" && m.tool === tool && m.status === "running"),
      );
      if (existing) return s;
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
            content: typeof args === "object" && args !== null ? JSON.stringify(args, null, 2) : "",
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

      let idx = -1;
      for (let i = s.chat.length - 1; i >= 0; i--) {
        const m = s.chat[i];
        if (
          (callId && m.callId === callId) ||
          (m.role === "tool" && m.tool === tool && m.status === "running")
        ) {
          idx = i;
          break;
        }
      }

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
            ts: Date.now(),
          },
        ],
      };
    }),

  pendingPermission: null,
  setPendingPermission: (p) => set({ pendingPermission: p }),

  pendingQuestion: null,
  setPendingQuestion: (q) => set({ pendingQuestion: q }),

  agentSessions: [],
  setAgentSessions: (s) => set({ agentSessions: s }),
  historyView: null,
  setHistoryView: (v) => set({ historyView: v }),
  sessionsVersion: 0,
  bumpSessions: () => set((s) => ({ sessionsVersion: s.sessionsVersion + 1 })),
}));
