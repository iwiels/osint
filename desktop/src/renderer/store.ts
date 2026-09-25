/**
 * Store central de la UI (Zustand).
 * Estado: casos, grafo, ledger, conversación del agente, permisos pendientes.
 */

import { create } from "zustand";
import type {
  CaseMetadata,
  GraphSubgraph,
  LedgerBlock,
  PermissionRequestPayload,
} from "@specter/sdk";

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  tool?: string;
  ts: number;
}

export interface ProviderSettings {
  provider: string;
  model: string;
  apiKey: string;
  baseUrl: string;
}

interface SpecterState {
  // Conexión
  engineUrl: string;
  engineOnline: boolean;
  setEngineUrl: (url: string) => void;
  setEngineOnline: (online: boolean) => void;

  // Casos
  cases: CaseMetadata[];
  activeCaseId: string | null;
  setCases: (cases: CaseMetadata[]) => void;
  setActiveCase: (caseId: string | null) => void;

  // Grafo y ledger
  graph: GraphSubgraph | null;
  ledger: LedgerBlock[];
  setGraph: (g: GraphSubgraph | null) => void;
  setLedger: (blocks: LedgerBlock[]) => void;

  // Agente
  chat: ChatMessage[];
  agentBusy: boolean;
  provider: ProviderSettings;
  pushMessage: (msg: Omit<ChatMessage, "id" | "ts">) => void;
  setAgentBusy: (busy: boolean) => void;
  setProvider: (p: Partial<ProviderSettings>) => void;

  // Permisos
  pendingPermission: PermissionRequestPayload | null;
  setPendingPermission: (p: PermissionRequestPayload | null) => void;
}

export const useStore = create<SpecterState>((set) => ({
  engineUrl: "http://127.0.0.1:8787",
  engineOnline: false,
  setEngineUrl: (url) => set({ engineUrl: url }),
  setEngineOnline: (online) => set({ engineOnline: online }),

  cases: [],
  activeCaseId: null,
  setCases: (cases) => set({ cases }),
  setActiveCase: (caseId) => set({ activeCaseId: caseId, graph: null, ledger: [] }),

  graph: null,
  ledger: [],
  setGraph: (graph) => set({ graph }),
  setLedger: (ledger) => set({ ledger }),

  chat: [],
  agentBusy: false,
  provider: { provider: "anthropic", model: "", apiKey: "", baseUrl: "" },
  pushMessage: (msg) =>
    set((s) => ({
      chat: [
        ...s.chat,
        { ...msg, id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, ts: Date.now() },
      ],
    })),
  setAgentBusy: (busy) => set({ agentBusy: busy }),
  setProvider: (p) => set((s) => ({ provider: { ...s.provider, ...p } })),

  pendingPermission: null,
  setPendingPermission: (p) => set({ pendingPermission: p }),
}));
