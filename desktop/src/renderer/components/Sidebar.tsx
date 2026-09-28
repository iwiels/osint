/**
 * Sidebar - gestión de casos (legajo del analista).
 *
 * Implementación de referencia de la migración: usa las primitivas de `ui/`
 * (Button, TextField, TextArea) y los tokens semánticos del sistema
 * (styles/colors.css). El layout y los estados de fila viven en su CSS hermano
 * (sidebar.css) y se seleccionan por `data-component`/`data-slot`, sin
 * concatenar clases utilitarias condicionales en el JSX.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { SpecterClient } from "@specter/sdk";
import type { AgentSession, AgentSessionMessage } from "@specter/sdk";
import { Button, IconButton, TextArea, TextField } from "../ui";
import { useStore } from "../store";
import type { ChatMessage } from "../store";
import { SessionHistory } from "./chat";
import "./sidebar.css";

function caseCreatedLabel(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleDateString(undefined, { day: "2-digit", month: "short" });
}

export default function Sidebar({ client }: { client: SpecterClient }) {
  const cases = useStore((s) => s.cases);
  const activeCaseId = useStore((s) => s.activeCaseId);
  const setActiveCase = useStore((s) => s.setActiveCase);
  const engineOnline = useStore((s) => s.engineOnline);
  const agentSessions = useStore((s) => s.agentSessions);
  const setAgentSessions = useStore((s) => s.setAgentSessions);
  const activeSessionId = useStore((s) => s.activeSessionId);
  const historyView = useStore((s) => s.historyView);
  const setHistoryView = useStore((s) => s.setHistoryView);
  const sessionsVersion = useStore((s) => s.sessionsVersion);
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [showHistory, setShowHistory] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [sidebarError, setSidebarError] = useState<string | null>(null);

  const filteredCases = useMemo(() => {
    if (!search.trim()) return cases;
    const q = search.toLowerCase();
    return cases.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.case_id.toLowerCase().includes(q) ||
        (c.description && c.description.toLowerCase().includes(q)),
    );
  }, [cases, search]);

  const createCase = async () => {
    if (!name.trim()) return;
    const created = await client.createCase({
      name: name.trim(),
      description: description.trim() || "Sin descripción",
    });
    useStore.getState().setCases([
      {
        case_id: created.case_id,
        name: created.name,
        description,
        investigator: created.investigator,
        created_at: new Date().toISOString(),
        status: "active",
      },
      ...cases,
    ]);
    setActiveCase(created.case_id);
    setCreating(false);
    setName("");
    setDescription("");
  };

  const deleteCase = async (caseId: string) => {
    // Confirmación en dos pasos (sin diálogos bloqueantes): el primero arma
    // (la papelera se vuelve roja), el segundo borra de verdad.
    if (confirmDeleteId !== caseId) {
      setConfirmDeleteId(caseId);
      setSidebarError(null);
      setTimeout(() => {
        setConfirmDeleteId((armed) => (armed === caseId ? null : armed));
      }, 4000);
      return;
    }
    setConfirmDeleteId(null);
    let target: { case_id: string; name: string } | undefined;
    try {
      target = cases.find((c) => c.case_id === caseId);
      await client.deleteCase(caseId);
    } catch (err) {
      setSidebarError(
        `No se pudo borrar ${target?.name ?? caseId}: ${err instanceof Error ? err.message : String(err)}`,
      );
      return;
    }
    const store = useStore.getState();
    const remaining = cases.filter((c) => c.case_id !== caseId);
    store.setCases(remaining);
    if (activeCaseId === caseId) {
      const next = remaining[0]?.case_id ?? null;
      setActiveCase(next);
      store.setGraph(null);
      store.setLedger(null);
      store.setTimeline(null);
      store.setCorrelations(null);
      store.setAttestation(null);
      store.setHistoryView(null);
    }
    store.bumpSessions();
  };

  const hasRestoredCaseChatRef = useRef<string | null>(null);

  // Conversaciones del agente: viven en el raíl (el centro queda solo para chatear).
  const refreshSessions = useCallback(async () => {
    if (!engineOnline) return;
    try {
      const res = await client.agentSessions(activeCaseId ?? undefined, 30);
      setAgentSessions(res.sessions);
      // Si el chat está vacío y no hay vista histórica abierta, restauramos la sesión más reciente del caso una sola vez
      const store = useStore.getState();
      if (
        activeCaseId &&
        res.sessions.length > 0 &&
        store.chat.length === 0 &&
        store.historyView === null &&
        hasRestoredCaseChatRef.current !== activeCaseId
      ) {
        hasRestoredCaseChatRef.current = activeCaseId;
        const latest = res.sessions[0];
        const detail = await client.agentSession(latest.session_id);
        const messages: ChatMessage[] = detail.messages.map((m: AgentSessionMessage) => ({
          id: `${m.session_id}-${m.seq}`,
          role:
            m.role === "tool"
              ? "tool"
              : m.role === "assistant"
                ? "assistant"
                : m.role === "system"
                  ? "system"
                  : "user",
          tool: m.tool ?? undefined,
          content: m.content,
          status: m.role === "tool" ? "completed" : undefined,
          ts: Date.parse(m.ts) || Date.now(),
        }));
        store.setActiveSessionId(latest.session_id);
        store.setChat(messages);
      }
    } catch {
      // engine sin historial o versión previa
    }
  }, [client, activeCaseId, engineOnline, setAgentSessions]);

  const prevCaseIdRef = useRef(activeCaseId);
  useEffect(() => {
    if (prevCaseIdRef.current !== activeCaseId) {
      prevCaseIdRef.current = activeCaseId;
      hasRestoredCaseChatRef.current = null;
      setHistoryView(null);
    }
    void refreshSessions();
  }, [activeCaseId, sessionsVersion, refreshSessions, setHistoryView]);

  const openSession = async (session: AgentSession) => {
    try {
      const detail = await client.agentSession(session.session_id);
      const store = useStore.getState();
      const targetCaseId = detail.session.case_id || session.case_id || store.cases[0]?.case_id;
      if (targetCaseId && targetCaseId !== store.activeCaseId) {
        store.setActiveCase(targetCaseId);
      }
      const messages: ChatMessage[] = detail.messages.map((m: AgentSessionMessage) => ({
        id: `${m.session_id}-${m.seq}`,
        role:
          m.role === "tool"
            ? "tool"
            : m.role === "assistant"
              ? "assistant"
              : m.role === "system"
                ? "system"
                : "user",
        tool: m.tool ?? undefined,
        content: m.content,
        status: m.role === "tool" ? "completed" : undefined,
        ts: Date.parse(m.ts) || Date.now(),
      }));
      store.setActiveSessionId(session.session_id);
      store.setChat(messages);
      setHistoryView(null);
      setShowHistory(false);
    } catch {
      // sesión ilegible
    }
  };

  const deleteSession = async (sessionId: string) => {
    try {
      await client.deleteAgentSession(sessionId);
      const store = useStore.getState();
      if (store.activeSessionId === sessionId) {
        store.startNewSession();
      }
      if (store.historyView?.session_id === sessionId) store.setHistoryView(null);
      await refreshSessions();
    } catch {
      // fallo de borrado reflejado en refresh
    }
  };

  return (
    <aside data-component="sidebar" aria-label="Casos y expedientes">
      <div data-slot="sidebar-header">
        <span className="label-caps">casos · expedientes</span>
        <Button
          size="small"
          variant={creating ? "ghost" : "secondary"}
          icon={creating ? "close" : "plus"}
          onClick={() => setCreating(!creating)}
        >
          {creating ? "Cerrar" : "Nuevo"}
        </Button>
      </div>

      <div className="px-2 pt-2 pb-1">
        <TextField
          size="small"
          placeholder="Buscar expediente…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {sidebarError && (
        <p role="alert" data-slot="sidebar-error">
          {sidebarError}
        </p>
      )}

      {creating && (
        <div className="anim-rise mx-3 mt-3 flex flex-col gap-2 rounded-lg border border-border-weak-base bg-surface-raised-strong p-3">
          <TextField
            autoFocus
            placeholder="Nombre del caso"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <TextArea
            placeholder="Descripción de la investigación"
            rows={3}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          <Button variant="primary" size="small" onClick={createCase} disabled={!name.trim()}>
            Crear caso
          </Button>
        </div>
      )}

      <ul data-slot="sidebar-list">
        {filteredCases.map((c, i) => {
          const active = c.case_id === activeCaseId;
          const armed = confirmDeleteId === c.case_id;
          return (
            <li key={c.case_id} data-slot="case-row-wrap">
              <button
                data-component="case-row"
                data-state={active ? "active" : undefined}
                aria-current={active ? "true" : undefined}
                onClick={() => setActiveCase(c.case_id)}
                title={`${c.name} (${c.case_id})`}
              >
                <span data-slot="case-index">{String(i + 1).padStart(2, "0")}</span>
                <span className="min-w-0 flex-1">
                  <span data-slot="case-name">{c.name}</span>
                  <span data-slot="case-meta">
                    <span data-slot="case-id">#{c.case_id.slice(0, 8)}</span>
                    <span data-slot="case-date">{caseCreatedLabel(c.created_at)}</span>
                  </span>
                </span>
              </button>
              <IconButton
                name="trash"
                size="small"
                label={armed ? `Confirmar borrado de ${c.name}` : `Borrar expediente ${c.name}`}
                aria-pressed={armed}
                onClick={() => void deleteCase(c.case_id)}
                title={armed ? "Pulsa de nuevo para confirmar el borrado" : "Borrar expediente"}
                data-state={armed ? "armed" : undefined}
              />
            </li>
          );
        })}
        {cases.length === 0 && !creating && (
          <li data-slot="sidebar-empty">
            <span className="block font-mono text-[10px] uppercase tracking-wider text-text-weaker mb-1">
              ARCHIVO SIN REGISTROS
            </span>
            <span className="block text-[12px] text-text-weak leading-relaxed">
              Pulsa <strong>+ Nuevo</strong> para iniciar un expediente forense.
            </span>
          </li>
        )}
      </ul>

      <div data-slot="sidebar-sessions">
        <SessionHistory
          sessions={agentSessions}
          currentSessionId={historyView?.session_id ?? activeSessionId}
          onSelectSession={openSession}
          onDeleteSession={deleteSession}
          isOpen={showHistory}
          onToggle={() => setShowHistory(!showHistory)}
        />
      </div>
    </aside>
  );
}
