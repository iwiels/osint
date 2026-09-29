/**
 * App - consola forense Wraith.
 * Layout: sidebar de casos | consola del agente (fija) | panel de evidencias (grafo, timeline, correlaciones, custodia).
 * Al montar: health-check del engine y suscripción al event bus (SSE).
 */

import { useCallback, useEffect, useMemo, useRef } from "react";
import { WraithClient, connectEvents } from "@wraith/sdk";
import { PANEL_BREAKPOINTS, useStore, type PanelState } from "./store";
import { IconButton, Tag, cn } from "./ui";
import Sidebar from "./components/Sidebar";
import CaseView from "./components/CaseView";
import AgentConsole from "./components/AgentConsole";
import ErrorBoundary from "./components/ErrorBoundary";
import { ModelSelector } from "./components/chat";

/** Puente mínimo con main (preload). Todo opcional: también corre en navegador. */
interface WraithDesktopBridge {
  checkHealth?: () => Promise<unknown>;
  getEngineToken?: () => Promise<string | null>;
  revealInFolder?: (fsPath: string) => Promise<boolean>;
  openExternal?: (url: string) => Promise<boolean>;
}

function desktopBridge(): WraithDesktopBridge | undefined {
  if (typeof window === "undefined") return undefined;
  return (window as unknown as { wraithDesktop?: WraithDesktopBridge }).wraithDesktop;
}

export default function App() {
  const engineUrl = useStore((s) => s.engineUrl);
  const engineToken = useStore((s) => s.engineToken);
  const engineOnline = useStore((s) => s.engineOnline);
  const setEngineOnline = useStore((s) => s.setEngineOnline);
  const setCases = useStore((s) => s.setCases);
  const cases = useStore((s) => s.cases);
  const activeCaseId = useStore((s) => s.activeCaseId);
  const setActiveTab = useStore((s) => s.setActiveTab);
  const panels = useStore((s) => s.panels);
  const settingsOpen = useStore((s) => s.settingsOpen);
  const setSettingsOpen = useStore((s) => s.setSettingsOpen);
  const sidebarToggleRef = useRef<HTMLButtonElement>(null);
  const evidenceToggleRef = useRef<HTMLButtonElement>(null);

  // Plegar un panel que contiene el foco lo deja huérfano (el navegador lo
  // manda al body): lo devolvemos al botón que lo gobierna.
  const applyPanel = useCallback((panel: keyof PanelState, open: boolean) => {
    const store = useStore.getState();
    if (!open && store.panels[panel]) {
      const host = document.getElementById(`panel-${panel}`);
      const toggle = panel === "sidebar" ? sidebarToggleRef.current : evidenceToggleRef.current;
      if (host?.contains(document.activeElement) && toggle) toggle.focus();
    }
    if (panel === "sidebar") store.setPanels({ sidebar: open });
    else store.setPanels({ evidence: open });
  }, []);

  const togglePanelSafely = useCallback(
    (panel: keyof PanelState) => applyPanel(panel, !useStore.getState().panels[panel]),
    [applyPanel],
  );

  const client = useMemo(
    () =>
      new WraithClient({
        baseUrl: engineUrl,
        defaultHeaders: engineToken ? { Authorization: `Bearer ${engineToken}` } : {},
      }),
    [engineUrl, engineToken],
  );
  const activeCase = useMemo(
    () => cases.find((c) => c.case_id === activeCaseId),
    [cases, activeCaseId],
  );

  // C1: el Bearer del engine llega por IPC (nunca en la URL).
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const t = await desktopBridge()?.getEngineToken?.();
        if (!cancelled && typeof t === "string" && t) useStore.getState().setEngineToken(t);
      } catch {
        // sin puente (navegador): el engine puede ir sin token en dev
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let dispose: (() => void) | undefined;
    let cancelled = false;
    let pollInterval: ReturnType<typeof setInterval> | null = null;

    const syncEngine = async () => {
      let isHealthy = false;
      try {
        const health = await client.health();
        isHealthy = true;
        if (!cancelled) useStore.getState().setEngineHealth(health);
      } catch (err) {
        console.warn("[wraith] client.health() fetch fallo:", err);
        // Fallback a IPC desde proceso principal Node si el navegador tuviera restricciones
        const res = await desktopBridge()?.checkHealth?.();
        if (res) isHealthy = true;
      }

      if (cancelled) return;

      if (isHealthy) {
        const wasOnline = useStore.getState().engineOnline;
        setEngineOnline(true);
        if (!wasOnline) {
          useStore.getState().bumpCaseData();
        }

        try {
          const fetchedCases = await client.listCases();
          if (!cancelled && Array.isArray(fetchedCases)) {
            setCases(fetchedCases);
            const currentActive = useStore.getState().activeCaseId;
            if (!currentActive || !fetchedCases.some((c) => c.case_id === currentActive)) {
              const stored =
                typeof window !== "undefined"
                  ? localStorage.getItem("wraith:activeCaseId")
                  : null;
              if (stored && fetchedCases.some((c) => c.case_id === stored)) {
                useStore.getState().setActiveCase(stored);
              } else if (fetchedCases.length > 0) {
                useStore.getState().setActiveCase(fetchedCases[0].case_id);
              }
            }
          }
        } catch (casesErr) {
          console.warn("[wraith] error cargando expedientes:", casesErr);
        }

        if (!dispose && !cancelled) {
          try {
            dispose = connectEvents(
              engineUrl,
              {
                "permission.request": (payload) =>
                  useStore.getState().enqueuePermission(payload as never),
                "permission.granted": (payload) => {
                  const p = payload as { request_id?: string };
                  if (p?.request_id) useStore.getState().resolvePermission(p.request_id);
                  else useStore.getState().clearPermissions();
                },
                // El motor rindió la petición (300s sin respuesta): retira el
                // diálogo obsoleto para que el analista no responda a un id ya
                // caducado y reciba un 404.
                "permission.timeout": (payload) => {
                  const p = payload as { request_id?: string };
                  if (p?.request_id) useStore.getState().resolvePermission(p.request_id);
                },
                "question.asked": (payload) =>
                  useStore.getState().setPendingQuestion(payload as never),
                "tool.started": (payload) => {
                  const p = payload as { call_id?: string; tool: string; arguments?: unknown };
                  useStore.getState().startToolCall(p.call_id ?? "", p.tool, p.arguments);
                },
                "tool.completed": (payload) => {
                  const p = payload as { call_id?: string; tool: string; result?: string };
                  useStore.getState().completeToolCall(p.call_id ?? "", p.tool, p.result ?? "");
                  useStore.getState().bumpCaseData();
                },
                // Streaming: el turno se va pintando token a token.
                "agent.token": (payload) => {
                  const p = payload as { delta?: string };
                  if (p.delta) useStore.getState().appendToken(p.delta);
                },
                // El mensaje completo cierra el stream y sustituye el texto parcial.
                "agent.message": (payload) => {
                  const p = payload as { role: string; content: string | null };
                  if (p.content) useStore.getState().finalizeAssistant(p.content);
                  else useStore.getState().closeStream();
                },
                "agent.plan": (payload) => {
                  const p = payload as { steps?: unknown[]; error?: string };
                  const steps = (p.steps ?? []) as never;
                  useStore.getState().setPlan(Array.isArray(p.steps) && p.steps.length ? steps : null);
                  if (p.error) {
                    useStore.getState().pushMessage({
                      role: "system",
                      content: `Sin plan inicial (el agente continúa): ${p.error}`,
                    });
                  }
                },
                "agent.tools_parallel": () => {
                  // Las herramientas en paralelo se agrupan limpiamente en la consola sin ensuciar el chat
                },
                "agent.stream_fallback": (payload) => {
                  const p = payload as { status?: number };
                  useStore.getState().pushMessage({
                    role: "system",
                    content: `El provider rechazó el streaming (${p.status ?? "?"}); se continúa en modo clásico.`,
                  });
                },
                "agent.completed": (payload) => {
                  const p = payload as { usage?: { input_tokens: number; output_tokens: number } };
                  useStore.getState().closeStream();
                  useStore.getState().setUsage(p.usage ?? null);
                  useStore.getState().clearPermissions();
                  useStore.getState().setPendingQuestion(null);
                  useStore.getState().bumpCaseData();
                  useStore.getState().bumpSessions();
                },
                "agent.rate_limited": (payload) => {
                  const p = payload as { wait_seconds?: number; attempt?: number };
                  useStore.getState().pushMessage({
                    role: "system",
                    content: `Límite del gateway alcanzado: esperando ${p.wait_seconds ?? 0}s antes del reintento ${p.attempt ?? 1}…`,
                  });
                },
              },
              engineToken ?? undefined,
            );
          } catch (sseErr) {
            console.warn("[wraith] fallo al conectar SSE:", sseErr);
          }
        }
      } else {
        if (!cancelled) {
          setEngineOnline(false);
          useStore.getState().setEngineHealth(null);
          if (dispose) {
            dispose();
            dispose = undefined;
          }
        }
      }
    };

    syncEngine();
    pollInterval = setInterval(syncEngine, 3500);

    return () => {
      cancelled = true;
      if (pollInterval) clearInterval(pollInterval);
      dispose?.();
    };
  }, [client, engineUrl, engineToken, setEngineOnline, setCases]);

  // Atajos de panel (Ctrl+B / Ctrl+J) y cambio de vistas de evidencia (Ctrl+1..4)
  useEffect(() => {
    const isTypingTarget = (target: EventTarget | null) => {
      const el = target as HTMLElement | null;
      if (!el || !el.tagName) return false;
      const tag = el.tagName.toLowerCase();
      return tag === "input" || tag === "textarea" || tag === "select" || el.isContentEditable;
    };

    const onKeyDown = (e: KeyboardEvent) => {
      if (!e.ctrlKey || e.altKey || e.metaKey || e.shiftKey) return;
      if (isTypingTarget(e.target)) return;
      const key = e.key.toLowerCase();
      if (key === "b") {
        e.preventDefault();
        togglePanelSafely("sidebar");
      } else if (key === "j" || key === "\\") {
        e.preventDefault();
        togglePanelSafely("evidence");
      } else if (key === ",") {
        e.preventDefault();
        setSettingsOpen(true);
      } else if (key === "1") {
        e.preventDefault();
        setActiveTab("graph");
        applyPanel("evidence", true);
      } else if (key === "2") {
        e.preventDefault();
        setActiveTab("timeline");
        applyPanel("evidence", true);
      } else if (key === "3") {
        e.preventDefault();
        setActiveTab("correlations");
        applyPanel("evidence", true);
      } else if (key === "4") {
        e.preventDefault();
        setActiveTab("ledger");
        applyPanel("evidence", true);
      }
    };
    window.addEventListener("keydown", onKeyDown);

    const panelKeys = Object.keys(PANEL_BREAKPOINTS) as Array<keyof typeof PANEL_BREAKPOINTS>;
    const unlisten = panelKeys.map((panel) => {
      const query = window.matchMedia(`(max-width: ${PANEL_BREAKPOINTS[panel]}px)`);
      const onChange = (event: MediaQueryListEvent) => {
        if (event.matches) applyPanel(panel, false);
      };
      query.addEventListener("change", onChange);
      return () => query.removeEventListener("change", onChange);
    });

    return () => {
      window.removeEventListener("keydown", onKeyDown);
      unlisten.forEach((off) => off());
    };
  }, [applyPanel, togglePanelSafely, setActiveTab]);

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-background-base bg-blueprint-grid">
      <a className="skip-link" href="#main-content">
        Saltar al chat
      </a>
      <header className="relative flex h-[46px] shrink-0 items-center justify-between gap-2 border-b border-border-weak-base bg-transparent px-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="size-2 rounded-xs bg-brand" />
            <span className="font-display text-[13px] font-semibold tracking-tight text-text-strong">
              Wraith<span className="text-text-brand">OSINT</span>
            </span>
            <Tag>v0.2.0</Tag>
          </div>

          {activeCase ? (
            <div className="hidden items-center gap-2 border-l border-border-weak-base pl-3 sm:flex">
              <span
                className="max-w-[280px] truncate text-[12.5px] font-medium text-text-strong font-mono"
                title={`${activeCase.name} (${activeCase.case_id})`}
              >
                {activeCase.name}
              </span>
              <span className="font-mono text-[10.5px] text-text-weaker">
                #{activeCase.case_id.slice(0, 8)}
              </span>
            </div>
          ) : null}
        </div>

        <div className="flex min-w-0 items-center gap-0.5">
          {/* Panel toggles: Sidebar & Evidence Panel */}
          <IconButton
            ref={sidebarToggleRef}
            name="list"
            size="small"
            label="Panel de casos (Ctrl+B)"
            aria-pressed={panels.sidebar}
            aria-expanded={panels.sidebar}
            aria-controls="panel-sidebar"
            onClick={() => togglePanelSafely("sidebar")}
          />
          <IconButton
            ref={evidenceToggleRef}
            name="graph"
            size="small"
            label="Panel de evidencias (Ctrl+J o Ctrl+\\)"
            aria-pressed={panels.evidence}
            aria-expanded={panels.evidence}
            aria-controls="panel-evidence"
            onClick={() => togglePanelSafely("evidence")}
          />
          <span className="mx-0.5 h-3.5 w-px bg-border-weak-base" aria-hidden="true" />
          <IconButton
            name="settings-gear"
            size="small"
            label="Ajustes del sistema (Ctrl+,)"
            title="Ajustes del sistema (Ctrl+,)"
            onClick={() => setSettingsOpen(true)}
          />
        </div>
      </header>

      {!engineOnline && (
        <div
          role="status"
          className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border-critical-base bg-surface-critical-weak px-4 py-2 text-[12.5px] text-text-critical"
        >
          <span className="anim-blink">·</span>
          Engine desconectado. Arranca{" "}
          <code className="rounded-xs border border-border-weak-base bg-background-base px-1.5 py-0.5 font-mono text-[11px] text-text-strong">
            python -m engine.http_server
          </code>{" "}
          o reinicia la app.
        </div>
      )}

      {/* Modular Workspace Area (Sidebar + Permanent Chat + Evidence Panel) */}
      <div className="flex min-h-0 flex-1 overflow-hidden">
        <div
          id="panel-sidebar"
          className="flex min-h-0"
          style={{ display: panels.sidebar ? undefined : "none" }}
        >
          <Sidebar client={client} />
        </div>

        {/* Modular Central Area: Consola de investigación fija y panel de evidencias */}
        <div className="flex min-h-0 flex-1 overflow-hidden">
          {/* Consola de Chat: siempre montada y fija */}
          <main
            id="main-content"
            tabIndex={-1}
            role="tabpanel"
            aria-label="Consola de investigación"
            className={cn(
              "flex min-h-0 flex-col overflow-hidden",
              panels.evidence ? "flex-1 border-r border-border-weak-base min-w-[360px]" : "flex-1",
            )}
          >
            <ErrorBoundary label="Consola del agente" fill>
              <AgentConsole client={client} />
            </ErrorBoundary>
          </main>

          {/* Vistas de Evidencia (Grafo, Timeline, Correlaciones, Custodia): siempre montadas para no perder canvas ni simulación */}
          <div
            id="panel-evidence"
            className="flex min-h-0 flex-1 flex-col overflow-hidden min-w-[380px]"
            style={{ display: panels.evidence ? undefined : "none" }}
          >
            <ErrorBoundary label="Panel de evidencias" fill>
              <CaseView client={client} />
            </ErrorBoundary>
          </div>
        </div>
      </div>

      {/* Modal global de Ajustes y Credenciales (Estilo opencode) */}
      <ModelSelector
        open={settingsOpen}
        onOpenChange={setSettingsOpen}
        client={client}
      />
    </div>
  );
}
