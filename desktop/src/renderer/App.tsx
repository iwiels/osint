/**
 * App - consola forense Specter.
 * Layout: sidebar de casos | vista de caso (grafo + custodia) | consola del agente.
 * Al montar: health-check del engine y suscripción al event bus (SSE).
 */

import { useCallback, useEffect, useMemo, useRef } from "react";
import { SpecterClient, connectEvents } from "@specter/sdk";
import { PANEL_BREAKPOINTS, useStore, type MainTab, type PanelState } from "./store";
import { Button, Icon, IconButton, Tag, cn } from "./ui";
import Sidebar from "./components/Sidebar";
import CaseView from "./components/CaseView";
import AgentConsole from "./components/AgentConsole";

const TABS: Array<{
  id: MainTab;
  index: string;
  label: string;
  icon: "terminal" | "graph" | "clock" | "link" | "shield";
  keybind: string;
}> = [
  { id: "chat", index: "01", label: "CHAT", icon: "terminal", keybind: "Ctrl+1" },
  { id: "graph", index: "02", label: "GRAFO", icon: "graph", keybind: "Ctrl+2" },
  { id: "timeline", index: "03", label: "TIMELINE", icon: "clock", keybind: "Ctrl+3" },
  { id: "correlations", index: "04", label: "CORRELACIONES", icon: "link", keybind: "Ctrl+4" },
  { id: "ledger", index: "05", label: "CUSTODIA", icon: "shield", keybind: "Ctrl+5" },
];

/** Puente mínimo con main (preload). Todo opcional: también corre en navegador. */
interface SpecterDesktopBridge {
  checkHealth?: () => Promise<unknown>;
  getEngineToken?: () => Promise<string | null>;
  revealInFolder?: (fsPath: string) => Promise<boolean>;
  openExternal?: (url: string) => Promise<boolean>;
}

function desktopBridge(): SpecterDesktopBridge | undefined {
  if (typeof window === "undefined") return undefined;
  return (window as unknown as { specterDesktop?: SpecterDesktopBridge }).specterDesktop;
}

export default function App() {
  const engineUrl = useStore((s) => s.engineUrl);
  const engineToken = useStore((s) => s.engineToken);
  const engineOnline = useStore((s) => s.engineOnline);
  const setEngineOnline = useStore((s) => s.setEngineOnline);
  const setCases = useStore((s) => s.setCases);
  const cases = useStore((s) => s.cases);
  const activeCaseId = useStore((s) => s.activeCaseId);
  const activeTab = useStore((s) => s.activeTab);
  const setActiveTab = useStore((s) => s.setActiveTab);
  const graph = useStore((s) => s.graph);
  const timeline = useStore((s) => s.timeline);
  const correlations = useStore((s) => s.correlations);
  const ledger = useStore((s) => s.ledger);
  const panels = useStore((s) => s.panels);
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
      new SpecterClient({
        baseUrl: engineUrl,
        defaultHeaders: engineToken ? { Authorization: `Bearer ${engineToken}` } : {},
      }),
    [engineUrl, engineToken],
  );
  const activeCase = useMemo(
    () => cases.find((c) => c.case_id === activeCaseId),
    [cases, activeCaseId],
  );

  // Una sola navegación (los conteos vivían duplicados en CaseView).
  const tabCounts = useMemo<Record<MainTab, number | null>>(
    () => ({
      chat: null,
      graph: graph?.nodes.length ?? null,
      timeline: timeline?.total_events ?? null,
      correlations:
        correlations == null
          ? null
          : correlations.cross_case.total_shared_entities +
            correlations.identity_candidates.total_candidates,
      ledger: ledger?.blocks.length ?? null,
    }),
    [graph, timeline, correlations, ledger],
  );

  // Navegación por teclado del tablist (patrón WCAG: flechas/Home/End + roving tabindex).
  const onTabListKeyDown = useCallback((e: React.KeyboardEvent<HTMLDivElement>) => {
    const tabs = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('[role="tab"]'));
    if (tabs.length === 0) return;
    const step: Record<string, number> = { ArrowRight: 1, ArrowLeft: -1 };
    if (step[e.key] === undefined && e.key !== "Home" && e.key !== "End") return;
    const focused = tabs.indexOf(document.activeElement as HTMLElement);
    const from = focused === -1 ? tabs.findIndex((t) => t.getAttribute("aria-selected") === "true") : focused;
    const next =
      e.key === "Home"
        ? 0
        : e.key === "End"
          ? tabs.length - 1
          : (((from < 0 ? 0 : from) + step[e.key]) % tabs.length + tabs.length) % tabs.length;
    e.preventDefault();
    tabs[next]?.focus();
    tabs[next]?.click();
  }, []);

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
        console.warn("[specter] client.health() fetch fallo:", err);
        // Fallback a IPC desde proceso principal Node si el navegador tuviera restricciones
        const res = await desktopBridge()?.checkHealth?.();
        if (res) isHealthy = true;
      }

      if (cancelled) return;

      if (isHealthy) {
        setEngineOnline(true);

        try {
          const fetchedCases = await client.listCases();
          if (!cancelled && Array.isArray(fetchedCases)) {
            setCases(fetchedCases);
          }
        } catch (casesErr) {
          console.warn("[specter] error cargando expedientes:", casesErr);
        }

        if (!dispose && !cancelled) {
          try {
            dispose = connectEvents(
              engineUrl,
              {
              "permission.request": (payload) =>
                useStore.getState().setPendingPermission(payload as never),
              "permission.granted": () => useStore.getState().setPendingPermission(null),
              "question.asked": (payload) =>
                useStore.getState().setPendingQuestion(payload as never),
              "tool.started": (payload) => {
                const p = payload as { call_id?: string; tool: string; arguments?: unknown };
                useStore.getState().startToolCall(p.call_id ?? "", p.tool, p.arguments);
              },
              "tool.completed": (payload) => {
                const p = payload as { call_id?: string; tool: string; result?: string };
                useStore.getState().completeToolCall(p.call_id ?? "", p.tool, p.result ?? "");
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
                useStore.getState().setPendingPermission(null);
                useStore.getState().setPendingQuestion(null);
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
            console.warn("[specter] fallo al conectar SSE:", sseErr);
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

  // Atajos de panel (Ctrl+B / Ctrl+J) y plegado automático al cruzar el umbral
  // de ventana estrecha: el expediente conserva el ancho y el analista reabre
  // lo que necesite cuando lo necesite.
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
      } else if (key === "1") {
        e.preventDefault();
        setActiveTab("chat");
      } else if (key === "2") {
        e.preventDefault();
        setActiveTab("graph");
      } else if (key === "3") {
        e.preventDefault();
        setActiveTab("timeline");
      } else if (key === "4") {
        e.preventDefault();
        setActiveTab("correlations");
      } else if (key === "5") {
        e.preventDefault();
        setActiveTab("ledger");
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
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-background-base">
      <a className="skip-link" href="#main-content">
        Saltar al chat
      </a>
      <header className="relative flex h-[46px] shrink-0 items-center justify-between gap-2 border-b border-border-weak-base bg-surface-raised-base bg-blueprint-grid px-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="size-2 rounded-xs bg-brand" />
            <span className="font-display text-[13px] font-semibold tracking-tight text-text-strong">
              Specter<span className="text-text-brand">OSINT</span>
            </span>
            <Tag>v0.2.0</Tag>
          </div>

          {activeCase ? (
            <div className="hidden items-center gap-2 border-l border-border-weak-base pl-3 sm:flex">
              <span
                className="max-w-[220px] truncate text-[13px] font-medium text-text-strong"
                title={`${activeCase.name} (${activeCase.case_id})`}
              >
                {activeCase.name}
              </span>
            </div>
          ) : null}
        </div>

        {/* Navegación única del workspace: pestañas estilo carpeta / dossier con índices mono */}
        <nav aria-label="Modo de espacio de trabajo" className="flex items-center">
          <div
            role="tablist"
            aria-label="Vistas"
            onKeyDown={onTabListKeyDown}
            className="flex items-center gap-1 rounded-sm border border-border-weak-base bg-surface-inset-base/90 p-0.5 shadow-paper-xs"
          >
            {TABS.map((t) => {
              const isActive = activeTab === t.id;
              const count = tabCounts[t.id];
              return (
                <button
                  key={t.id}
                  type="button"
                  role="tab"
                  id={`workspace-tab-${t.id}`}
                  aria-selected={isActive}
                  aria-controls="main-content"
                  tabIndex={isActive ? 0 : -1}
                  onClick={() => setActiveTab(t.id)}
                  title={`${t.label} (${t.keybind})`}
                  className={cn(
                    "relative flex cursor-pointer items-center gap-1.5 rounded-xs px-2.5 py-1 text-[11px] font-mono tracking-tight transition-all duration-base",
                    isActive
                      ? "bg-surface-raised-strong font-semibold text-text-strong shadow-paper-xs border border-border-base"
                      : "text-text-weak hover:bg-surface-base-hover hover:text-text-base border border-transparent",
                  )}
                >
                  <span className="font-mono text-[10px] text-text-weaker font-semibold">{t.index}</span>
                  <Icon name={t.icon} size="small" />
                  <span className="font-sans text-[11.5px] font-medium tracking-wide">
                    {t.label}
                  </span>
                  {count != null && (
                    <span className="mono-data ml-0.5 rounded-xs border border-border-weak-base/60 bg-surface-inset-base px-1 py-0.2 text-[9px] text-text-weaker">
                      {count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </nav>

        <div className="flex min-w-0 items-center">
          {/* Panel toggles: Sidebar & Split View */}
          <div className="flex items-center gap-0.5">
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
              name="terminal"
              size="small"
              label="Vista dividida Chat/Evidencias (Ctrl+J o Ctrl+\\)"
              aria-pressed={panels.evidence}
              aria-expanded={panels.evidence}
              aria-controls="panel-evidence"
              onClick={() => togglePanelSafely("evidence")}
            />
          </div>
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

      {/* Modular Workspace Area (Sidebar + Central Canvas/Tabs) */}
      <div className="flex min-h-0 flex-1 overflow-hidden">
        <div
          id="panel-sidebar"
          className="flex min-h-0"
          style={{ display: panels.sidebar ? undefined : "none" }}
        >
          <Sidebar client={client} />
        </div>

        {panels.evidence && activeTab !== "chat" ? (
          /* Split View: Chat on Left, Active Evidence Tab on Right */
          <div className="flex min-h-0 flex-1 overflow-hidden">
            <main
              id="main-content"
              tabIndex={-1}
              role="tabpanel"
              aria-label="Chat del agente"
              className="flex min-w-0 flex-1 flex-col overflow-hidden border-r border-border-weak-base"
            >
              <AgentConsole client={client} />
            </main>
            <div
              id="panel-evidence"
              className="flex min-h-0 w-[540px] max-w-[50vw] flex-col overflow-hidden"
            >
              {activeCaseId ? (
                <CaseView client={client} tab={activeTab} hideTabs />
              ) : (
                <EmptyEvidence />
              )}
            </div>
          </div>
        ) : (
          /* Full View: Whatever tab is selected */
          <main
            id="main-content"
            tabIndex={-1}
            role="tabpanel"
            aria-label="Espacio de trabajo principal"
            className="flex min-w-0 flex-1 flex-col overflow-hidden"
          >
            {activeTab === "chat" ? (
              <AgentConsole client={client} />
            ) : activeCaseId ? (
              <CaseView client={client} tab={activeTab} hideTabs />
            ) : (
              <EmptyEvidence />
            )}
          </main>
        )}
      </div>
    </div>
  );
}

function EmptyEvidence() {
  return (
    <div className="anim-rise relative flex flex-1 items-center justify-center p-8 bg-blueprint-grid">
      <div className="relative max-w-sm rounded-lg border border-border-weak-base bg-surface-raised-strong p-6 text-center shadow-paper-sm">
        <div className="mb-3 flex justify-center">
          <span className="flex size-10 items-center justify-center rounded-md border border-border-weak-base bg-surface-inset-base text-text-brand shadow-paper-xs">
            <Icon name="folder" size="medium" />
          </span>
        </div>
        <div className="label-caps mb-2 text-text-strong font-mono tracking-wider">Sin expediente</div>
        <p className="text-[12.5px] leading-relaxed text-text-base mb-4">
          Selecciona un expediente en el panel lateral o presiona Nuevo para abrir una investigación activa.
        </p>
        <Button
          variant="secondary"
          size="small"
          onClick={() => useStore.getState().setPanels({ sidebar: true })}
          icon="folder"
        >
          Explorar expedientes (Ctrl+B)
        </Button>
      </div>
    </div>
  );
}
