/**
 * CaseView - vista unificada del expediente activo.
 *
 * Integra y coordina las vistas de evidencia modularizadas:
 *  - Grafo de conocimiento (GraphCanvas con ForceGraph2D, GraphControls y GraphNodeDetail)
 *  - Timeline forense con histograma temporal y alertas de ráfagas (TimelineView)
 *  - Correlaciones y candidatos de resolución de identidad (CorrelationsView)
 *  - Cadena de custodia HMAC-SHA256 y atestaciones criptográficas (LedgerTable)
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import type { WraithClient } from "@wraith/sdk";
import { useStore } from "../store";
import { createCaseLoadGuard } from "../caseLoadGuard";
import ErrorBoundary from "./ErrorBoundary";
import { Button, Icon, IconButton, cn } from "../ui";
import {
  CorrelationsView,
  EmptyState,
  GraphCanvas,
  LedgerTable,
  TimelineView,
  type CaseViewTab,
} from "./evidence";

export type { CaseViewTab };
export {
  CorrelationsView,
  EmptyState,
  GraphCanvas,
  GraphControls,
  GraphNodeDetail,
  LedgerTable,
  TimelineView,
} from "./evidence";

export interface CaseViewProps {
  client: WraithClient;
  caseId?: string;
  tab?: CaseViewTab;
  onTabChange?: (tab: CaseViewTab) => void;
  hideHeader?: boolean;
  /** Oculta los tabs locales cuando la navegación principal se gestiona externamente. */
  hideTabs?: boolean;
  className?: string;
}

const TABS: Array<{
  id: CaseViewTab;
  label: string;
  icon: "graph" | "clock" | "link" | "shield";
  keybind: string;
}> = [
  { id: "graph", label: "GRAFO", icon: "graph", keybind: "Ctrl+1" },
  { id: "timeline", label: "TIMELINE", icon: "clock", keybind: "Ctrl+2" },
  { id: "correlations", label: "CORRELACIONES", icon: "link", keybind: "Ctrl+3" },
  { id: "ledger", label: "CUSTODIA", icon: "shield", keybind: "Ctrl+4" },
];

export default function CaseView({
  client,
  caseId: propCaseId,
  tab: controlledTab,
  onTabChange,
  hideHeader = false,
  hideTabs = false,
  className = "",
}: CaseViewProps) {
  const storeCaseId = useStore((s) => s.activeCaseId);
  const activeCaseId = propCaseId ?? storeCaseId ?? "";
  const activeCaseIdRef = useRef(activeCaseId);
  activeCaseIdRef.current = activeCaseId;

  const graph = useStore((s) => s.graph);
  const ledger = useStore((s) => s.ledger);
  const timeline = useStore((s) => s.timeline);
  const correlations = useStore((s) => s.correlations);
  const attestation = useStore((s) => s.attestation);
  const storeActiveTab = useStore((s) => s.activeTab);
  const setActiveTab = useStore((s) => s.setActiveTab);
  const caseDataVersion = useStore((s) => s.caseDataVersion);
  const engineOnline = useStore((s) => s.engineOnline);

  const [busy, setBusy] = useState(false);
  const loadGuard = useRef(createCaseLoadGuard());

  const activeTab: CaseViewTab = controlledTab ?? storeActiveTab;

  const handleTabChange = (next: CaseViewTab) => {
    setActiveTab(next);
    onTabChange?.(next);
  };

  const load = async (cid: string) => {
    if (!cid) return;
    const request = loadGuard.current.begin(cid);
    const requestIsCurrent = () =>
      loadGuard.current.isCurrent(request, activeCaseIdRef.current) &&
      (propCaseId !== undefined || useStore.getState().activeCaseId === cid);
    setBusy(true);
    try {
      const [gRes, lRes, tRes, cRes] = await Promise.allSettled([
        client.caseGraph(cid, { maxDepth: 5 }),
        client.caseLedger(cid),
        client.caseTimeline(cid, "day"),
        client.caseCorrelations(cid),
      ]);
      if (!requestIsCurrent()) return;

      const store = useStore.getState();
      if (gRes.status === "fulfilled") store.setGraph(gRes.value);
      else console.warn("[wraith] error al cargar grafo:", gRes.reason);

      if (lRes.status === "fulfilled") store.setLedger(lRes.value);
      else console.warn("[wraith] error al cargar ledger:", lRes.reason);

      if (tRes.status === "fulfilled") store.setTimeline(tRes.value);
      else console.warn("[wraith] error al cargar timeline:", tRes.reason);

      if (cRes.status === "fulfilled") store.setCorrelations(cRes.value);
      else console.warn("[wraith] error al cargar correlaciones:", cRes.reason);

      store.setAttestation(null);
    } finally {
      if (requestIsCurrent()) setBusy(false);
    }
  };

  useEffect(() => {
    if (!activeCaseId || !engineOnline) {
      setBusy(false);
      return () => loadGuard.current.invalidate();
    }
    void load(activeCaseId).catch((err) => {
      console.warn("[wraith] error cargando el caso:", err);
    });
    return () => {
      loadGuard.current.invalidate();
    };
  }, [client, activeCaseId, caseDataVersion, engineOnline]);

  const refresh = async () => {
    if (!activeCaseId) return;
    await load(activeCaseId);
  };

  const sealCase = async () => {
    if (!activeCaseId) return;
    const requestedCaseId = activeCaseId;
    const caseIsCurrent = () =>
      activeCaseIdRef.current === requestedCaseId &&
      (propCaseId !== undefined || useStore.getState().activeCaseId === requestedCaseId);
    setBusy(true);
    try {
      const result = await client.caseAttestation(requestedCaseId);
      if (caseIsCurrent()) {
        useStore.getState().setAttestation(result);
      }
    } finally {
      if (caseIsCurrent()) setBusy(false);
    }
  };

  const counts: Record<CaseViewTab, number | null> = useMemo(
    () => ({
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

  // Navegación por teclado accesible para tablist
  const onTabListKeyDown = useCallback((e: ReactKeyboardEvent<HTMLDivElement>) => {
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

  return (
    <section className={`flex min-h-0 min-w-0 flex-1 flex-col bg-transparent ${className}`}>
      {/* Barra de navegación flotante centrada, sin línea divisoria inferior y con margen superior holgado */}
      {!hideHeader && !hideTabs && (
        <div className="relative flex shrink-0 items-center justify-center px-4 pt-5 pb-3 bg-transparent z-10">
          <nav aria-label="Vistas del expediente" className="flex items-center justify-center">
            <div
              role="tablist"
              aria-label="Vistas"
              onKeyDown={onTabListKeyDown}
              className="flex items-center gap-1 rounded-md border border-border-base bg-surface-raised-stronger/95 p-1 shadow-paper-sm backdrop-blur-md"
            >
              {TABS.map((t) => {
                const isActive = activeTab === t.id;
                const count = counts[t.id];
                return (
                  <button
                    key={t.id}
                    type="button"
                    role="tab"
                    id={`workspace-tab-${t.id}`}
                    aria-selected={isActive}
                    aria-controls={`tabpanel-${t.id}`}
                    tabIndex={isActive ? 0 : -1}
                    onClick={() => handleTabChange(t.id)}
                    title={`${t.label} (${t.keybind})`}
                    className={cn(
                      "relative flex cursor-pointer items-center gap-1.5 rounded-xs px-2.5 py-1 text-[11px] font-mono tracking-tight transition-all duration-base",
                      isActive
                        ? "bg-surface-raised-strong font-semibold text-text-strong shadow-paper-xs border border-border-base"
                        : "text-text-weak hover:bg-surface-base-hover hover:text-text-base border border-transparent",
                    )}
                  >
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

          <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
            {activeCaseId && (
              <IconButton
                name="refresh"
                size="small"
                label="Recargar evidencias"
                onClick={() => void refresh()}
                disabled={busy}
                title="Recargar grafo y evidencias desde el engine"
              />
            )}
          </div>
        </div>
      )}

      {/* Contenido de la pestaña activa o estado vacío */}
      {!activeCaseId ? (
        <EmptyEvidenceView />
      ) : (
        <div className="relative flex min-h-0 min-w-0 flex-1 flex-col outline-none">
          {/* Grafo de conocimiento: permanece montado para conservar canvas WebGL, simulación d3 y posiciones */}
          <div
            role="tabpanel"
            id="tabpanel-graph"
            aria-labelledby="workspace-tab-graph"
            tabIndex={0}
            className="flex min-h-0 min-w-0 flex-1 flex-col outline-none"
            style={{ display: activeTab === "graph" ? undefined : "none" }}
          >
            {busy && !graph ? (
              <div className="flex flex-1 items-center justify-center p-8 bg-transparent">
                <span className="font-mono text-[12px] text-text-weak anim-blink">
                  Cargando grafo de conocimiento…
                </span>
              </div>
            ) : (
              <ErrorBoundary label="Grafo de conocimiento" fill>
                <GraphCanvas nodes={graph?.nodes ?? []} edges={graph?.edges ?? []} />
              </ErrorBoundary>
            )}
          </div>

          {/* Timeline forense: permanece montado para preservar scroll y filtros */}
          <div
            role="tabpanel"
            id="tabpanel-timeline"
            aria-labelledby="workspace-tab-timeline"
            tabIndex={0}
            className="flex min-h-0 min-w-0 flex-1 flex-col outline-none"
            style={{ display: activeTab === "timeline" ? undefined : "none" }}
          >
            <TimelineView report={timeline} />
          </div>

          {/* Correlaciones y candidatos de resolución */}
          <div
            role="tabpanel"
            id="tabpanel-correlations"
            aria-labelledby="workspace-tab-correlations"
            tabIndex={0}
            className="flex min-h-0 min-w-0 flex-1 flex-col outline-none"
            style={{ display: activeTab === "correlations" ? undefined : "none" }}
          >
            <CorrelationsView
              report={correlations}
              caseId={activeCaseId}
              client={client}
              onChanged={refresh}
            />
          </div>

          {/* Cadena de custodia y atestaciones criptográficas */}
          <div
            role="tabpanel"
            id="tabpanel-ledger"
            aria-labelledby="workspace-tab-ledger"
            tabIndex={0}
            className="flex min-h-0 min-w-0 flex-1 flex-col outline-none"
            style={{ display: activeTab === "ledger" ? undefined : "none" }}
          >
            <LedgerTable
              report={ledger}
              attestation={attestation}
              client={client}
              caseId={activeCaseId}
              busy={busy}
              onSeal={sealCase}
            />
          </div>
        </div>
      )}
    </section>
  );
}

function EmptyEvidenceView() {
  const cases = useStore((s) => s.cases);
  const setActiveCase = useStore((s) => s.setActiveCase);
  const hasCases = cases.length > 0;

  return (
    <div className="anim-rise relative flex flex-1 items-center justify-center p-8 bg-transparent">
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
        <div className="flex flex-col gap-2">
          {hasCases && (
            <Button
              variant="primary"
              size="small"
              onClick={() => setActiveCase(cases[0].case_id)}
              icon="folder"
            >
              Abrir {cases[0].name}
            </Button>
          )}
          <Button
            variant="secondary"
            size="small"
            onClick={() => useStore.getState().setPanels({ sidebar: true })}
            icon="list"
          >
            Explorar expedientes (Ctrl+B)
          </Button>
        </div>
      </div>
    </div>
  );
}
