/**
 * CaseView - vista unificada del expediente activo.
 *
 * Integra y coordina las vistas de evidencia modularizadas:
 *  - Grafo de conocimiento (GraphCanvas con ForceGraph2D, GraphControls y GraphNodeDetail)
 *  - Timeline forense con histograma temporal y alertas de ráfagas (TimelineView)
 *  - Correlaciones y candidatos de resolución de identidad (CorrelationsView)
 *  - Cadena de custodia HMAC-SHA256 y atestaciones criptográficas (LedgerTable)
 *
 * Admite tanto el modo de navegación completa por pestañas internas como el
 * renderizado directo de una pestaña específica (prop `tab`), permitiendo
 * incrustación modular en el tab bar central o en paneles laterales.
 */

import {
  useEffect,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
} from "react";
import type { SpecterClient } from "@specter/sdk";
import { useStore } from "../store";
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
  client: SpecterClient;
  caseId?: string;
  tab?: CaseViewTab;
  onTabChange?: (tab: CaseViewTab) => void;
  hideHeader?: boolean;
  /** Oculta los tabs locales cuando la navegación principal se gestiona en la cabecera global. */
  hideTabs?: boolean;
  className?: string;
}

const TABS: Array<{ id: CaseViewTab; label: string }> = [
  { id: "graph", label: "Grafo" },
  { id: "timeline", label: "Timeline" },
  { id: "correlations", label: "Correl." },
  { id: "ledger", label: "Custodia" },
];

const STATUS_DOT: Record<string, string> = {
  SEALED: "bg-success",
  PARTIAL: "bg-warning",
  UNSIGNED: "bg-warning",
  INVALID: "bg-critical",
  KEY_UNAVAILABLE: "bg-surface-disabled",
};

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

  const graph = useStore((s) => s.graph);
  const ledger = useStore((s) => s.ledger);
  const timeline = useStore((s) => s.timeline);
  const correlations = useStore((s) => s.correlations);
  const attestation = useStore((s) => s.attestation);

  const [internalTab, setInternalTab] = useState<CaseViewTab>(controlledTab ?? "graph");
  const [busy, setBusy] = useState(false);

  // El tab controlado viene de la nav global: si trae un id ajeno (p.ej. "chat"),
  // se cae a grafo en vez de pintar un panel vacío.
  const activeTab: CaseViewTab =
    controlledTab && (TABS as Array<{ id: CaseViewTab }>).some((t) => t.id === controlledTab)
      ? controlledTab
      : internalTab;

  const handleTabChange = (next: CaseViewTab) => {
    setInternalTab(next);
    onTabChange?.(next);
  };

  const load = async (cid: string) => {
    if (!cid) return;
    const [g, l, t, c] = await Promise.all([
      client.caseGraph(cid, { maxDepth: 5 }),
      client.caseLedger(cid),
      client.caseTimeline(cid, "day"),
      client.caseCorrelations(cid),
    ]);
    const store = useStore.getState();
    store.setGraph(g);
    store.setLedger(l);
    store.setTimeline(t);
    store.setCorrelations(c);
    store.setAttestation(null);
  };

  useEffect(() => {
    if (!activeCaseId) return;
    let cancelled = false;
    (async () => {
      setBusy(true);
      try {
        await load(activeCaseId);
      } catch (err) {
        if (!cancelled) console.warn("[specter] error cargando el caso:", err);
      } finally {
        if (!cancelled) setBusy(false);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, activeCaseId]);

  const refresh = async () => {
    if (!activeCaseId) return;
    setBusy(true);
    try {
      await load(activeCaseId);
    } finally {
      setBusy(false);
    }
  };

  const sealCase = async () => {
    if (!activeCaseId) return;
    setBusy(true);
    try {
      useStore.getState().setAttestation(await client.caseAttestation(activeCaseId));
    } finally {
      setBusy(false);
    }
  };

  if (!activeCaseId) {
    return (
      <EmptyState
        label="sin expediente activo"
        body="Selecciona o crea un expediente en el panel lateral para visualizar su grafo de conocimiento, timeline y custodia."
      />
    );
  }

  const counts: Record<CaseViewTab, number | null> = {
    graph: graph?.nodes.length ?? null,
    timeline: timeline?.total_events ?? null,
    correlations:
      correlations == null
        ? null
        : correlations.cross_case.total_shared_entities +
          correlations.identity_candidates.total_candidates,
    ledger: ledger?.blocks.length ?? null,
  };

  const statusDot = ledger?.signature_status ? STATUS_DOT[ledger.signature_status] : undefined;

  // Navegación por teclado accesible para tablist
  const onTabListKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    const step: Record<string, number> = { ArrowRight: 1, ArrowLeft: -1 };
    if (step[e.key] === undefined && e.key !== "Home" && e.key !== "End") return;
    const tabs = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('[role="tab"]'));
    if (tabs.length === 0) return;
    const focused = tabs.indexOf(document.activeElement as HTMLElement);
    const from = focused === -1 ? tabs.findIndex((t) => t.dataset.state === "selected") : focused;
    const next =
      e.key === "Home"
        ? 0
        : e.key === "End"
          ? tabs.length - 1
          : (((from < 0 ? 0 : from) + step[e.key]) % tabs.length + tabs.length) % tabs.length;
    e.preventDefault();
    tabs[next]?.focus();
    tabs[next]?.click();
  };

  return (
    <section className={`flex min-h-0 min-w-0 flex-1 flex-col ${className}`}>
      {/* Cabecera: tabs locales únicamente si la navegación global no los gestiona */}
      {!hideHeader && !hideTabs && (
        <div className="flex h-[42px] shrink-0 items-center gap-1 border-b border-border-weak-base bg-surface-raised-base px-2.5">
          <div
            role="tablist"
            aria-label="Vistas del expediente"
            onKeyDown={onTabListKeyDown}
            className="flex min-w-0 items-center gap-0.5"
          >
            {TABS.map((t) => (
              <TabButton
                key={t.id}
                id={`tab-${t.id}`}
                panelId={`tabpanel-${t.id}`}
                selected={activeTab === t.id}
                dot={t.id === "ledger" ? statusDot : undefined}
                onClick={() => handleTabChange(t.id)}
              >
                {t.label}
                {counts[t.id] != null && (
                  <span className="mono-data ml-1.5 text-[10px] text-text-weaker">
                    {counts[t.id]}
                  </span>
                )}
              </TabButton>
            ))}
          </div>
        </div>
      )}

      {/* Contenido de la pestaña activa */}
      <div
        role="tabpanel"
        id={`tabpanel-${activeTab}`}
        aria-labelledby={`tab-${activeTab}`}
        tabIndex={0}
        className="flex min-h-0 min-w-0 flex-1 flex-col outline-none"
      >
        {activeTab === "graph" && (
          <GraphCanvas nodes={graph?.nodes ?? []} edges={graph?.edges ?? []} />
        )}
        {activeTab === "timeline" && <TimelineView report={timeline} />}
        {activeTab === "correlations" && (
          <CorrelationsView
            report={correlations}
            caseId={activeCaseId}
            client={client}
            onChanged={refresh}
          />
        )}
        {activeTab === "ledger" && (
          <LedgerTable
            report={ledger}
            attestation={attestation}
            client={client}
            caseId={activeCaseId}
            busy={busy}
            onSeal={sealCase}
          />
        )}
      </div>
    </section>
  );
}

function TabButton({
  id,
  panelId,
  selected,
  onClick,
  dot,
  children,
}: {
  id: string;
  panelId: string;
  selected: boolean;
  onClick: () => void;
  dot?: string;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      role="tab"
      id={id}
      aria-selected={selected}
      aria-controls={panelId}
      tabIndex={selected ? 0 : -1}
      data-state={selected ? "selected" : "unselected"}
      onClick={onClick}
      className={`flex cursor-pointer items-center whitespace-nowrap border-b-2 px-2.5 py-2 font-display text-[12px] font-medium tracking-wide transition-colors duration-150 ${
        selected
          ? "border-brand text-text-strong"
          : "border-transparent text-text-weak hover:text-text-strong"
      }`}
    >
      {dot && <span className={`mr-1.5 inline-block size-2 rounded-xs ${dot}`} />}
      {children}
    </button>
  );
}
