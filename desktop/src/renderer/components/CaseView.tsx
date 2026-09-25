/**
 * CaseView - vista del caso activo.
 *  - Grafo de conocimiento (layout radial simple en SVG, sin dependencias)
 *  - Cadena de custodia (ledger inmutable)
 *  - Acciones rápidas (dossier, integridad)
 */

import { useEffect, useMemo, useState } from "react";
import type { SpecterClient, EntityNode, LedgerBlock } from "@specter/sdk";
import { useStore } from "../store";

export default function CaseView({ client }: { client: SpecterClient }) {
  const activeCaseId = useStore((s) => s.activeCaseId)!;
  const graph = useStore((s) => s.graph);
  const setGraph = useStore((s) => s.setGraph);
  const ledger = useStore((s) => s.ledger);
  const setLedger = useStore((s) => s.setLedger);
  const [tab, setTab] = useState<"graph" | "ledger">("graph");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setBusy(true);
      try {
        const [g, l] = await Promise.all([
          client.caseGraph(activeCaseId, { maxDepth: 5 }),
          client.caseLedger(activeCaseId),
        ]);
        if (!cancelled) {
          setGraph(g);
          setLedger(l.blocks);
        }
      } finally {
        if (!cancelled) setBusy(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, activeCaseId, setGraph, setLedger]);

  const refresh = async () => {
    const [g, l] = await Promise.all([
      client.caseGraph(activeCaseId, { maxDepth: 5 }),
      client.caseLedger(activeCaseId),
    ]);
    setGraph(g);
    setLedger(l.blocks);
  };

  const exportDossier = async (format: "html" | "md") => {
    setBusy(true);
    try {
      await client.callTool("export_case_dossier", { case_id: activeCaseId, format });
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="case-view">
      <div className="case-toolbar">
        <div className="tabs">
          <button className={tab === "graph" ? "tab active" : "tab"} onClick={() => setTab("graph")}>
            Grafo
          </button>
          <button className={tab === "ledger" ? "tab active" : "tab"} onClick={() => setTab("ledger")}>
            Cadena de custodia ({ledger.length})
          </button>
        </div>
        <div className="toolbar-actions">
          <button className="btn small" onClick={refresh} disabled={busy}>
            ↻ Refrescar
          </button>
          <button className="btn small" onClick={() => exportDossier("html")} disabled={busy}>
            Dossier HTML
          </button>
          <button className="btn small" onClick={() => exportDossier("md")} disabled={busy}>
            Dossier MD
          </button>
        </div>
      </div>

      {tab === "graph" && <GraphCanvas nodes={graph?.nodes ?? []} edges={graph?.edges ?? []} />}
      {tab === "ledger" && <LedgerTable blocks={ledger} />}
    </section>
  );
}

// ---------------------------------------------------------------------
// Grafo radial en SVG puro: sin dependencias, determinista y rápido.
// ---------------------------------------------------------------------

const TYPE_COLORS: Record<string, string> = {
  DOMAIN: "#4da3ff",
  SUBDOMAIN: "#69c0ff",
  IP_ADDRESS: "#b085ff",
  PERSON: "#ff7ab8",
  EMAIL: "#ffb84d",
  SOCIAL_PROFILE: "#4ddbbe",
  FILE_ARTIFACT: "#d3d34d",
  GEO_LOCATION: "#7dff8a",
  ORGANIZATION: "#ff8f5e",
  ALIAS: "#9aa4b2",
  PHONE: "#5ed7ff",
};

function GraphCanvas({ nodes, edges }: { nodes: EntityNode[]; edges: { source_id: string; target_id: string; relation_type: string }[] }) {
  const layout = useMemo(() => {
    // Layout radial: nodo con más conexiones al centro; anillos por BFS.
    const degree = new Map<string, number>();
    for (const e of edges) {
      degree.set(e.source_id, (degree.get(e.source_id) ?? 0) + 1);
      degree.set(e.target_id, (degree.get(e.target_id) ?? 0) + 1);
    }
    const sorted = [...nodes].sort((a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0));
    const pos = new Map<string, { x: number; y: number }>();
    const W = 760;
    const H = 560;
    if (sorted.length > 0) {
      pos.set(sorted[0].id, { x: W / 2, y: H / 2 });
      let ring = 1;
      let idx = 1;
      while (idx < sorted.length) {
        const ringCount = Math.min(sorted.length - idx, ring * 6);
        const radius = 110 + ring * 95;
        for (let i = 0; i < ringCount; i++) {
          const angle = (2 * Math.PI * i) / ringCount + ring * 0.5;
          pos.set(sorted[idx].id, {
            x: W / 2 + radius * Math.cos(angle) * (H / W) * 1.35,
            y: H / 2 + radius * Math.sin(angle),
          });
          idx++;
        }
        ring++;
      }
    }
    return pos;
  }, [nodes, edges]);

  if (nodes.length === 0) {
    return <div className="empty-note pad">El grafo está vacío. Ejecuta recolecciones con el agente o desde la consola.</div>;
  }

  return (
    <div className="graph-wrap">
      <svg viewBox="0 0 760 560" className="graph-svg">
        {edges.map((e, i) => {
          const a = layout.get(e.source_id);
          const b = layout.get(e.target_id);
          if (!a || !b) return null;
          return (
            <line key={`e${i}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="edge" />
          );
        })}
        {nodes.map((n) => {
          const p = layout.get(n.id);
          if (!p) return null;
          const color = TYPE_COLORS[n.type] ?? "#9aa4b2";
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`} className="node">
              <circle r={9} fill={color} fillOpacity={0.9} stroke="#0b0e14" strokeWidth={2} />
              <title>{`${n.type}: ${n.value}`}</title>
              <text y={22} textAnchor="middle" className="node-label">
                {n.value.length > 22 ? `${n.value.slice(0, 21)}…` : n.value}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="legend">
        {Object.entries(TYPE_COLORS).map(([t, c]) => (
          <span key={t} className="legend-item">
            <span className="dot" style={{ background: c }} /> {t.toLowerCase()}
          </span>
        ))}
      </div>
    </div>
  );
}

function LedgerTable({ blocks }: { blocks: LedgerBlock[] }) {
  return (
    <div className="ledger-wrap">
      <table className="ledger-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Timestamp</th>
            <th>Collector</th>
            <th>Acción</th>
            <th>Hash</th>
          </tr>
        </thead>
        <tbody>
          {blocks.map((b) => (
            <tr key={`${b.case_id}-${b.block_index}`}>
              <td>{b.block_index}</td>
              <td>{b.timestamp.slice(0, 19).replace("T", " ")}</td>
              <td>{b.collector}</td>
              <td className="action-cell">{b.action}</td>
              <td className="hash-cell" title={b.block_hash}>
                {b.block_hash.slice(0, 14)}…
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
