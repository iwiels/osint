import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { EntityNode } from "@specter/sdk";
import { Icon } from "../../ui";
import { EmptyState } from "./EmptyState";
import { GraphControls } from "./GraphControls";
import { GraphNodeDetail } from "./GraphNodeDetail";
import {
  BG_COLOR,
  FALLBACK_NODE_COLOR,
  LINK_COLOR,
  TYPE_COLORS,
  idOf,
  type FGraphLink,
  type FGraphNode,
  type ForceGraphMethods,
  type RawEdge,
} from "./types";

interface GraphCanvasProps {
  nodes: EntityNode[];
  edges: RawEdge[];
}

export function GraphCanvas({ nodes, edges }: GraphCanvasProps) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<ForceGraphMethods | undefined>(undefined);
  const prevNodesRef = useRef<FGraphNode[]>([]);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [hover, setHover] = useState<FGraphNode | null>(null);
  const [selected, setSelected] = useState<FGraphNode | null>(null);
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set());
  // Leyenda plegable (WCAG/Clutter): solo tipos presentes con conteo. El filtro
  // completo vive en el control "Tipos"; aquí solo se informa.
  const [legendOpen, setLegendOpen] = useState(false);

  // Tipos únicos presentes en las entidades del grafo
  const availableTypes = useMemo(() => {
    const s = new Set<string>();
    for (const n of nodes) s.add(n.type);
    return Array.from(s).sort();
  }, [nodes]);

  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const n of nodes) {
      counts[n.type] = (counts[n.type] ?? 0) + 1;
    }
    return counts;
  }, [nodes]);

  const toggleTypeFilter = (type: string) => {
    setSelectedTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  };

  const selectAllTypes = () => {
    setSelectedTypes(new Set(availableTypes));
  };

  const clearTypeFilters = () => {
    setSelectedTypes(new Set());
  };

  const handleZoomIn = () => {
    const current = (fgRef.current?.zoom() as number) || 1;
    fgRef.current?.zoom(current * 1.3, 300);
  };

  const handleZoomOut = () => {
    const current = (fgRef.current?.zoom() as number) || 1;
    fgRef.current?.zoom(current / 1.3, 300);
  };

  const handleZoomToFit = () => {
    fgRef.current?.zoomToFit(300, 48);
  };

  // Atajos de teclado locales para el grafo (+, -, 0, F)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

      if (
        e.key === "+" ||
        e.key === "=" ||
        e.code === "Equal" ||
        e.code === "NumpadAdd" ||
        e.code === "BracketRight"
      ) {
        e.preventDefault();
        handleZoomIn();
      } else if (
        e.key === "-" ||
        e.key === "_" ||
        e.code === "Minus" ||
        e.code === "NumpadSubtract" ||
        e.code === "Slash"
      ) {
        e.preventDefault();
        handleZoomOut();
      } else if (
        e.key === "0" ||
        e.code === "Digit0" ||
        e.code === "Numpad0" ||
        e.key.toLowerCase() === "f"
      ) {
        e.preventDefault();
        handleZoomToFit();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  // Medir el contenedor de forma reactiva: ForceGraph2D necesita width/height explícitos.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const r = entries[0]?.contentRect;
      if (r && r.width > 0 && r.height > 0) {
        setSize({ w: Math.floor(r.width), h: Math.floor(r.height) });
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Filtrado de nodos y cálculo exacto de grados y aristas válidas
  const { data, droppedLinks } = useMemo(() => {
    const activeFilter = selectedTypes.size > 0 && selectedTypes.size < availableTypes.length;
    const filteredNodes = activeFilter
      ? nodes.filter((n) => selectedTypes.has(n.type))
      : nodes;

    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    const degree = new Map<string, number>();

    // Normaliza ambas formas de arista y descarta las colgantes (extremos
    // ausentes): un solo enlace a undefined envenena con NaN toda la
    // simulación d3 y el canvas queda negro.
    const fLinks: FGraphLink[] = [];
    let dropped = 0;
    for (const e of edges) {
      const s = idOf(e.source_id ?? e.source);
      const t = idOf(e.target_id ?? e.target);
      if (!s || !t || !nodeIds.has(s) || !nodeIds.has(t)) {
        dropped += 1;
        continue;
      }
      degree.set(s, (degree.get(s) ?? 0) + 1);
      degree.set(t, (degree.get(t) ?? 0) + 1);
      fLinks.push({ source: s, target: t, relation_type: e.relation_type ?? "" });
    }

    const prevPositions = new Map<string, { x?: number; y?: number; vx?: number; vy?: number }>();
    for (const n of prevNodesRef.current) {
      if (n.x !== undefined && n.y !== undefined) {
        prevPositions.set(n.id, { x: n.x, y: n.y, vx: n.vx, vy: n.vy });
      }
    }

    const seen = new Set<string>();
    const fNodes: FGraphNode[] = [];
    for (const n of filteredNodes) {
      if (seen.has(n.id)) continue;
      seen.add(n.id);
      const prev = prevPositions.get(n.id);
      fNodes.push({
        id: n.id,
        type: n.type,
        value: n.value,
        confidence: n.confidence,
        first_seen: n.first_seen,
        last_seen: n.last_seen,
        degree: degree.get(n.id) ?? 0,
        ...(prev ? { x: prev.x, y: prev.y, vx: prev.vx, vy: prev.vy } : {}),
      });
    }

    return { data: { nodes: fNodes, links: fLinks }, droppedLinks: dropped };
  }, [nodes, edges, selectedTypes, availableTypes]);

  useEffect(() => {
    prevNodesRef.current = data.nodes as FGraphNode[];
  }, [data.nodes]);

  const nodeById = useMemo(() => {
    const m = new Map<string, FGraphNode>();
    for (const n of data.nodes as FGraphNode[]) m.set(n.id, n);
    return m;
  }, [data]);

  // Encuadrar cuando la simulación se estabiliza (y en cada cambio de datos).
  useEffect(() => {
    if (size.w === 0 || data.nodes.length === 0) return;
    const t = setTimeout(() => fgRef.current?.zoomToFit(400, 48), 900);
    return () => clearTimeout(t);
  }, [size.w, data]);

  const neighborsOf = (id: string): FGraphNode[] => {
    const out: FGraphNode[] = [];
    for (const l of data.links as FGraphLink[]) {
      const s = typeof l.source === "object" ? l.source.id : l.source;
      const t = typeof l.target === "object" ? l.target.id : l.target;
      if (s === id && nodeById.has(t)) out.push(nodeById.get(t)!);
      else if (t === id && nodeById.has(s)) out.push(nodeById.get(s)!);
      if (out.length >= 12) break;
    }
    return out;
  };

  if (nodes.length === 0) {
    return (
      <EmptyState
        label="grafo vacío"
        body="Ejecuta recolecciones con el agente o desde la consola para poblar el grafo de conocimiento del caso."
      />
    );
  }

  const paintNode = (node: FGraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
    ctx.save();
    const x = node.x ?? 0;
    const y = node.y ?? 0;
    const color = TYPE_COLORS[node.type] ?? FALLBACK_NODE_COLOR;
    const baseRadius = 4.5 + Math.min(6, (node.degree ?? 0) * 0.8);
    const isActive = hover?.id === node.id || selected?.id === node.id;
    const radius = isActive ? baseRadius + 2.5 : baseRadius;

    // Nodo circular con relleno sólido de color
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, 2 * Math.PI, false);
    ctx.fillStyle = color;
    ctx.fill();

    // Borde de contraste alto
    if (isActive) {
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = Math.max(1.5, 2 / (globalScale || 1));
      ctx.stroke();
    } else {
      ctx.strokeStyle = "#0b0f19";
      ctx.lineWidth = Math.max(0.8, 1 / (globalScale || 1));
      ctx.stroke();
    }

    // Etiquetas: solo cuando el nodo está activo o es un hub con zoom suficiente
    const isHub = (node.degree ?? 0) >= 3;
    const showLabel = isActive || (isHub && globalScale >= 0.75);
    if (showLabel) {
      const fontSize = Math.min(13, Math.max(9, 11 / (globalScale || 1)));
      ctx.font = `${fontSize}px "IBM Plex Mono", monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      const label = node.value.length > 25 ? `${node.value.slice(0, 24)}…` : node.value;
      if (isActive) {
        const textWidth = ctx.measureText(label).width;
        ctx.fillStyle = "rgba(11, 15, 25, 0.9)";
        ctx.fillRect(x - textWidth / 2 - 4, y + radius + 2, textWidth + 8, fontSize + 3);
        ctx.fillStyle = "#ffffff";
      } else {
        ctx.fillStyle = "#94a3b8";
      }
      ctx.fillText(label, x, y + radius + 3);
    }
    ctx.restore();
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Canvas del grafo con full-bleed, retícula blueprint y marcas técnicas de plano */}
      <div
        ref={wrapRef}
        role="group"
        aria-label={`Grafo de conocimiento: ${data.nodes.length} entidades y ${data.links.length} relaciones`}
        className="relative min-h-0 flex-1 overflow-hidden bg-background-base bg-blueprint-grid"
      >
        {/* Marcas de registro en esquinas (puramente visuales, sin texto) */}
        <div className="pointer-events-none absolute inset-3 z-10 flex flex-col justify-between select-none">
          <div className="flex items-center justify-between font-mono text-[10px] leading-none text-text-weaker/60">
            <span>+</span>
            <span>+</span>
          </div>
          <div className="flex items-center justify-between font-mono text-[10px] leading-none text-text-weaker/60">
            <span>+</span>
            <span>+</span>
          </div>
        </div>

        {size.w > 0 && size.h > 0 && (
          <ForceGraph2D
            ref={fgRef as never}
            width={size.w}
            height={size.h}
            graphData={data}
            backgroundColor={BG_COLOR}
            minZoom={0.15}
            maxZoom={6}
            nodeRelSize={4}
            nodeCanvasObject={paintNode as never}
            nodePointerAreaPaint={(
              node: FGraphNode,
              color: string,
              ctx: CanvasRenderingContext2D,
              _globalScale: number,
            ) => {
              ctx.save();
              const x = node.x ?? 0;
              const y = node.y ?? 0;
              const baseRadius = 4.5 + Math.min(6, (node.degree ?? 0) * 0.8);
              const hitRadius = Math.max(baseRadius + 5, 12);
              ctx.fillStyle = color;
              ctx.beginPath();
              ctx.arc(x, y, hitRadius, 0, 2 * Math.PI, false);
              ctx.fill();
              ctx.restore();
            }}
            linkColor={() => LINK_COLOR}
            linkWidth={() => 1.5}
            linkDirectionalArrowLength={3.5}
            linkDirectionalArrowRelPos={0.95}
            onNodeHover={(n: FGraphNode | null) => setHover(n)}
            onNodeClick={(n: FGraphNode) => setSelected(n)}
            onBackgroundClick={() => setSelected(null)}
            onEngineStop={() => fgRef.current?.zoomToFit(400, 40)}
            enableNodeDrag
            warmupTicks={60}
            cooldownTime={4000}
            d3VelocityDecay={0.35}
          />
        )}

        {/* Dock flotante de controles (zoom, encuadre y filtro de tipos) */}
        <GraphControls
          onZoomIn={handleZoomIn}
          onZoomOut={handleZoomOut}
          onFitView={handleZoomToFit}
          availableTypes={availableTypes}
          typeCounts={typeCounts}
          selectedTypes={selectedTypes}
          onToggleType={toggleTypeFilter}
          onSelectAllTypes={selectAllTypes}
          onClearTypes={clearTypeFilters}
        />

        {/* Ficha flotante de detalle del nodo seleccionado */}
        {selected && (
          <GraphNodeDetail
            node={selected}
            neighbors={neighborsOf(selected.id)}
            onSelectNode={(nb) => setSelected(nb)}
            onClose={() => setSelected(null)}
          />
        )}
      </div>

      {/* Barra de estado forense inferior */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border-weak-base bg-surface-raised-base px-3.5 py-2 font-mono text-[10px] text-text-weak">
        <span className="mono-data">
          {data.nodes.length} nodos · {data.links.length} aristas
          {droppedLinks > 0 && ` (${droppedLinks} enlaces fuera de filtro)`}
        </span>
        <span className="hidden sm:inline text-text-weaker">|</span>
        <button
          type="button"
          aria-expanded={legendOpen}
          onClick={() => setLegendOpen(!legendOpen)}
          className="ml-auto inline-flex cursor-pointer items-center gap-1 font-mono text-[10px] text-text-weak hover:text-text-strong"
          title="Mostrar u ocultar la leyenda de tipos presentes"
        >
          <span
            className="inline-block size-[7px] rounded-xs"
            style={{ background: "var(--text-weak)" }}
          />
          Leyenda ({availableTypes.length})
          <span aria-hidden="true" className={`inline-flex transition-transform duration-base ${legendOpen ? "rotate-180" : ""}`}>
            <Icon name="chevron-down" size="small" />
          </span>
        </button>
      </div>
      {legendOpen && (
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 border-t border-border-weak-base bg-surface-raised-base px-3.5 py-1.5">
          {availableTypes.map((t) => (
            <span key={t} className="inline-flex items-center gap-1 font-mono text-[10px]">
              <span
                className="inline-block size-[7px] rounded-xs"
                style={{ background: TYPE_COLORS[t] ?? FALLBACK_NODE_COLOR }}
              />
              {t.toLowerCase()} · {typeCounts[t] ?? 0}
            </span>
          ))}
          {availableTypes.length === 0 && (
            <span className="font-mono text-[10px] text-text-weaker">sin nodos</span>
          )}
        </div>
      )}
    </div>
  );
}
