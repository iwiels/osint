import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { EntityNode } from "@wraith/sdk";
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
  const hasFocusedInitialRef = useRef(false);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [hover, setHover] = useState<FGraphNode | null>(null);
  const [selected, setSelected] = useState<FGraphNode | null>(null);
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set());
  const [clusterLeaves, setClusterLeaves] = useState(true);
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set());
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

  // Localiza el objetivo principal de la investigación para centrado de cámara
  const findPrimaryTarget = (targetNodes: FGraphNode[]): FGraphNode | null => {
    if (targetNodes.length === 0) return null;
    const person = targetNodes.find((n) => n.type === "PERSON");
    if (person) return person;
    const org = targetNodes.find((n) => n.type === "ORGANIZATION");
    if (org) return org;
    let best = targetNodes[0];
    for (const n of targetNodes) {
      if ((n.degree ?? 0) > (best.degree ?? 0)) {
        best = n;
      }
    }
    return best;
  };

  const handleFocusTarget = (durationMs = 600) => {
    if (!fgRef.current || data.nodes.length === 0) return;
    const target = findPrimaryTarget(data.nodes as FGraphNode[]);
    if (target && target.x !== undefined && target.y !== undefined) {
      fgRef.current.centerAt(target.x, target.y, durationMs);
      fgRef.current.zoom(1.35, durationMs);
    } else {
      fgRef.current.zoomToFit(durationMs, 50);
    }
  };

  const handleToggleClusterLeaves = () => {
    setClusterLeaves((prev) => {
      if (!prev) {
        setExpandedClusters(new Set());
        return true;
      }
      return false;
    });
    setTimeout(() => {
      fgRef.current?.d3ReheatSimulation();
    }, 50);
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

  // Filtrado de nodos, clustering de subdominios masivos y cálculo exacto de grados y aristas válidas
  const { data, droppedLinks, hasClusters } = useMemo(() => {
    const activeFilter = selectedTypes.size > 0 && selectedTypes.size < availableTypes.length;
    const filteredNodes = activeFilter
      ? nodes.filter((n) => selectedTypes.has(n.type))
      : nodes;

    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    const nodeMap = new Map<string, EntityNode>();
    for (const n of filteredNodes) nodeMap.set(n.id, n);

    // Identificar hojas SUBDOMAIN agrupadas por nodo padre (vía SUBDOMAIN_OF)
    // Para calificar como cluster, el dominio debe tener >= 6 subdominios.
    const subdomainsByParent = new Map<string, string[]>();
    for (const e of edges) {
      const s = idOf(e.source_id ?? e.source);
      const t = idOf(e.target_id ?? e.target);
      if (!s || !t || !nodeIds.has(s) || !nodeIds.has(t)) continue;

      const sNode = nodeMap.get(s);
      const tNode = nodeMap.get(t);
      if (e.relation_type === "SUBDOMAIN_OF" && sNode?.type === "SUBDOMAIN" && tNode?.type === "DOMAIN") {
        const list = subdomainsByParent.get(t) ?? [];
        list.push(s);
        subdomainsByParent.set(t, list);
      }
    }

    // Detectar cuáles padres superan el umbral (>= 6)
    const clusterCandidates = new Map<string, string[]>();
    let anyClusterFound = false;
    for (const [parentId, subIds] of subdomainsByParent.entries()) {
      if (subIds.length >= 6) {
        clusterCandidates.set(parentId, subIds);
        anyClusterFound = true;
      }
    }

    // Si clusterLeaves está activo, determinar qué subdominios se ocultan en supernodos
    const collapsedSubIds = new Set<string>();
    const superNodes: FGraphNode[] = [];
    const superLinks: FGraphLink[] = [];

    if (clusterLeaves) {
      for (const [parentId, subIds] of clusterCandidates.entries()) {
        const clusterId = `cluster:${parentId}:subdomains`;
        if (expandedClusters.has(clusterId)) {
          // El usuario expandió este cluster individualmente
          continue;
        }
        for (const subId of subIds) {
          collapsedSubIds.add(subId);
        }
        const parentNode = nodeMap.get(parentId);
        superNodes.push({
          id: clusterId,
          type: "CLUSTER",
          value: `${subIds.length} subdominios`,
          confidence: 1.0,
          first_seen: parentNode?.first_seen ?? "",
          last_seen: parentNode?.last_seen ?? "",
          degree: subIds.length,
          isCluster: true,
          clusterCount: subIds.length,
          clusterParentId: parentId,
          clusterChildIds: subIds,
        });
        superLinks.push({
          source: parentId,
          target: clusterId,
          relation_type: "CONTAINS",
        });
      }
    }

    const degree = new Map<string, number>();
    const fLinks: FGraphLink[] = [];
    let dropped = 0;

    for (const e of edges) {
      const s = idOf(e.source_id ?? e.source);
      const t = idOf(e.target_id ?? e.target);
      if (!s || !t || !nodeIds.has(s) || !nodeIds.has(t)) {
        dropped += 1;
        continue;
      }
      // Si alguno de los extremos fue absorbido en un supernodo colapsado, ignoramos el enlace individual
      if (collapsedSubIds.has(s) || collapsedSubIds.has(t)) {
        continue;
      }
      degree.set(s, (degree.get(s) ?? 0) + 1);
      degree.set(t, (degree.get(t) ?? 0) + 1);
      fLinks.push({ source: s, target: t, relation_type: e.relation_type ?? "" });
    }

    // Añadir superlinks
    for (const sl of superLinks) {
      const s = typeof sl.source === "string" ? sl.source : sl.source.id;
      const t = typeof sl.target === "string" ? sl.target : sl.target.id;
      degree.set(s, (degree.get(s) ?? 0) + 1);
      degree.set(t, (degree.get(t) ?? 0) + 1);
      fLinks.push(sl);
    }

    const prevPositions = new Map<string, { x?: number; y?: number; vx?: number; vy?: number }>();
    for (const n of prevNodesRef.current) {
      if (n.x !== undefined && n.y !== undefined) {
        prevPositions.set(n.id, { x: n.x, y: n.y, vx: n.vx, vy: n.vy });
      }
    }

    const seen = new Set<string>();
    const fNodes: FGraphNode[] = [];

    // Añadir nodos filtrados no colapsados
    for (const n of filteredNodes) {
      if (collapsedSubIds.has(n.id)) continue;
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

    // Añadir supernodes
    for (const sn of superNodes) {
      if (seen.has(sn.id)) continue;
      seen.add(sn.id);
      const prev = prevPositions.get(sn.id);
      const parentPos = prevPositions.get(sn.clusterParentId ?? "");
      fNodes.push({
        ...sn,
        degree: degree.get(sn.id) ?? sn.degree,
        ...(prev
          ? { x: prev.x, y: prev.y, vx: prev.vx, vy: prev.vy }
          : parentPos && parentPos.x !== undefined && parentPos.y !== undefined
          ? { x: parentPos.x + 35, y: parentPos.y + 35 }
          : {}),
      });
    }

    return {
      data: { nodes: fNodes, links: fLinks },
      droppedLinks: dropped,
      hasClusters: anyClusterFound,
    };
  }, [nodes, edges, selectedTypes, availableTypes, clusterLeaves, expandedClusters]);

  useEffect(() => {
    prevNodesRef.current = data.nodes as FGraphNode[];
  }, [data.nodes]);

  const nodeById = useMemo(() => {
    const m = new Map<string, FGraphNode>();
    for (const n of data.nodes as FGraphNode[]) m.set(n.id, n);
    return m;
  }, [data]);

  // Configuración de física D3: repulsión acotada (distanceMax/distanceMin)
  // para evitar que los grafos e islas salgan despedidos al infinito.
  useEffect(() => {
    if (!fgRef.current) return;
    const charge = fgRef.current.d3Force("charge") as any;
    if (charge) {
      if (typeof charge.strength === "function") charge.strength(-110);
      if (typeof charge.distanceMax === "function") charge.distanceMax(280);
      if (typeof charge.distanceMin === "function") charge.distanceMin(18);
    }
    const link = fgRef.current.d3Force("link") as any;
    if (link && typeof link.distance === "function") {
      link.distance((l: any) => {
        if (l.relation_type === "CONTAINS" || l.relation_type === "SUBDOMAIN_OF") return 42;
        return 52;
      });
    }
    const center = fgRef.current.d3Force("center") as any;
    if (center && typeof center.strength === "function") {
      center.strength(0.08);
    }
    fgRef.current.d3ReheatSimulation();
  }, [size.w, size.h, data.nodes.length]);

  // Reset del indicador de foco inicial al cambiar el caso investigado
  const caseIdKey = useMemo(() => nodes.map((n) => n.id).slice(0, 3).join("|"), [nodes]);
  useEffect(() => {
    hasFocusedInitialRef.current = false;
  }, [caseIdKey]);

  // Auto-foco inicial centrado en el objetivo tras el calentamiento de la física
  useEffect(() => {
    if (size.w === 0 || data.nodes.length === 0) return;
    if (hasFocusedInitialRef.current) return;

    const t = setTimeout(() => {
      handleFocusTarget(600);
      hasFocusedInitialRef.current = true;
    }, 700);

    return () => clearTimeout(t);
  }, [size.w, data.nodes]);

  const neighborsOf = (id: string): FGraphNode[] => {
    const out: FGraphNode[] = [];
    for (const l of data.links as FGraphLink[]) {
      const s = typeof l.source === "object" ? (l.source as any).id : l.source;
      const t = typeof l.target === "object" ? (l.target as any).id : l.target;
      if (s === id && nodeById.has(t)) out.push(nodeById.get(t)!);
      else if (t === id && nodeById.has(s)) out.push(nodeById.get(s)!);
      if (out.length >= 16) break;
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
    const isCluster = Boolean(node.isCluster);
    const isPerson = node.type === "PERSON";
    const isActive = hover?.id === node.id || selected?.id === node.id;

    if (isCluster) {
      // Supernodo estilizado de subdominios
      const clusterCount = node.clusterCount ?? 0;
      const radius = 10 + Math.min(6, Math.log2(clusterCount || 1));

      // Halo discontinuo exterior
      ctx.beginPath();
      ctx.arc(x, y, radius + 4, 0, 2 * Math.PI, false);
      ctx.strokeStyle = "rgba(56, 189, 248, 0.4)";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([3, 2]);
      ctx.stroke();
      ctx.setLineDash([]);

      // Esfera de supernodo
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, 2 * Math.PI, false);
      ctx.fillStyle = isActive ? "#0284c7" : "#0369a1";
      ctx.fill();
      ctx.strokeStyle = isActive ? "#ffffff" : "#38bdf8";
      ctx.lineWidth = isActive ? 2 : 1.2;
      ctx.stroke();

      // Conteo numérico centrado dentro del supernodo
      const countText = clusterCount > 999 ? "999+" : String(clusterCount);
      const badgeFontSize = Math.max(8, Math.min(11, radius * 0.9));
      ctx.font = `bold ${badgeFontSize}px "IBM Plex Mono", monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillStyle = "#ffffff";
      ctx.fillText(countText, x, y);

      // Etiqueta descriptiva debajo del supernodo
      const showLabel = isActive || globalScale >= 0.65;
      if (showLabel) {
        const fontSize = Math.min(12, Math.max(9, 10 / (globalScale || 1)));
        ctx.font = `600 ${fontSize}px "IBM Plex Mono", monospace`;
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        const label = `[+${clusterCount}] SUBDOMINIOS`;
        const textWidth = ctx.measureText(label).width;
        ctx.fillStyle = "rgba(11, 15, 25, 0.92)";
        ctx.fillRect(x - textWidth / 2 - 4, y + radius + 3, textWidth + 8, fontSize + 4);
        ctx.fillStyle = "#7dd3fc";
        ctx.fillText(label, x, y + radius + 4);
      }
      ctx.restore();
      return;
    }

    const color = TYPE_COLORS[node.type] ?? FALLBACK_NODE_COLOR;
    const baseRadius = 4.5 + Math.min(6, (node.degree ?? 0) * 0.8);
    const radius = isActive ? baseRadius + 2.5 : baseRadius;

    // Halo distintivo para PERSON (objetivo de la investigación)
    if (isPerson) {
      ctx.beginPath();
      ctx.arc(x, y, radius + 5, 0, 2 * Math.PI, false);
      ctx.strokeStyle = "rgba(255, 122, 184, 0.5)";
      ctx.lineWidth = 2;
      ctx.stroke();
    }

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

    // Etiquetas: siempre visibles para PERSON, o cuando el nodo está activo, o es un hub con zoom suficiente
    const isHub = (node.degree ?? 0) >= 3;
    const showLabel = isPerson || isActive || (isHub && globalScale >= 0.75);
    if (showLabel) {
      const fontSize = Math.min(13, Math.max(9, 11 / (globalScale || 1)));
      ctx.font = isPerson
        ? `bold ${fontSize}px "IBM Plex Mono", monospace`
        : `${fontSize}px "IBM Plex Mono", monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      const label = node.value.length > 25 ? `${node.value.slice(0, 24)}…` : node.value;
      if (isActive || isPerson) {
        const textWidth = ctx.measureText(label).width;
        ctx.fillStyle = isPerson ? "rgba(24, 15, 26, 0.95)" : "rgba(11, 15, 25, 0.9)";
        ctx.fillRect(x - textWidth / 2 - 4, y + radius + 2, textWidth + 8, fontSize + 3);
        ctx.fillStyle = isPerson ? "#ff7ab8" : "#ffffff";
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
        className="relative min-h-0 flex-1 overflow-hidden bg-transparent"
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
              const baseRadius = node.isCluster
                ? 12
                : 4.5 + Math.min(6, (node.degree ?? 0) * 0.8);
              const hitRadius = Math.max(baseRadius + 5, 14);
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
            onNodeClick={(n: FGraphNode) => {
              if (n.isCluster) {
                setExpandedClusters((prev) => {
                  const next = new Set(prev);
                  if (next.has(n.id)) {
                    next.delete(n.id);
                  } else {
                    next.add(n.id);
                  }
                  return next;
                });
                setTimeout(() => {
                  fgRef.current?.d3ReheatSimulation();
                }, 50);
                return;
              }
              setSelected(n);
            }}
            onBackgroundClick={() => setSelected(null)}
            onEngineStop={() => {
              if (!hasFocusedInitialRef.current) {
                handleFocusTarget(400);
                hasFocusedInitialRef.current = true;
              }
            }}
            enableNodeDrag
            warmupTicks={60}
            cooldownTime={4000}
            d3VelocityDecay={0.35}
          />
        )}

        {/* Dock flotante de controles (zoom, encuadre, objetivo y filtro de tipos) */}
        <GraphControls
          onZoomIn={handleZoomIn}
          onZoomOut={handleZoomOut}
          onFitView={handleZoomToFit}
          onFocusTarget={() => handleFocusTarget(600)}
          clusterLeaves={clusterLeaves}
          onToggleClusterLeaves={handleToggleClusterLeaves}
          hasClusters={hasClusters}
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
          {clusterLeaves && hasClusters && " · supernodos activos"}
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
