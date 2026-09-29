import { Icon, IconButton, Tag } from "../../ui";
import { FALLBACK_NODE_COLOR, TYPE_COLORS, type FGraphNode } from "./types";

interface GraphNodeDetailProps {
  node: FGraphNode;
  neighbors: FGraphNode[];
  onSelectNode: (node: FGraphNode) => void;
  onClose: () => void;
}

export function GraphNodeDetail({
  node,
  neighbors,
  onSelectNode,
  onClose,
}: GraphNodeDetailProps) {
  const isWebResource =
    node.type === "DOMAIN" ||
    node.type === "SUBDOMAIN" ||
    node.type === "SOCIAL_PROFILE" ||
    node.value.startsWith("http://") ||
    node.value.startsWith("https://");

  const handleOpenExternal = () => {
    const url =
      node.value.startsWith("http://") || node.value.startsWith("https://")
        ? node.value
        : `https://${node.value}`;

    const desktop = (
      window as unknown as {
        wraithDesktop?: { openExternal?: (u: string) => Promise<boolean> };
      }
    ).wraithDesktop;

    if (desktop?.openExternal) {
      void desktop.openExternal(url);
    } else {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  };

  const nodeColor = TYPE_COLORS[node.type] ?? FALLBACK_NODE_COLOR;
  const confPct = Math.round(node.confidence * 100);

  return (
    <div
      role="dialog"
      aria-label={`Detalle de la entidad: ${node.value}`}
      className="anim-rise absolute bottom-3 left-3 z-20 w-[320px] max-w-[calc(100%-24px)] rounded-md border border-border-strong-base bg-surface-raised-stronger/95 p-3.5 shadow-paper-sm backdrop-blur-md"
    >
      {/* Cabecera del detalle */}
      <div className="mb-2 flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="mb-1 flex items-center gap-1.5">
            <span
              className="inline-block size-2 rounded-xs shrink-0"
              style={{ background: nodeColor }}
              aria-hidden="true"
            />
            <Tag size="normal" tone="neutral" className="mono-data text-[10px] uppercase">
              {node.type}
            </Tag>
            <span className="mono-data text-[10px] text-text-weak">
              conf {confPct}%
            </span>
          </div>

          <div
            className="mono-data select-all text-[12px] font-semibold text-text-strong break-all"
            title={node.value}
          >
            {node.value}
          </div>

          {isWebResource && (
            <button
              type="button"
              className="mt-1.5 inline-flex cursor-pointer items-center gap-1 font-mono text-[11px] text-text-brand transition-colors hover:underline"
              onClick={handleOpenExternal}
              title="Abrir en navegador web externo"
            >
              <Icon name="external-link" size="small" />
              <span>Abrir en navegador</span>
            </button>
          )}
        </div>

        <IconButton
          name="close"
          size="small"
          variant="ghost"
          label="Cerrar detalle del nodo"
          onClick={onClose}
        />
      </div>

      {/* Atributos y métricas */}
      <dl className="my-2.5 grid grid-cols-[76px_1fr] gap-x-2 gap-y-1 rounded border border-border-weak-base bg-surface-inset-base/60 p-2 font-mono text-[11px]">
        <dt className="text-text-weak">conexiones</dt>
        <dd className="mono-data text-text-strong font-medium">{node.degree}</dd>
        <dt className="text-text-weak">visto</dt>
        <dd className="mono-data text-text-base truncate">
          {node.first_seen.slice(0, 10)} → {node.last_seen.slice(0, 10)}
        </dd>
      </dl>

      {/* Lista de vecinos interconectados */}
      <div>
        <div className="label-caps mb-1.5 flex items-center justify-between">
          <span>vecinos</span>
          <span className="mono-data text-[10px] text-text-weaker">
            {neighbors.length}
          </span>
        </div>

        {neighbors.length === 0 ? (
          <p className="font-mono text-[10.5px] text-text-weak">Sin conexiones directas</p>
        ) : (
          <div className="flex max-h-24 flex-wrap gap-1.5 overflow-auto pr-0.5">
            {neighbors.map((nb) => (
              <button
                key={nb.id}
                type="button"
                className="inline-flex cursor-pointer items-center gap-1 rounded-xs border border-border-weak-base bg-surface-raised-strong px-1.5 py-0.5 font-mono text-[10.5px] text-text-base transition-colors hover:border-border-brand-base hover:bg-surface-raised-base hover:text-text-brand"
                onClick={() => onSelectNode(nb)}
                title={`${nb.type}: ${nb.value}`}
              >
                <span
                  className="size-1.5 shrink-0 rounded-xs"
                  style={{ background: TYPE_COLORS[nb.type] ?? FALLBACK_NODE_COLOR }}
                />
                <span className="truncate max-w-[140px]">
                  {nb.value.length > 18 ? `${nb.value.slice(0, 17)}…` : nb.value}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
