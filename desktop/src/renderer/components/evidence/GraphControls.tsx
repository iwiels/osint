import { Button, Icon, IconButton, Popover, PopoverContent, PopoverTrigger } from "../../ui";
import { FALLBACK_NODE_COLOR, TYPE_COLORS } from "./types";

interface GraphControlsProps {
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFitView: () => void;
  onFocusTarget?: () => void;
  clusterLeaves?: boolean;
  onToggleClusterLeaves?: () => void;
  hasClusters?: boolean;
  availableTypes: string[];
  typeCounts?: Record<string, number>;
  selectedTypes: Set<string>;
  onToggleType: (type: string) => void;
  onSelectAllTypes: () => void;
  onClearTypes: () => void;
}

export function GraphControls({
  onZoomIn,
  onZoomOut,
  onFitView,
  onFocusTarget,
  clusterLeaves = true,
  onToggleClusterLeaves,
  hasClusters = false,
  availableTypes,
  typeCounts = {},
  selectedTypes,
  onToggleType,
  onSelectAllTypes,
  onClearTypes,
}: GraphControlsProps) {
  const isFiltering = selectedTypes.size > 0 && selectedTypes.size < availableTypes.length;

  return (
    <div
      role="toolbar"
      aria-label="Controles del grafo de conocimiento"
      className="anim-rise absolute bottom-3 right-3 z-20 flex items-center gap-1 rounded-md border border-border-base bg-surface-raised-stronger/95 p-1 shadow-paper-sm backdrop-blur-md"
    >
      <IconButton
        name="plus"
        size="small"
        variant="ghost"
        label="Acercar zoom (+)"
        onClick={onZoomIn}
      />
      <IconButton
        name="minus"
        size="small"
        variant="ghost"
        label="Alejar zoom (-)"
        onClick={onZoomOut}
      />
      <Button
        size="small"
        variant="ghost"
        icon="eye"
        onClick={onFitView}
        title="Encuadrar todo el grafo (F)"
      >
        Encuadrar
      </Button>

      {onFocusTarget && (
        <Button
          size="small"
          variant="ghost"
          icon="user"
          onClick={onFocusTarget}
          title="Centrar en el objetivo principal del caso"
        >
          Objetivo
        </Button>
      )}

      {hasClusters && onToggleClusterLeaves && (
        <Button
          size="small"
          variant={clusterLeaves ? "secondary" : "ghost"}
          icon="folder"
          onClick={onToggleClusterLeaves}
          title={
            clusterLeaves
              ? "Supernodos activos: haz clic para expandir todos los subdominios masivos"
              : "Subdominios expandidos: haz clic para agrupar en supernodos limpios"
          }
        >
          {clusterLeaves ? "Supernodos" : "Expandidos"}
        </Button>
      )}

      {availableTypes.length > 0 && (
        <>
          <span className="mx-0.5 h-4 w-px bg-border-weak-base" aria-hidden="true" />
          <Popover>
            <PopoverTrigger asChild>
              <Button
                size="small"
                variant={isFiltering ? "primary" : "ghost"}
                icon="list"
                title="Filtrar por tipo de entidad"
              >
                <span>Tipos</span>
                {isFiltering && (
                  <span className="ml-1 rounded-full bg-surface-raised-stronger px-1.5 py-0.2 font-mono text-[9px] text-text-invert">
                    {selectedTypes.size}
                  </span>
                )}
              </Button>
            </PopoverTrigger>
            <PopoverContent
              align="end"
              sideOffset={8}
              className="w-64 rounded-lg border border-border-strong-base bg-surface-raised-stronger p-3 shadow-pop"
            >
              <div className="mb-2 flex items-center justify-between border-b border-border-weak-base pb-2">
                <span className="label-caps">Filtrar entidades</span>
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={onSelectAllTypes}
                    className="cursor-pointer font-mono text-[10px] text-text-brand hover:underline"
                  >
                    Todos
                  </button>
                  <span className="text-text-weaker">·</span>
                  <button
                    type="button"
                    onClick={onClearTypes}
                    className="cursor-pointer font-mono text-[10px] text-text-weak hover:underline"
                  >
                    Limpiar
                  </button>
                </div>
              </div>

              <div className="flex max-h-56 flex-col gap-1 overflow-auto pr-1">
                {availableTypes.map((type) => {
                  const isChecked = selectedTypes.has(type);
                  const count = typeCounts[type] ?? 0;
                  const color = TYPE_COLORS[type] ?? FALLBACK_NODE_COLOR;

                  return (
                    <button
                      key={type}
                      type="button"
                      onClick={() => onToggleType(type)}
                      className={`flex w-full cursor-pointer items-center justify-between rounded-xs px-2 py-1 text-left font-mono text-[11px] transition-colors ${
                        isChecked
                          ? "bg-surface-raised-strong text-text-strong"
                          : "text-text-weak hover:bg-surface-raised-base hover:text-text-base"
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className="size-2 shrink-0 rounded-xs"
                          style={{ background: color }}
                        />
                        <span className="truncate">{type.toLowerCase()}</span>
                      </div>
                      <span className="mono-data text-[10px] text-text-weaker">
                        {count}
                      </span>
                    </button>
                  );
                })}
              </div>
            </PopoverContent>
          </Popover>
        </>
      )}
    </div>
  );
}
