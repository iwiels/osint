import { useEffect, useId, useMemo, useState } from "react";
import type { ChatMessage } from "../../store";
import { Icon } from "../../ui";
import { ToolItemCard } from "./ToolItemCard";

export interface ToolActivityGroupProps {
  tools: ChatMessage[];
}

export function ToolActivityGroup({ tools }: ToolActivityGroupProps) {
  const panelId = useId();
  const runningTools = tools.filter((t) => t.status === "running");
  const isAnyRunning = runningTools.length > 0;
  const hasErrors = tools.some((t) => t.status === "error");
  // Un grupo donde todo se interrumpió no es un grupo exitoso: sin esto se
  // pintaría con el punto verde de "completado".
  const hasInterrupted = tools.some((t) => t.status === "interrupted");

  // Live runs open automatically so the analyst sees real-time operations;
  // when finished, user preference is preserved.
  const [open, setOpen] = useState(isAnyRunning);

  useEffect(() => {
    if (isAnyRunning) setOpen(true);
  }, [isAnyRunning]);

  const distinctToolNames = useMemo(() => {
    return Array.from(new Set(tools.map((t) => t.tool).filter(Boolean))) as string[];
  }, [tools]);

  const completedCount = tools.length - runningTools.length;

  return (
    <div
      data-component="tool-activity-group"
      className="overflow-hidden rounded-sm border border-border-weak-base bg-surface-raised-base shadow-paper-xs transition-all"
    >
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen(!open)}
        className="flex w-full cursor-pointer items-center justify-between px-3 py-2 text-left transition-colors hover:bg-surface-base-hover"
      >
        <div className="flex min-w-0 items-center gap-2">
          {isAnyRunning ? (
            <span className="size-2 shrink-0 rounded-full bg-brand animate-dot-live shadow-[0_0_6px_var(--brand)]" />
          ) : hasErrors ? (
            <span className="size-2 shrink-0 rounded-full bg-critical" />
          ) : hasInterrupted ? (
            <span className="size-2 shrink-0 rounded-full bg-text-weaker" />
          ) : (
            <span className="size-2 shrink-0 rounded-full bg-success" />
          )}

          <div className="truncate font-mono text-[11px] font-medium tracking-wide text-text-strong">
            {isAnyRunning ? (
              <span className="text-text-brand">
                Ejecutando ({completedCount}/{tools.length}) ·{" "}
                {runningTools[0]?.tool || "operación"}…
              </span>
            ) : (
              <span>
                {tools.length}{" "}
                {tools.length === 1 ? "operación completada" : "operaciones completadas"}{" "}
                {distinctToolNames.length > 0 && (
                  <span className="text-text-weak">
                    ({distinctToolNames.join(", ")})
                  </span>
                )}
              </span>
            )}
          </div>
        </div>

        <div className="ml-2 flex shrink-0 items-center gap-2">
          <span className="flex items-center gap-1 font-mono text-[10px] text-text-weak hover:text-text-brand">
            {open ? "ocultar" : "ver traza"}
            <Icon name={open ? "chevron-up" : "chevron-down"} size="small" />
          </span>
        </div>
      </button>

      {open && (
        <div
          id={panelId}
          className="flex flex-col gap-1.5 border-t border-dashed border-border-weak-base bg-surface-inset-base/30 p-2.5"
        >
          {tools.map((t) => (
            <ToolItemCard key={t.id} message={t} />
          ))}
        </div>
      )}
    </div>
  );
}
export default ToolActivityGroup;
