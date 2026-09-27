import { useId, useMemo, useState } from "react";
import type { ChatMessage } from "../../store";
import { Button, Icon } from "../../ui";

export interface ToolItemCardProps {
  message: ChatMessage;
}

export function ToolItemCard({ message }: ToolItemCardProps) {
  const [detailOpen, setDetailOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const detailId = useId();

  const isRunning = message.status === "running";
  const isError = message.status === "error";

  const copyContent = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!message.content) return;
    try {
      await navigator.clipboard.writeText(message.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard access error
    }
  };

  const summary = useMemo(() => {
    if (isRunning) return "En ejecución…";
    if (message.args && typeof message.args === "object") {
      const rec = message.args as Record<string, unknown>;
      const primary = rec.query || rec.url || rec.target || rec.term || rec.domain || rec.name || rec.username;
      if (primary && typeof primary === "string") {
        return `"${primary.length > 40 ? primary.slice(0, 40) + "…" : primary}"`;
      }
    }
    const clean = (message.content || "").trim();
    if (!clean) return "Completado sin retorno";
    if (clean.startsWith("{") || clean.startsWith("[")) {
      try {
        const parsed = JSON.parse(clean);
        if (typeof parsed === "object" && parsed !== null) {
          const keys = Object.keys(parsed);
          return `resultado (${keys.length} campos: ${keys.slice(0, 2).join(", ")})`;
        }
      } catch {
        // fallback
      }
    }
    const sanitized = clean.replace(/^[{\[\s\n]+/, "").split("\n")[0].trim();
    if (!sanitized) return "Completado";
    return sanitized.length > 45 ? `${sanitized.slice(0, 45)}…` : sanitized;
  }, [message.content, message.args, isRunning]);

  return (
    <div
      data-component="tool-item-card"
      className="overflow-hidden rounded-xs border border-border-weak-base bg-surface-raised-base transition-colors"
    >
      <button
        type="button"
        aria-expanded={detailOpen}
        aria-controls={detailId}
        onClick={() => setDetailOpen(!detailOpen)}
        className="flex w-full cursor-pointer items-center justify-between px-2.5 py-1.5 text-left transition-colors hover:bg-surface-base-hover"
      >
        <div className="flex min-w-0 items-center gap-2">
          {isRunning ? (
            <span className="size-1.5 shrink-0 rounded-full bg-brand animate-dot-live shadow-[0_0_6px_var(--brand)]" />
          ) : isError ? (
            <span className="size-1.5 shrink-0 rounded-full bg-critical" />
          ) : (
            <span className="size-1.5 shrink-0 rounded-full bg-success" />
          )}

          <span className="font-mono text-[10px] font-semibold tracking-wider text-text-strong uppercase">
            {message.tool || "operación"}
          </span>

          <span className="truncate font-mono text-[10px] text-text-weak">{summary}</span>
        </div>

        <span className="ml-1.5 shrink-0 text-text-weak">
          <Icon name={detailOpen ? "chevron-up" : "chevron-down"} size="small" />
        </span>
      </button>

      {detailOpen && (
        <div
          id={detailId}
          className="border-t border-border-weak-base bg-background-base p-2.5"
        >
          {message.args != null && (
            <div className="mb-2.5 border-b border-border-weak-base pb-2">
              <span className="font-mono text-[9px] font-semibold tracking-wider text-text-brand uppercase">
                Parámetros de entrada:
              </span>
              <pre className="mt-1 max-h-36 overflow-auto rounded border border-border-weak-base bg-surface-inset-base p-2 font-mono text-[10.5px] leading-relaxed break-all whitespace-pre-wrap text-text-weak select-text">
                {typeof message.args === "object"
                  ? JSON.stringify(message.args, null, 2)
                  : String(message.args)}
              </pre>
            </div>
          )}

          <div className="flex items-center justify-between">
            <span className="font-mono text-[9px] font-semibold tracking-wider text-text-weak uppercase">
              Resultado ({message.content.length} caracteres)
            </span>
            {message.content && (
              <Button
                variant="ghost"
                size="small"
                onClick={copyContent}
                className="h-5 px-1.5 font-mono text-[10px] text-text-weak hover:text-text-brand"
                title="Copiar resultado"
              >
                <Icon name={copied ? "check" : "copy"} size="small" tone={copied ? "success" : "weak"} />
                <span>{copied ? "Copiado" : "Copiar"}</span>
              </Button>
            )}
          </div>

          <pre className="mt-1.5 max-h-56 overflow-auto rounded border border-border-weak-base bg-surface-inset-base p-2 font-mono text-[11px] leading-relaxed break-all whitespace-pre-wrap text-text-strong select-text">
            {message.content || "(sin salida)"}
          </pre>
        </div>
      )}
    </div>
  );
}
export default ToolItemCard;
