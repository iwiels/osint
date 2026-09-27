import { useMemo, useState } from "react";
import type { AgentSession } from "@specter/sdk";
import { Icon, IconButton, Tag, TextField } from "../../ui";

export interface SessionHistoryProps {
  sessions: AgentSession[];
  currentSessionId?: string | null;
  onSelectSession: (session: AgentSession) => void;
  onDeleteSession: (sessionId: string) => void;
  isOpen: boolean;
  onToggle: () => void;
}

export function SessionHistory({
  sessions,
  currentSessionId,
  onSelectSession,
  onDeleteSession,
  isOpen,
  onToggle,
}: SessionHistoryProps) {
  const [filter, setFilter] = useState("");

  const filteredSessions = useMemo(() => {
    if (!filter.trim()) return sessions;
    const q = filter.trim().toLowerCase();
    return sessions.filter(
      (s) =>
        (s.prompt || "").toLowerCase().includes(q) ||
        s.session_id.toLowerCase().includes(q) ||
        (s.provider || "").toLowerCase().includes(q) ||
        (s.model || "").toLowerCase().includes(q),
    );
  }, [sessions, filter]);

  return (
    <div
      data-component="session-history-drawer"
      className="shrink-0 border-b border-border-weak-base bg-surface-raised-base transition-colors"
    >
      <button
        type="button"
        aria-expanded={isOpen}
        onClick={onToggle}
        className="flex w-full cursor-pointer items-center justify-between px-3 py-2 text-left transition-colors hover:bg-surface-raised-base-hover"
      >
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <Icon name="clock" size="small" tone="weak" />
          <span className="truncate font-mono text-[10.5px] font-semibold tracking-wider text-text-weak uppercase">
            Sesiones ({sessions.length})
          </span>
        </div>
        <span
          aria-hidden="true"
          data-open={isOpen ? "" : undefined}
          className="flex size-5 shrink-0 items-center justify-center rounded-xs text-text-weak transition-transform duration-base data-[open]:rotate-180"
        >
          <Icon name="chevron-down" size="small" />
        </span>
      </button>

      {isOpen && (
        <div className="animate-rise max-h-72 overflow-y-auto px-3.5 pb-3">
          {sessions.length === 0 ? (
            <p className="py-3 text-[12px] leading-relaxed text-text-weak">
              Sin conversaciones guardadas todavía. Cada run del agente queda registrado automáticamente
              en el motor forense.
            </p>
          ) : (
            <>
              <div className="pt-1 pb-2">
                <TextField
                  size="small"
                  aria-label="Buscar en el historial"
                  placeholder="Buscar sesión por objetivo, modelo o ID…"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                />
              </div>

              {filteredSessions.length === 0 ? (
                <p className="py-2 text-[12px] text-text-weak">
                  No se encontraron sesiones que coincidan con &quot;{filter}&quot;.
                </p>
              ) : (
                <div className="flex flex-col gap-1.5 pt-1">
                  {filteredSessions.map((s) => {
                    const isSelected = currentSessionId === s.session_id;
                    const statusTone =
                      s.status === "completed"
                        ? "success"
                        : s.status === "error"
                          ? "critical"
                          : "warning";

                    return (
                      <div
                        key={s.session_id}
                        className={`flex items-stretch justify-between gap-2 rounded border p-2 transition-colors ${
                          isSelected
                            ? "border-border-brand-base bg-surface-brand-weak/30"
                            : "border-border-weak-base bg-surface-raised-strong/60 hover:border-border-strong-base hover:bg-surface-raised-strong"
                        }`}
                      >
                        <button
                          type="button"
                          onClick={() => onSelectSession(s)}
                          className="min-w-0 flex-1 cursor-pointer text-left"
                          title={`${s.session_id} · ${s.provider}/${s.model}`}
                        >
                          <div className="truncate text-[12.5px] font-medium text-text-strong">
                            {s.prompt || "(sin objetivo especificado)"}
                          </div>
                          <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[10px] text-text-weak">
                            <span>{s.started_at.slice(0, 16).replace("T", " ")}</span>
                            <Tag tone={statusTone} size="normal">
                              {s.status}
                            </Tag>
                            <span>
                              {s.provider}/{s.model}
                            </span>
                            <span>
                              {s.iterations} it · {s.tools_used} tools
                            </span>
                          </div>
                        </button>

                        <div className="flex shrink-0 items-center">
                          <IconButton
                            name="trash"
                            label={`Borrar sesión ${s.session_id}`}
                            size="small"
                            variant="ghost"
                            onClick={(e) => {
                              e.stopPropagation();
                              onDeleteSession(s.session_id);
                            }}
                            className="text-text-weak hover:text-text-critical"
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
export default SessionHistory;
