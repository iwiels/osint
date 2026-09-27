import type { TimelineEvent, TimelineReport } from "@specter/sdk";
import { Tag } from "../../ui";
import { EmptyState } from "./EmptyState";
import { KIND_COLORS } from "./types";

interface TimelineViewProps {
  report: TimelineReport | null;
}

export function TimelineView({ report }: TimelineViewProps) {
  if (!report || report.total_events === 0) {
    return (
      <EmptyState
        label="timeline vacío"
        body="Sin actividad registrada todavía. El timeline se llena con cada recolección, evidencia y bloque del ledger."
      />
    );
  }

  const max = Math.max(...report.buckets.map((b) => b.count), 1);
  const burstKeys = new Set(report.bursts.map((b) => b.bucket));
  const recent = [...report.events].reverse().slice(0, 60);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Resumen superior del rango temporal */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border-weak-base bg-surface-raised-base/50 px-3.5 py-2 font-mono text-[10.5px] text-text-weak">
        <span className="mono-data font-medium text-text-strong">
          {report.total_events} eventos
        </span>
        <span className="mono-data">
          {report.first_activity?.slice(0, 19).replace("T", " ")} →{" "}
          {report.last_activity?.slice(0, 19).replace("T", " ")}
        </span>
        <span className="mono-data">{report.span_hours ?? 0} h de ventana</span>
        {report.bursts.length > 0 && (
          <Tag tone="warning" size="normal">
            {report.bursts.length} ráfaga(s) de actividad
          </Tag>
        )}
        <span className="ml-auto flex items-center gap-2.5">
          {Object.entries(KIND_COLORS).map(([kind, color]) => (
            <span key={kind} className="inline-flex items-center gap-1 font-mono text-[10.5px]">
              <span className="inline-block size-[7px] rounded-xs" style={{ background: color }} />
              {kind}
            </span>
          ))}
        </span>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-auto">
        {/* Histograma temporal por buckets */}
        <div className="flex flex-col gap-1.5 border-b border-border-weak-base bg-background-base/50 px-3.5 py-2.5">
          {report.buckets.map((b) => (
            <div key={b.bucket} className="flex items-center gap-2">
              <span className="w-[104px] shrink-0 font-mono text-[10.5px] text-text-weak">
                {b.bucket.replace("T", " ")}
              </span>
              <div className="flex h-[14px] flex-1 items-stretch gap-px overflow-hidden rounded-xs bg-surface-inset-base">
                <Segment
                  count={b.entities}
                  total={max}
                  color={KIND_COLORS.entity}
                  title={`${b.entities} entidades`}
                />
                <Segment
                  count={b.evidences}
                  total={max}
                  color={KIND_COLORS.evidence}
                  title={`${b.evidences} evidencias`}
                />
                <Segment
                  count={b.ledger_blocks}
                  total={max}
                  color={KIND_COLORS.ledger}
                  title={`${b.ledger_blocks} bloques`}
                />
              </div>
              <span className="mono-data w-[54px] shrink-0 text-right text-[10.5px] text-text-base">
                {b.count}
              </span>
              <span className="w-[14px] shrink-0 text-center font-mono text-[11px] font-bold text-text-warning">
                {burstKeys.has(b.bucket) ? "!" : ""}
              </span>
            </div>
          ))}
        </div>

        {/* Tabla de cronología de eventos recientes */}
        <table className="w-full border-collapse text-[12px]">
          <caption className="sr-only">Eventos del timeline forense del caso</caption>
          <thead>
            <tr>
              {["Timestamp", "Tipo", "Detalle", "Sello"].map((h) => (
                <th
                  key={h}
                  scope="col"
                  className="sticky top-0 z-10 border-b border-border-weak-base bg-surface-raised-base px-3 py-2 text-left font-mono text-[10px] font-medium tracking-[0.18em] text-text-weak uppercase"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {recent.map((e, i) => (
              <tr
                key={`${e.kind}-${e.artifact_id}-${i}`}
                className="border-b border-border-weak-base/50 transition-colors duration-100 hover:bg-surface-raised-base/60"
              >
                <td className="mono-data px-3 py-1.5 text-[11px] whitespace-nowrap text-text-base">
                  {e.timestamp.slice(0, 19).replace("T", " ")}
                </td>
                <td className="px-3 py-1.5">
                  <span
                    className="inline-flex items-center gap-1.5 font-mono text-[10.5px] text-text-weak"
                    title={e.kind}
                  >
                    <span
                      className="inline-block size-[7px] rounded-xs"
                      style={{ background: KIND_COLORS[e.kind] }}
                    />
                    {e.type ?? e.collector ?? e.kind}
                  </span>
                </td>
                <td className="mono-data max-w-[420px] truncate px-3 py-1.5 text-[11px] text-text-strong">
                  {describeEvent(e)}
                </td>
                <td className="px-3 py-1.5 font-mono text-[10.5px]">
                  {e.kind === "ledger" ? (
                    e.signed ? (
                      <span className="mono-data font-semibold text-text-success">hmac</span>
                    ) : (
                      <span className="text-text-weaker">sin firma</span>
                    )
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function describeEvent(e: TimelineEvent): string {
  if (e.kind === "ledger") return `${e.action ?? ""} · #${e.block_index ?? "?"}`;
  if (e.kind === "evidence")
    return `${e.source_url ?? ""} · ${e.payload_hash?.slice(0, 12) ?? ""}`;
  return `${e.value ?? e.artifact_id}${e.confidence != null ? ` · conf ${e.confidence}` : ""}`;
}

function Segment({
  count,
  total,
  color,
  title,
}: {
  count: number;
  total: number;
  color: string;
  title: string;
}) {
  if (count === 0) return null;
  return (
    <span
      title={title}
      style={{ background: color, width: `${(count / total) * 100}%` }}
      className="min-w-[3px] opacity-85 transition-opacity hover:opacity-100"
    />
  );
}
