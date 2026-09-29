import { useState } from "react";
import type { CaseCorrelations, WraithClient } from "@wraith/sdk";
import { Button, Tag } from "../../ui";
import { EmptyState } from "./EmptyState";
import { FALLBACK_NODE_COLOR, TYPE_COLORS } from "./types";

interface CorrelationsViewProps {
  report: CaseCorrelations | null;
  caseId: string;
  client: WraithClient;
  onChanged: () => Promise<void>;
}

export function CorrelationsView({
  report,
  caseId,
  client,
  onChanged,
}: CorrelationsViewProps) {
  const [linking, setLinking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!report) {
    return <EmptyState label="correlaciones" body="Cargando vínculos del caso…" />;
  }

  const cross = report.cross_case;
  const candidates = report.identity_candidates.candidates;

  const link = async (candidateIndex: number) => {
    const candidate = candidates[candidateIndex];
    const [a, b] = candidate.entities;
    setLinking(`${a.entity_id}->${b.entity_id}`);
    setError(null);
    try {
      await client.callTool("link_entities", {
        case_id: caseId,
        source_id: a.entity_id,
        target_id: b.entity_id,
        relation_type: candidate.suggested_relation,
        confidence: candidate.score,
        rationale: `Resolución de identidad (score ${candidate.score}): ${candidate.reason}`,
      });
      await onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLinking(null);
    }
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-auto p-4">
      {/* Sección 1: Artefactos compartidos entre investigaciones */}
      <section>
        <div className="label-caps mb-2.5">
          artefactos compartidos con otros casos · {cross.total_shared_entities}
        </div>
        {cross.matches.length === 0 ? (
          <p className="text-[12.5px] text-text-weak">
            Ningún artefacto de este caso aparece todavía en otra investigación.
          </p>
        ) : (
          <div className="flex flex-col gap-2">
            {cross.matches.map((m) => (
              <div
                key={m.entity_id}
                className="flex items-center gap-3 rounded-md border border-border-weak-base bg-surface-raised-base px-3 py-2.5 transition-colors hover:bg-surface-raised-strong"
              >
                <span
                  className="size-2 shrink-0 rounded-xs"
                  style={{ background: TYPE_COLORS[m.type] ?? FALLBACK_NODE_COLOR }}
                />
                <div className="min-w-0 flex-1">
                  <span className="mono-data block truncate text-[12px] font-medium text-text-strong">
                    {m.value}
                  </span>
                  <span className="mono-data text-[10px] tracking-wide text-text-weak uppercase">
                    {m.type} · conf {Math.round(m.confidence * 100)}%
                  </span>
                </div>
                <div className="flex flex-wrap justify-end gap-1.5">
                  {m.case_ids.map((id) => (
                    <Tag
                      key={id}
                      tone={id === cross.anchor_case ? "brand" : "neutral"}
                      size="normal"
                      className="mono-data text-[10.5px]"
                    >
                      {id.replace("case-", "")}
                    </Tag>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Sección 2: Candidatos de resolución de identidad */}
      <section>
        <div className="label-caps mb-2.5 flex flex-wrap items-center gap-2">
          <span>resolución de identidad · {report.identity_candidates.total_candidates} candidatos</span>
          <span className="mono-data text-[10px] text-text-weaker lowercase">
            (umbral {report.identity_candidates.min_score} · {report.identity_candidates.analyzed_entities} identidades analizadas)
          </span>
        </div>

        {error && (
          <div className="mb-2.5 rounded-md border border-border-critical-base bg-surface-critical-weak p-2.5 text-[12px] text-text-critical">
            {error}
          </div>
        )}

        {candidates.length === 0 ? (
          <p className="text-[12.5px] text-text-weak">
            Sin coincidencias de handle entre alias, emails y perfiles de este caso.
          </p>
        ) : (
          <div className="flex flex-col gap-2">
            {candidates.map((c, i) => {
              const pairKey = `${c.entities[0].entity_id}->${c.entities[1].entity_id}`;
              const isLinkingThis = linking === pairKey;

              return (
                <div
                  key={`${c.entities[0].entity_id}-${c.entities[1].entity_id}`}
                  className="flex flex-col gap-2 rounded-md border border-border-weak-base bg-surface-raised-base p-3 transition-colors hover:border-border-base"
                >
                  <div className="flex items-center gap-3">
                    <span className="mono-data text-[12px] font-bold text-text-success">
                      {(c.score * 100).toFixed(0)}%
                    </span>
                    <span className="min-w-0 flex-1 truncate text-[12.5px] text-text-base">
                      {c.reason}
                    </span>
                    <Button
                      size="small"
                      variant="secondary"
                      icon="link"
                      disabled={linking != null}
                      onClick={() => link(i)}
                    >
                      {isLinkingThis ? "Vinculando…" : `Vincular ${c.suggested_relation}`}
                    </Button>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 border-t border-border-weak-base/50 pt-2">
                    {c.entities.map((e) => (
                      <span
                        key={e.entity_id}
                        className="inline-flex items-center gap-1.5 rounded-xs border border-border-weak-base bg-surface-raised-strong px-2 py-0.5 font-mono text-[10.5px] text-text-base"
                      >
                        <span
                          className="size-1.5 shrink-0 rounded-xs"
                          style={{ background: TYPE_COLORS[e.type] ?? FALLBACK_NODE_COLOR }}
                        />
                        <span className="truncate max-w-[160px]">{e.value}</span>
                      </span>
                    ))}
                    <span className="mono-data ml-auto text-[10px] text-text-weaker">
                      clave: {c.normalized_key}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
