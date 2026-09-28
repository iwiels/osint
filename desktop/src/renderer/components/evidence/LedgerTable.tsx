import { useState } from "react";
import type {
  LedgerAttestation,
  LedgerBlock,
  LedgerReport,
  SpecterClient,
} from "@specter/sdk";
import { Button, Tag } from "../../ui";
import { EmptyState } from "./EmptyState";
import { STATUS_LABEL, STATUS_TONE } from "./types";

interface LedgerTableProps {
  report: LedgerReport | null;
  attestation: LedgerAttestation | null;
  client: SpecterClient;
  caseId: string;
  busy: boolean;
  onSeal?: () => Promise<void>;
}

export function LedgerTable({
  report,
  attestation,
  client,
  caseId,
  busy,
  onSeal,
}: LedgerTableProps) {
  const blocks: LedgerBlock[] = report?.blocks ?? [];
  const [exporting, setExporting] = useState<"html" | "md" | null>(null);
  const [copied, setCopied] = useState(false);

  const exportDossier = async (format: "html" | "md") => {
    setExporting(format);
    try {
      await client.callTool("export_case_dossier", { case_id: caseId, format });
    } finally {
      setExporting(null);
    }
  };

  const copyAttestation = async () => {
    if (!attestation?.attestation) return;
    const json = JSON.stringify(attestation.attestation, null, 2);
    try {
      await navigator.clipboard?.writeText(json);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.warn("[specter] error al copiar atestación:", err);
    }
  };

  if (blocks.length === 0) {
    return (
      <EmptyState
        label="cadena de custodia"
        body="Sin bloques aún. Cada recolección del agente sellará un bloque SHA-256 aquí."
      />
    );
  }

  const status = report?.signature_status;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Barra de cabecera con estado criptográfico y acciones de exportación */}
      <div className="flex shrink-0 flex-wrap items-center gap-3 border-b border-border-weak-base bg-surface-raised-base/50 px-3.5 py-2">
        {status === "SEALED" ? (
          <span
            className="stamp-badge"
            title={
              report?.key_id
                ? `key_id ${report.key_id} · cadena íntegra y sellada`
                : "Cadena íntegra y firmada con HMAC-SHA256; protege la clave y la base de datos"
            }
          >
            <span className="size-1.5 rounded-full bg-[var(--terracotta)]" />
            <span>CHAIN_SEALED // HMAC-SHA256</span>
          </span>
        ) : status ? (
          <Tag
            tone={STATUS_TONE[status] ?? "warning"}
            size="normal"
            className="mono-data tracking-wide"
            title={
              report?.key_id
                ? `key_id ${report.key_id} · cadena válida: ${report.valid}`
                : "El caso no tiene clave de firma: la cadena SHA-256 se verifica, el sello no existe"
            }
          >
            custodia · {STATUS_LABEL[status] ?? status}
          </Tag>
        ) : null}

        {status && status !== "SEALED" && status !== "INVALID" && (
          <span
            className="mono-data text-[10px] text-text-warning"
            title="Los hashes encadenan bien, pero los bloques no llevan firma HMAC: cualquiera con acceso a la BD podría reescribir historia"
          >
            íntegra pero sin sellar
          </span>
        )}

        <div className="ml-auto flex items-center gap-1.5">
          <span className="label-caps mr-1 hidden sm:inline">dossier</span>
          <Button
            size="small"
            variant="secondary"
            icon="download"
            onClick={() => exportDossier("html")}
            disabled={busy || exporting !== null}
            title="Exportar dossier de investigación en HTML"
          >
            {exporting === "html" ? "Exportando…" : "HTML"}
          </Button>
          <Button
            size="small"
            variant="secondary"
            icon="download"
            onClick={() => exportDossier("md")}
            disabled={busy || exporting !== null}
            title="Exportar dossier de investigación en Markdown"
          >
            {exporting === "md" ? "Exportando…" : "MD"}
          </Button>
          {onSeal && (
            <Button
              size="small"
              variant="primary"
              icon="shield"
              onClick={onSeal}
              disabled={busy || exporting !== null}
              title="Emite una atestación HMAC; validarla requiere compartir la clave secreta"
            >
              Sellar
            </Button>
          )}
        </div>
      </div>

      {/* Tabla de bloques auditables con estilo de legajo archival */}
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full border-collapse text-[12px]">
          <caption className="sr-only">Cadena de custodia sellada: bloques del ledger</caption>
          <thead>
            <tr>
              {["#", "Timestamp", "Collector", "Acción", "Hash SHA-256", "Firma HMAC"].map((h) => (
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
            {blocks.map((b) => (
              <tr
                key={`${b.case_id}-${b.block_index}`}
                className="border-b border-border-weak-base/50 transition-colors duration-100 hover:bg-surface-raised-base/60"
              >
                <td className="px-3 py-1.5">
                  <span className="inline-flex size-5 items-center justify-center rounded-xs border border-border-weak-base bg-surface-inset-base font-mono text-[10px] font-semibold text-text-weaker tabular-nums">
                    {b.block_index}
                  </span>
                </td>
                <td className="mono-data px-3 py-1.5 text-[11px] text-text-base whitespace-nowrap">
                  {b.timestamp.slice(0, 19).replace("T", " ")}
                </td>
                <td className="mono-data px-3 py-1.5 text-text-strong font-medium">
                  {b.collector}
                </td>
                <td className="mono-data px-3 py-1.5 text-[11px] text-text-base">
                  {b.action}
                </td>
                <td className="px-3 py-1.5" title={b.block_hash}>
                  <span className="mono-data select-all text-[11px] font-medium text-text-success">
                    {b.block_hash.slice(0, 14)}…
                  </span>
                </td>
                <td className="px-3 py-1.5" title={b.signature ?? "Bloque sin firma"}>
                  {b.signature ? (
                    <div className="flex items-center gap-1.5">
                      <span className="stamp-badge !px-1.5 !py-0.2 !text-[9px]">
                        SEALED
                      </span>
                      <span className="mono-data select-all text-[11px] font-medium text-text-brand">
                        {b.signature.slice(0, 12)}…
                      </span>
                    </div>
                  ) : (
                    <span className="mono-data text-[11px] text-text-weaker">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Tarjeta de atestación criptográfica HMAC con sello de verificación forense */}
      {attestation?.attestation?.signature && (
        <div className="shrink-0 border-t border-border-weak-base bg-surface-raised-base/80 px-3.5 py-3 shadow-paper-xs">
          <div className="mb-2 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="stamp-badge">
                <span className="size-1.5 rounded-full bg-[var(--terracotta)] animate-pulse" />
                <span>CHAIN_VERIFIED // HMAC-SHA256</span>
              </span>
              <span className="label-caps font-mono text-[10px] text-text-weak">
                KEY_ID // {attestation.key_id} · {attestation.algorithm}
              </span>
            </div>
            <span className="mono-data text-[10px] text-text-weaker">
              {blocks.length} BLOQUES FORENSES SELLADOS
            </span>
          </div>
          <div className="flex items-center gap-2">
            <code className="mono-data min-w-0 flex-1 truncate rounded border border-border-weak-base bg-surface-inset-base px-2.5 py-1.5 text-[10.5px] text-text-success select-all shadow-paper-xs">
              {attestation.attestation.signature}
            </code>
            <Button
              size="small"
              variant="secondary"
              icon={copied ? "check" : "copy"}
              onClick={copyAttestation}
              title="Copiar atestación completa en formato JSON"
            >
              {copied ? "Copiado" : "Copiar"}
            </Button>
          </div>
          <p className="mt-1.5 text-[11px] leading-snug text-text-weak">
            Entrégala junto al dossier: un tercero con la clave recomprueba el HMAC del payload sin
            acceso a la base forense.
          </p>
        </div>
      )}
    </div>
  );
}
