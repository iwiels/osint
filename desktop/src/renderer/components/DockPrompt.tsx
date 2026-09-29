/**
 * DockPrompt - componente anclado directamente sobre el área de entrada del compositor.
 * Inspirado en OpenCode Session UI (dock-prompt.tsx, session-permission-dock.tsx, session-question-dock.tsx).
 * Permite al analista autorizar permisos o responder preguntas del agente sin que un
 * diálogo modal bloquee el grafo forense ni la vista del caso.
 */

import React, { useEffect, useRef, useState } from "react";
import type {
  AnalystQuestion,
  PermissionRequestPayload,
  QuestionAskedPayload,
  WraithClient,
} from "@wraith/sdk";
import { WraithError } from "@wraith/sdk";
import { useStore } from "../store";
import { Button } from "../ui/button";
import { TextField } from "../ui/text-field";
import { Tag } from "../ui/tag";
import { Checkbox } from "../ui/checkbox";
import { IconButton } from "../ui/icon-button";
import { DockSurface } from "../ui/dock-surface";

export { DockSurface };

export interface DockPromptProps {
  kind: "question" | "permission";
  header: React.ReactNode;
  children: React.ReactNode;
  footer: React.ReactNode;
  className?: string;
  onKeyDown?: React.KeyboardEventHandler<HTMLDivElement>;
}

export function DockShell({
  children,
  className = "",
  "data-slot": dataSlot,
}: {
  children: React.ReactNode;
  className?: string;
  "data-slot"?: string;
}) {
  return (
    <div
      data-dock-surface="shell"
      data-slot={dataSlot}
      className={`relative z-10 flex flex-col gap-2 p-3 ${className}`}
    >
      {children}
    </div>
  );
}

export function DockTray({
  children,
  className = "",
  "data-slot": dataSlot,
}: {
  children: React.ReactNode;
  className?: string;
  "data-slot"?: string;
}) {
  return (
    <div
      data-dock-surface="tray"
      data-slot={dataSlot}
      className={`relative z-0 flex items-center justify-between border-t border-border-weak-base bg-surface-raised-base/90 px-3 py-2 text-[11px] text-text-weak ${className}`}
    >
      {children}
    </div>
  );
}

export function DockPrompt({
  kind,
  header,
  children,
  footer,
  className = "",
  onKeyDown,
}: DockPromptProps) {
  const slot = (name: string) => `${kind}-${name}`;

  return (
    <div
      data-component="dock-prompt"
      data-kind={kind}
      onKeyDown={onKeyDown}
      tabIndex={-1}
      className={`anim-rise flex w-full shrink-0 flex-col border-t border-border-strong-base bg-surface-raised-strong focus:outline-none ${
        kind === "permission"
          ? "border-t-2 border-t-warning shadow-[0_-4px_16px_rgba(251,191,36,0.12)]"
          : "border-t-2 border-t-brand shadow-[0_-4px_16px_rgba(56,189,248,0.12)]"
      } ${className}`}
    >
      <DockShell data-slot={slot("body")}>
        <div data-slot={slot("header")}>{header}</div>
        <div data-slot={slot("content")}>{children}</div>
      </DockShell>
      <DockTray data-slot={slot("footer")}>{footer}</DockTray>
    </div>
  );
}

/**
 * SessionPermissionDock - dock anclado para solicitudes de permisos de herramientas.
 * Reemplaza el PermissionDialog modal de pantalla completa.
 */
export function SessionPermissionDock({
  request,
  client,
  onDecide,
}: {
  request: PermissionRequestPayload;
  client: WraithClient;
  onDecide?: (decision: "allow" | "allow_session" | "deny") => void;
}) {
  const [responding, setResponding] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const resolve = useStore((s) => s.resolvePermission);
  const queued = useStore((s) => s.permissionQueue.length);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    rootRef.current?.focus();
  }, []);

  const handleDecide = async (decision: "allow" | "allow_session" | "deny") => {
    if (responding) return;
    setResponding(true);
    setFailure(null);
    try {
      await client.agentPermissionRespond(request.request_id, decision);
      resolve(request.request_id);
      onDecide?.(decision);
    } catch (err) {
      const status = err instanceof WraithError ? err.status : 0;
      if (status === 404) {
        // El motor ya resolvió o caducó esta petición: retira el diálogo
        // obsoleto en vez de dejarlo en pantalla (responderlo daría 404).
        resolve(request.request_id);
      } else {
        // Fallo de red u otro: conserva el diálogo para que el analista pueda
        // reintentar (antes se ocultaba y el clic parecía haber funcionado).
        console.error("[wraith] error respondiendo permiso:", err);
        setFailure(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setResponding(false);
    }
  };

  const handleKeyDown: React.KeyboardEventHandler<HTMLDivElement> = (e) => {
    if (responding) return;
    if (e.key === "Escape" || e.key === "d" || e.key === "D") {
      e.preventDefault();
      void handleDecide("deny");
    } else if (e.key === "1" || e.key === "o" || e.key === "O") {
      e.preventDefault();
      void handleDecide("allow");
    } else if (e.key === "a" || e.key === "A") {
      e.preventDefault();
      void handleDecide("allow_session");
    }
  };

  const hasArgs = request.arguments && Object.keys(request.arguments).length > 0;

  return (
    <div
      ref={rootRef}
      tabIndex={-1}
      role="group"
      aria-label="Solicitud de permiso de herramienta"
      onKeyDown={handleKeyDown}
      className="w-full focus:outline-none"
    >
      <DockPrompt
        kind="permission"
        header={
          <div data-slot="permission-row" data-variant="header" className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span
                data-slot="permission-icon"
                className="size-2 rounded-xs bg-warning shadow-[0_0_8px_var(--warning)] shrink-0"
              />
              <span
                data-slot="permission-header-title"
                className="font-sans text-[12.5px] font-semibold tracking-wider text-text-strong uppercase"
              >
                Permiso requerido
              </span>
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              {queued > 1 && (
                <Tag tone="brand" className="font-mono text-[11px] font-semibold shrink-0">
                  {queued} en cola
                </Tag>
              )}
              <Tag tone="warning" className="font-mono text-[11px] font-semibold shrink-0">
                {request.tool}
              </Tag>
              <IconButton
                name="close"
                label="Denegar permiso (Esc)"
                size="small"
                variant="ghost"
                onClick={() => void handleDecide("deny")}
                className="size-5 p-0 text-text-weaker hover:text-text-critical"
                title="Denegar permiso (Esc)"
              />
            </div>
          </div>
        }
        footer={
          <div className="flex w-full items-center justify-between gap-2">
            <span className="truncate font-mono text-[10px] text-text-weaker" title={request.request_id}>
              req: {request.request_id.slice(0, 8)}…
            </span>
            <div data-slot="permission-footer-actions" className="flex shrink-0 items-center gap-1.5">
              <Button
                type="button"
                variant="danger"
                size="small"
                disabled={responding}
                onClick={() => void handleDecide("deny")}
                title="Denegar ejecución de la herramienta (Esc o D)"
              >
                Denegar
              </Button>
              <Button
                type="button"
                variant="secondary"
                size="small"
                disabled={responding}
                onClick={() => void handleDecide("allow")}
                title="Permitir solo esta ejecución (1 u O)"
              >
                Una vez
              </Button>
              <Button
                type="button"
                variant="primary"
                size="small"
                disabled={responding}
                onClick={() => void handleDecide("allow_session")}
                title="Permitir para el resto de este run (A)"
              >
                Siempre
              </Button>
            </div>
          </div>
        }
      >
        <div className="flex flex-col gap-2 text-[12px]">
          <div data-slot="permission-hint" className="leading-snug text-text-base">
            El agente solicita autorización para invocar la herramienta con los parámetros:
          </div>
          {failure && (
            <div
              data-slot="permission-error"
              role="alert"
              className="rounded-md border border-border-critical-base bg-surface-critical-weak p-2 font-mono text-[11px] leading-snug text-text-critical"
            >
              No se pudo enviar la respuesta al motor: {failure}. Vuelve a pulsar un botón para
              reintentar.
            </div>
          )}
          {hasArgs ? (
            <pre
              data-slot="permission-patterns"
              className="max-h-36 overflow-auto rounded-md border border-border-weak-base bg-background-base p-2.5 font-mono text-[10.5px] leading-relaxed text-text-base select-text"
            >
              {JSON.stringify(request.arguments, null, 2)}
            </pre>
          ) : (
            <div className="py-1 font-mono text-[11px] text-text-weaker italic">
              (sin argumentos adicionales)
            </div>
          )}
        </div>
      </DockPrompt>
    </div>
  );
}

/**
 * SessionQuestionDock - dock anclado para preguntas del agente al analista (ask_analyst).
 * Reemplaza el QuestionDialog modal de pantalla completa.
 */
export function SessionQuestionDock({
  request,
  client,
  onSubmit,
}: {
  request: QuestionAskedPayload;
  client: WraithClient;
  onSubmit?: () => void;
}) {
  const clear = useStore((s) => s.setPendingQuestion);
  const [activeTab, setActiveTab] = useState(0);
  // Soporta opciones múltiples y selección única por pregunta
  const [picked, setPicked] = useState<Record<number, string[]>>({});
  const [custom, setCustom] = useState<Record<number, string>>({});
  const [responding, setResponding] = useState(false);
  const dockRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    dockRef.current?.focus();
  }, []);

  const totalQuestions = request.questions.length;
  const currentQ: AnalystQuestion | undefined = request.questions[activeTab] || request.questions[0];
  const isMulti = currentQ?.multiple === true;

  const choose = (qi: number, label: string) => {
    setPicked((prev) => {
      const current = prev[qi] ?? [];
      const questionMulti = request.questions[qi]?.multiple === true;
      if (questionMulti) {
        const nextList = current.includes(label)
          ? current.filter((l) => l !== label)
          : [...current, label];
        return { ...prev, [qi]: nextList };
      }
      // Selección única tipo radio: si ya estaba marcado, se puede deseleccionar; sino se selecciona
      const nextList = current.includes(label) ? [] : [label];
      return { ...prev, [qi]: nextList };
    });
  };

  const respond = async (answers: string[][]) => {
    if (responding) return;
    setResponding(true);
    try {
      await client.agentQuestionRespond(request.request_id, answers);
      clear(null);
      onSubmit?.();
    } catch (err) {
      console.error("[wraith] error respondiendo preguntas:", err);
      clear(null);
    } finally {
      setResponding(false);
    }
  };

  const handleSend = () => {
    const answers: string[][] = request.questions.map((_, qi) => {
      const out: string[] = [...(picked[qi] ?? [])];
      const free = (custom[qi] ?? "").trim();
      if (free && !out.includes(free)) out.push(free);
      return out;
    });
    void respond(answers);
  };

  const handleSkip = () => {
    void respond(request.questions.map(() => []));
  };

  const handleKeyDown: React.KeyboardEventHandler<HTMLDivElement> = (e) => {
    const target = e.target as HTMLElement;
    const isInput = target.tagName === "INPUT" || target.tagName === "TEXTAREA";

    if (e.key === "Escape") {
      e.preventDefault();
      handleSkip();
      return;
    }

    if (!isInput) {
      if (e.key === "ArrowRight" && totalQuestions > 1 && activeTab < totalQuestions - 1) {
        e.preventDefault();
        setActiveTab((t) => t + 1);
      } else if (e.key === "ArrowLeft" && totalQuestions > 1 && activeTab > 0) {
        e.preventDefault();
        setActiveTab((t) => t - 1);
      }
    }
  };

  return (
    <div
      ref={dockRef}
      tabIndex={-1}
      role="group"
      aria-label="Pregunta del agente al analista"
      data-component="session-question-dock"
      onKeyDown={handleKeyDown}
      className="w-full focus:outline-none"
    >
      <DockPrompt
        kind="question"
        header={
          <div className="flex w-full items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="size-2 rounded-xs bg-brand shadow-[0_0_8px_var(--brand)] shrink-0" />
              <span
                data-slot="question-header-title"
                className="font-sans text-[12.5px] font-semibold tracking-wider text-text-strong uppercase"
              >
                El agente necesita un dato
              </span>
            </div>
            <div data-slot="question-header-actions" className="flex items-center gap-1.5 shrink-0">
              {totalQuestions > 1 ? (
                <Tag tone="brand" size="normal" className="font-mono text-[10px]">
                  {activeTab + 1} de {totalQuestions}
                </Tag>
              ) : (
                <Tag tone="brand" size="normal" className="font-mono text-[10px]">
                  ask_analyst
                </Tag>
              )}
              <IconButton
                name="close"
                label="Omitir preguntas (Esc)"
                size="small"
                variant="ghost"
                onClick={handleSkip}
                className="size-5 p-0 text-text-weaker hover:text-text-strong"
                title="Omitir preguntas (Esc)"
              />
            </div>
          </div>
        }
        footer={
          <div className="flex w-full items-center justify-between gap-2">
            <div data-slot="question-footer-hint" className="flex items-center gap-1 text-[11px] text-text-weak">
              {totalQuestions > 1 ? (
                <div className="flex items-center gap-1.5">
                  <Button
                    type="button"
                    variant="ghost"
                    size="small"
                    icon="chevron-left"
                    disabled={activeTab === 0}
                    onClick={() => setActiveTab((t) => t - 1)}
                    title="Pregunta anterior (ArrowLeft)"
                  >
                    Ant
                  </Button>
                  <span className="font-mono text-[10.5px] text-text-weaker px-1">
                    {activeTab + 1}/{totalQuestions}
                  </span>
                  <Button
                    type="button"
                    variant="ghost"
                    size="small"
                    iconAfter="chevron-right"
                    disabled={activeTab >= totalQuestions - 1}
                    onClick={() => setActiveTab((t) => t + 1)}
                    title="Pregunta siguiente (ArrowRight)"
                  >
                    Sig
                  </Button>
                </div>
              ) : (
                <span className="font-mono text-[10px] text-text-weaker">expira en 5 min</span>
              )}
            </div>

            <div data-slot="question-footer-actions" className="flex shrink-0 items-center gap-1.5">
              <Button
                type="button"
                variant="ghost"
                size="small"
                disabled={responding}
                onClick={handleSkip}
                title="Omitir responder preguntas y permitir al agente continuar (Esc)"
              >
                Omitir
              </Button>
              <Button
                type="button"
                variant="primary"
                size="small"
                disabled={responding}
                onClick={handleSend}
                title="Enviar respuestas al agente"
              >
                Responder
              </Button>
            </div>
          </div>
        }
      >
        <div className="flex flex-col gap-2">
          {/* Segmentos de progreso */}
          {totalQuestions > 1 && (
            <div data-slot="question-progress" className="flex items-center gap-1 border-b border-border-weak-base pb-2">
              {request.questions.map((_, idx) => {
                const isAnswered = Boolean((picked[idx]?.length ?? 0) > 0 || (custom[idx] ?? "").trim());
                return (
                  <button
                    key={idx}
                    type="button"
                    data-slot="question-progress-segment"
                    data-active={idx === activeTab}
                    data-answered={isAnswered}
                    aria-label={`Pregunta ${idx + 1}${isAnswered ? " (respondida)" : ""}`}
                    aria-current={idx === activeTab ? "true" : undefined}
                    onClick={() => setActiveTab(idx)}
                    className={`relative h-1.5 flex-1 rounded-xs transition-all before:absolute before:-inset-y-[11px] before:inset-x-0 ${
                      idx === activeTab
                        ? "bg-brand shadow-[0_0_6px_var(--brand)]"
                        : isAnswered
                          ? "bg-success"
                          : "bg-surface-raised-stronger hover:bg-border-strong-base"
                    }`}
                    title={`Pregunta ${idx + 1}`}
                  />
                );
              })}
            </div>
          )}

          {currentQ && (
            <div className="flex flex-col gap-2">
              {currentQ.header && (
                <div className="text-[10.5px] font-medium tracking-wider text-text-brand uppercase">
                  {currentQ.header}
                </div>
              )}
              {/* Al cambiar de pregunta (flechas / Ant / Sig) el lector anuncia
                  el texto nuevo. */}
              <div
                data-slot="question-text"
                aria-live="polite"
                className="text-[12.5px] font-medium leading-snug text-text-strong select-text"
              >
                {currentQ.question}
              </div>

              {currentQ.options && currentQ.options.length > 0 && (
                <div
                  data-slot="question-options"
                  role={isMulti ? "group" : "radiogroup"}
                  aria-label={`Opciones de respuesta · pregunta ${activeTab + 1}`}
                  className="flex max-h-40 flex-col gap-1.5 overflow-y-auto pr-1"
                >
                  {currentQ.options.map((opt) => {
                    const isSelected = (picked[activeTab] ?? []).includes(opt.label);
                    return (
                      <div
                        key={opt.label}
                        data-slot="question-option"
                        data-picked={isSelected}
                        role={isMulti ? "checkbox" : "radio"}
                        aria-checked={isSelected}
                        tabIndex={0}
                        onClick={() => choose(activeTab, opt.label)}
                        onKeyDown={(e) => {
                          if (e.key === " " || e.key === "Enter") {
                            e.preventDefault();
                            choose(activeTab, opt.label);
                          }
                        }}
                        className={`group flex cursor-pointer items-start gap-2.5 rounded-md border p-2 text-left transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-brand ${
                          isSelected
                            ? "border-border-brand-base bg-surface-brand-weak text-text-strong shadow-xs"
                            : "border-border-weak-base bg-surface-raised-base/70 text-text-base hover:border-border-base hover:bg-surface-raised-base hover:text-text-strong"
                        }`}
                      >
                        {isMulti ? (
                          <Checkbox
                            checked={isSelected}
                            onCheckedChange={() => choose(activeTab, opt.label)}
                            tabIndex={-1}
                            aria-hidden="true"
                            className="mt-0.5 shrink-0 pointer-events-none"
                          />
                        ) : (
                          <span
                            data-slot="question-option-check"
                            className="mt-0.5 flex size-4 shrink-0 items-center justify-center"
                            aria-hidden="true"
                          >
                            <span
                              data-slot="question-option-box"
                              data-type="radio"
                              data-picked={isSelected}
                              className={`flex size-3.5 items-center justify-center rounded-full border transition-colors ${
                                isSelected
                                  ? "border-border-brand-base bg-surface-brand-base text-text-invert"
                                  : "border-border-strong-base bg-surface-raised-strong text-transparent group-hover:border-border-brand-base"
                              }`}
                            >
                              {isSelected && (
                                <span
                                  data-slot="question-option-radio-dot"
                                  className="size-1.5 rounded-full bg-background-base"
                                />
                              )}
                            </span>
                          </span>
                        )}
                        <div data-slot="question-option-main" className="flex-1 leading-snug">
                          <div data-slot="option-label" className="text-[12px] font-medium text-text-strong">
                            {opt.label}
                          </div>
                          {opt.description && (
                            <div data-slot="option-description" className="mt-0.5 text-[11px] text-text-weak">
                              {opt.description}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {currentQ.custom !== false && (
                <TextField
                  size="small"
                  aria-label={
                    isMulti
                      ? "Otra respuesta personalizada (opcional)"
                      : "Respuesta personalizada (opcional)"
                  }
                  placeholder={
                    isMulti
                      ? "O escribe otra respuesta personalizada… (opcional)"
                      : "O escribe tu respuesta personalizada… (opcional)"
                  }
                  value={custom[activeTab] ?? ""}
                  onChange={(e) => setCustom((s) => ({ ...s, [activeTab]: e.target.value }))}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      if (totalQuestions > 1 && activeTab < totalQuestions - 1) {
                        setActiveTab((t) => t + 1);
                      } else {
                        handleSend();
                      }
                    }
                  }}
                />
              )}
            </div>
          )}
        </div>
      </DockPrompt>
    </div>
  );
}
