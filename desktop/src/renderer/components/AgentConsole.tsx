/**
 * AgentConsole - chat con el agente investigador forense Wraith.
 * Muestra transcripción en vivo vía SSE:
 * - Traza de herramientas agrupada en acordeón (estilo Claude Desktop / Cursor)
 * - Renderizado Markdown rico con tablas GFM, encabezados y bloques de código
 * - Streaming de tokens en vivo con cursor pulsante
 * - Copia directa de informes forenses al portapapeles
 * - Popover/modal para configuración de modelos (Zen free prestado, etc.)
 * - Historial persistente de investigaciones previas
 * - Composer multilínea auto-expandible con docks de permisos y preguntas
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { WraithClient } from "@wraith/sdk";
import { useStore } from "../store";
import type { ChatMessage as ChatMessageType } from "../store";
import { Button, Icon, Tag, useAutoScroll } from "../ui";
import {
  ChatComposer,
  ChatMessage,
  ToolActivityGroup,
} from "./chat";

type GroupedItem =
  | { type: "message"; message: ChatMessageType }
  | { type: "tool_group"; id: string; tools: ChatMessageType[] };

function groupMessages(messages: ChatMessageType[]): GroupedItem[] {
  const result: GroupedItem[] = [];
  let currentGroup: ChatMessageType[] = [];

  const flushGroup = () => {
    if (currentGroup.length > 0) {
      result.push({
        type: "tool_group",
        id: `group-${currentGroup[0].id}`,
        tools: [...currentGroup],
      });
      currentGroup = [];
    }
  };

  for (const msg of messages) {
    if (msg.role === "tool") {
      currentGroup.push(msg);
    } else {
      flushGroup();
      result.push({ type: "message", message: msg });
    }
  }
  flushGroup();
  return result;
}

export interface AgentConsoleProps {
  client: WraithClient;
}

export default function AgentConsole({ client }: AgentConsoleProps) {
  const chat = useStore((s) => s.chat);
  const pushMessage = useStore((s) => s.pushMessage);
  const clearChat = useStore((s) => s.clearChat);
  const activeSessionId = useStore((s) => s.activeSessionId);
  const setActiveSessionId = useStore((s) => s.setActiveSessionId);
  const startNewSession = useStore((s) => s.startNewSession);
  const agentBusy = useStore((s) => s.agentBusy);
  const setAgentBusy = useStore((s) => s.setAgentBusy);
  const activeRunId = useStore((s) => s.activeRunId);
  const provider = useStore((s) => s.provider);
  const activeCaseId = useStore((s) => s.activeCaseId);
  const cases = useStore((s) => s.cases);
  const engineOnline = useStore((s) => s.engineOnline);
  const plan = useStore((s) => s.plan);
  const setPlan = useStore((s) => s.setPlan);
  const usage = useStore((s) => s.usage);
  const setUsage = useStore((s) => s.setUsage);
  const runOptions = useStore((s) => s.runOptions);
  const historyView = useStore((s) => s.historyView);
  const setHistoryView = useStore((s) => s.setHistoryView);
  const bumpSessions = useStore((s) => s.bumpSessions);
  const bumpCaseData = useStore((s) => s.bumpCaseData);
  const pendingPermission = useStore((s) => s.pendingPermission);
  const pendingQuestion = useStore((s) => s.pendingQuestion);
  const setSettingsOpen = useStore((s) => s.setSettingsOpen);

  const [input, setInput] = useState("");
  const [isPlanExpanded, setIsPlanExpanded] = useState(true);
  const abortRef = useRef<AbortController | null>(null);
  const stopRequestedRef = useRef(false);

  const autoScroll = useAutoScroll({ working: agentBusy });
  const { scrollRef, contentRef, onScroll, userScrolled, forceScrollToBottom } = autoScroll;

  // El historial vive en el raíl izquierdo; solo se reinicia si realmente cambió el caso activo.
  const prevCaseIdRef = useRef(activeCaseId);
  useEffect(() => {
    if (prevCaseIdRef.current !== activeCaseId) {
      prevCaseIdRef.current = activeCaseId;
      setHistoryView(null);
    }
  }, [activeCaseId, setHistoryView]);

  const activeCase = useMemo(
    () => cases.find((c) => c.case_id === activeCaseId),
    [cases, activeCaseId],
  );

  const messagesToRender = historyView ? historyView.messages : chat;
  const groupedItems = useMemo(() => groupMessages(messagesToRender), [messagesToRender]);

  // Contenido nuevo (mensajes, plan): bajar solo si el analista sigue al fondo.
  useEffect(() => {
    autoScroll.scrollToBottom();
  }, [chat, plan, autoScroll]);

  const stop = useCallback(() => {
    stopRequestedRef.current = true;
    abortRef.current?.abort();
    // Cancelación cooperativa en servidor: el loop la observa entre iteraciones.
    // El run_id (si lo tenemos) es el ancla exacta; el case_id sólo acierta
    // cuando el run está ámbito a un caso (un run global no se detenía).
    void client
      .cancelRuns(activeCaseId ?? undefined, activeRunId ?? undefined)
      .catch(() => undefined);
    setAgentBusy(false);
    pushMessage({ role: "system", content: "Investigación detenida por el analista." });
    // Las tool calls en vuelo nunca recibirán su `tool.completed`: el servidor
    // ya canceló la iteración. Sin esto quedan en `running` para siempre y el
    // grupo de operaciones se queda girando como si el run siguiera vivo.
    useStore.getState().interruptRunningTools();
    useStore.getState().closeStream();
  }, [client, activeCaseId, activeRunId, pushMessage, setAgentBusy]);

  const send = async () => {
    const message = input.trim();
    if (!message || agentBusy || !engineOnline) return;
    const runCaseId = activeCaseId;

    setSettingsOpen(false);
    pushMessage({ role: "user", content: message });
    setInput("");
    setAgentBusy(true);
    setPlan(null);
    setUsage(null);
    stopRequestedRef.current = false;
    useStore.getState().closeStream();
    forceScrollToBottom();
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const result = await client.agentRun(
        {
          case_id: activeCaseId ?? undefined,
          session_id: activeSessionId ?? undefined,
          message,
          provider: provider.provider,
          model: provider.model || undefined,
          api_key: provider.apiKey || undefined,
          base_url: provider.baseUrl || undefined,
          stream: runOptions.stream,
          plan_first: runOptions.planFirst,
          auto_approve: runOptions.autoApprove,
        },
        { signal: controller.signal },
      );

      const runCaseIsActive = useStore.getState().activeCaseId === runCaseId;
      if (result.session_id && runCaseIsActive) {
        setActiveSessionId(result.session_id);
      }

      if (runCaseIsActive) {
        const last = useStore.getState().chat.at(-1);
        if (!last || last.role !== "assistant") {
          pushMessage({ role: "assistant", content: result.final_message || "(sin respuesta)" });
        }
        setUsage(result.usage ?? null);
      }
    } catch (err) {
      if (stopRequestedRef.current || controller.signal.aborted) {
        // stop() ya registró la advertencia en el chat
      } else if (useStore.getState().activeCaseId === runCaseId) {
        pushMessage({
          role: "system",
          content: `Error: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    } finally {
      abortRef.current = null;
      setAgentBusy(false);
      // Sin agent.completed (error de transporte), el run_id no debe quedar
      // apuntando a un run que ya no existe.
      useStore.getState().setActiveRunId(null);
      if (useStore.getState().activeCaseId === runCaseId) {
        setHistoryView(null);
        bumpSessions();
        bumpCaseData();
      }
    }
  };

  const composerPlaceholder = pendingPermission
    ? "Permiso pendiente: autoriza o deniega en el panel superior…"
    : pendingQuestion
      ? "Consulta pendiente: responde o pulsa Omitir en el panel superior…"
      : historyView
        ? "Viendo historial: vuelve a la sesión activa para escribir…"
        : activeCase
          ? `Investigar en expediente "${activeCase.name}"…`
          : activeCaseId
            ? "Comando o consulta forense en el expediente activo…"
            : "Comando o consulta forense (ej. rastrear dns target.com)…";

  return (
    <section
      aria-label="Consola de investigación"
      className="flex h-full min-h-0 flex-1 flex-col overflow-hidden bg-transparent"
    >
      {/* Cabecera de 42px full-bleed alineada con la del panel de evidencias */}
      <div className="flex h-[42px] shrink-0 items-center justify-between border-b border-border-weak-base bg-surface-raised-base/40 backdrop-blur-xs px-3.5">
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-mono text-[11px] font-semibold tracking-wider text-text-weak uppercase">
            Chat
          </span>
          {activeCase && (
            <span
              className="font-mono text-[10.5px] text-text-weaker truncate max-w-[200px]"
              title={`${activeCase.name} (${activeCase.case_id})`}
            >
              · {activeCase.name}
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {usage && (usage.input_tokens > 0 || usage.output_tokens > 0) && (
            <Tag
              tone="neutral"
              size="normal"
              title={`Consumo de la sesión: ${usage.input_tokens} de entrada, ${usage.output_tokens} de salida`}
            >
              <span className="inline-flex items-center gap-1">
                <Icon name="arrow-down" size="small" />
                {usage.input_tokens}
                <Icon name="arrow-up" size="small" />
                {usage.output_tokens}
              </span>
            </Tag>
          )}

          {chat.length > 0 && !agentBusy && (
            <Button
              variant="ghost"
              size="small"
              onClick={startNewSession}
              className="h-6 px-2 font-mono text-[10.5px] text-text-weak hover:text-text-base"
              title="Iniciar una nueva sesión / hilo de conversación en este expediente"
            >
              + nueva sesión
            </Button>
          )}
        </div>
      </div>

      <div className="mx-auto flex min-h-0 w-full max-w-[840px] flex-1 flex-col">
        {plan && plan.length > 0 && (
          <div className="shrink-0 border-b border-border-base bg-surface-raised-strong/60 shadow-paper-xs">
            <button
              type="button"
              aria-expanded={isPlanExpanded}
              onClick={() => setIsPlanExpanded(!isPlanExpanded)}
              className="flex w-full cursor-pointer items-center justify-between px-3.5 py-2 text-left transition-colors hover:bg-surface-base-hover"
            >
              <div className="flex items-center gap-2">
                <Icon name="list" size="small" tone="brand" />
                <span className="font-mono text-[11px] font-semibold tracking-wider text-text-strong uppercase">
                  secuencia de investigación
                </span>
                <Tag tone="brand" variant="dashed" size="normal">
                  {plan.length} {plan.length === 1 ? "fase" : "fases"}
                </Tag>
              </div>
              <span
                aria-hidden="true"
                data-open={isPlanExpanded ? "" : undefined}
                className="flex size-5 shrink-0 items-center justify-center text-text-weak transition-transform duration-fast data-[open]:rotate-180"
              >
                <Icon name="chevron-down" size="small" tone="weak" />
              </span>
            </button>

            {isPlanExpanded && (
              <div className="max-h-48 overflow-y-auto px-3.5 pb-2.5">
                <ol className="flex flex-col gap-2 border-t border-border-weak-base/70 pt-2">
                  {plan.map((s) => (
                    <li key={s.step} className="flex gap-2.5 text-[12px] leading-snug">
                      <span className="shrink-0 font-mono text-[10px] font-bold text-text-brand px-1.5 py-0.5 rounded-xs border border-border-brand-base/40 bg-surface-brand-weak/20">
                        {String(s.step).padStart(2, "0")}
                      </span>
                      <div className="flex-1 min-w-0">
                        <span className="text-[12.5px] leading-relaxed text-text-strong">{s.goal}</span>
                        {s.tools.length > 0 && (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {s.tools.map((t) => (
                              <Tag key={t} tone="neutral" variant="dashed" size="normal">
                                {t}
                              </Tag>
                            ))}
                          </div>
                        )}
                      </div>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        )}

        {/* Flujo de mensajes con scroll automático accesible */}
        <div
          ref={scrollRef}
          onScroll={onScroll}
          role="log"
          aria-live="polite"
          aria-relevant="additions"
          aria-busy={agentBusy}
          aria-label="Conversación con el agente"
          className="relative flex min-h-0 flex-1 flex-col overflow-y-auto p-3.5"
        >
          <div ref={contentRef} className="flex flex-col gap-3">
            {/* Banner de modo historial (solo lectura) */}
            {historyView && (
              <div className="animate-rise flex items-center justify-between gap-3 rounded-md border border-border-brand-base bg-surface-brand-weak/30 p-2.5">
                <div className="min-w-0">
                  <div className="font-mono text-[10.5px] font-semibold tracking-wider text-text-brand uppercase">
                    viendo historial (solo lectura)
                  </div>
                  <div className="truncate font-mono text-[11px] text-text-base">
                    {historyView.session_id}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <Button
                    variant="primary"
                    size="small"
                    onClick={() => {
                      useStore.getState().setChat(historyView.messages);
                      setHistoryView(null);
                    }}
                    title="Cargar esta sesión como activa para continuar investigando"
                  >
                    Reanudar
                  </Button>
                  <Button
                    variant="secondary"
                    size="small"
                    iconAfter="arrow-right"
                    onClick={() => setHistoryView(null)}
                    title="Volver al chat en vivo"
                  >
                    en vivo
                  </Button>
                </div>
              </div>
            )}

            {!historyView && chat.length === 0 && (
              <div className="animate-rise relative overflow-hidden rounded-lg border border-border-weak-base bg-surface-raised-base p-7 text-center shadow-paper-md">
                <h2 className="mb-2 font-display text-[20px] font-semibold tracking-tight text-text-strong">
                  Consola de Inteligencia Forense
                </h2>

                <p className="mx-auto mb-5 max-w-md text-[13px] leading-relaxed text-text-base">
                  Ingresa un objetivo de investigación (dominio, dirección IP, nombre de persona o alias). Wraith triangulará registros públicos, rastreará huellas digitales y consolidará las evidencias en el libro mayor forense.
                </p>

                <div className="flex flex-wrap items-center justify-center gap-2 border-t border-border-weak-base/60 pt-3">
                  <span className="font-mono text-[10px] tracking-wider text-text-weaker uppercase">
                    Prueba con:
                  </span>
                  <button
                    type="button"
                    onClick={() => setInput("Investiga el dominio ejemplo.com: subdominios, DNS y certificados")}
                    className="cursor-pointer rounded-xs border border-dashed border-border-strong-base bg-surface-raised-strong/50 px-2.5 py-1 font-mono text-[11px] text-text-strong transition-all hover:border-brand hover:bg-surface-brand-weak/30 hover:text-text-brand active:translate-y-[1px]"
                  >
                    ejemplo.com: huella completa
                  </button>
                  <button
                    type="button"
                    onClick={() => setInput("Analiza la infraestructura de red de 192.0.2.1: PTR, RDAP, ASN y reputación")}
                    className="cursor-pointer rounded-xs border border-dashed border-border-strong-base bg-surface-raised-strong/50 px-2.5 py-1 font-mono text-[11px] text-text-strong transition-all hover:border-brand hover:bg-surface-brand-weak/30 hover:text-text-brand active:translate-y-[1px]"
                  >
                    192.0.2.1: reputación IP
                  </button>
                </div>
              </div>
            )}

            {groupedItems.map((item) => {
              if (item.type === "tool_group") {
                return <ToolActivityGroup key={item.id} tools={item.tools} />;
              }
              return <ChatMessage key={item.message.id} message={item.message} />;
            })}
          </div>

          {userScrolled && !historyView && (
            <div className="sticky bottom-2 flex justify-center">
              <Button
                variant="secondary"
                size="small"
                icon="arrow-down"
                onClick={() => autoScroll.resume()}
                className="shadow-[2px_2px_0_rgb(0_0_0/0.2)]"
                title="Volver al final del chat"
              >
                ir al fondo
              </Button>
            </div>
          )}
        </div>

        {!historyView && agentBusy && (
          <div
            role="status"
            className="animate-rise flex shrink-0 items-center gap-2 border-t border-border-brand-base/30 bg-surface-brand-weak/20 px-3.5 py-1.5 font-mono text-[11px] text-text-brand"
          >
            <span className="size-2 rounded-full bg-brand animate-dot-live shrink-0" />
            <span className="flex-1">Investigando en vivo…</span>
          </div>
        )}

        <ChatComposer
          input={input}
          setInput={setInput}
          onSend={() => void send()}
          onStop={stop}
          isBusy={agentBusy}
          disabled={!engineOnline || !!historyView || !!pendingPermission || !!pendingQuestion}
          placeholder={composerPlaceholder}
          client={client}
          providerLabel={provider.provider}
          modelLabel={provider.model}
          onOpenModelSettings={() => setSettingsOpen(true)}
          pendingPermission={pendingPermission}
          pendingQuestion={pendingQuestion}
        />
      </div>
    </section>
  );
}
