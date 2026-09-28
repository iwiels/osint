import { useEffect, useRef } from "react";
import type {
  PermissionRequestPayload,
  QuestionAskedPayload,
  SpecterClient,
} from "@specter/sdk";
import { Button, Tag } from "../../ui";
import { SessionPermissionDock, SessionQuestionDock } from "../DockPrompt";

export interface ChatComposerProps {
  input: string;
  setInput: (value: string) => void;
  onSend: () => void;
  onStop: () => void;
  isBusy: boolean;
  disabled?: boolean;
  placeholder?: string;
  client: SpecterClient;
  providerLabel?: string;
  modelLabel?: string;
  onOpenModelSettings?: () => void;
  pendingPermission?: PermissionRequestPayload | null;
  pendingQuestion?: QuestionAskedPayload | null;
}

export function ChatComposer({
  input,
  setInput,
  onSend,
  onStop,
  isBusy,
  disabled = false,
  placeholder,
  client,
  providerLabel,
  modelLabel,
  onOpenModelSettings,
  pendingPermission,
  pendingQuestion,
}: ChatComposerProps) {
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Auto-expanding textarea: expands up to 200px then enables internal scroll.
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`;
  }, [input]);

  const defaultPlaceholder = pendingPermission
    ? "Permiso pendiente: autoriza o deniega en el panel superior…"
    : pendingQuestion
      ? "Consulta pendiente: responde o pulsa Omitir en el panel superior…"
      : "Comando o consulta forense (ej. rastrear dns target.com, correlacionar identidades)…";

  return (
    <div data-component="chat-composer-area" className="shrink-0 flex flex-col">
      {pendingPermission && (
        <SessionPermissionDock request={pendingPermission} client={client} />
      )}
      {pendingQuestion && (
        <SessionQuestionDock request={pendingQuestion} client={client} />
      )}

      <div className="border-t border-border-weak-base bg-surface-raised-base/40 backdrop-blur-xs p-3">
        <div className="rounded-md border border-border-base bg-surface-inset-base p-2.5 shadow-paper-xs focus-within:border-border-brand-base focus-within:ring-1 focus-within:ring-border-brand-base transition-all">
          <textarea
            ref={inputRef}
            rows={1}
            aria-label="Comando o consulta forense"
            disabled={disabled}
            placeholder={placeholder || defaultPlaceholder}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                onSend();
              }
              if (e.key === "Escape" && isBusy) {
                e.preventDefault();
                onStop();
              }
            }}
            className="w-full min-h-[40px] max-h-[200px] resize-none overflow-y-auto bg-transparent p-1 font-sans text-[13px] leading-relaxed text-text-strong placeholder:text-text-weak focus:outline-none disabled:cursor-not-allowed disabled:opacity-50"
          />

          <div className="mt-2 flex items-center justify-between border-t border-border-weak-base/60 pt-2">
            <div className="flex items-center gap-2">
              {providerLabel && (
                <button
                  type="button"
                  onClick={onOpenModelSettings}
                  className="cursor-pointer transition-opacity hover:opacity-80 active:translate-y-[1px]"
                  title="Configurar motor analítico y credenciales"
                >
                  <Tag tone="brand" size="normal" icon="settings">
                    {providerLabel}
                    {modelLabel ? ` · ${modelLabel}` : ""}
                  </Tag>
                </button>
              )}
            </div>

            <div className="flex items-center gap-2">
              {isBusy ? (
                <Button
                  variant="danger"
                  size="small"
                  icon="stop"
                  onClick={onStop}
                  title="Detener la investigación en curso (Esc)"
                >
                  Detener
                </Button>
              ) : (
                <Button
                  variant="primary"
                  size="small"
                  iconAfter="arrow-right"
                  disabled={disabled || !input.trim()}
                  onClick={onSend}
                  title="Enviar (Enter · Shift+Enter nueva línea)"
                >
                  Enviar
                </Button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
export default ChatComposer;
