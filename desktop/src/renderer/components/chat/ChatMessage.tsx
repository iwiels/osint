import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { ChatMessage as ChatMessageType } from "../../store";
import { Icon } from "../../ui";
import { CodeBlock } from "./CodeBlock";

export interface ChatMessageProps {
  message: ChatMessageType;
}

export function ChatMessage({ message }: ChatMessageProps) {
  const [copied, setCopied] = useState(false);

  // System alert / telemetry notice (estilo docket forense sutil, sin wash amarillo agresivo)
  if (message.role === "system") {
    if (/^permiso para/i.test(message.content)) {
      return null;
    }
    const isError = /error|falló|fallo|excepción|abort/i.test(message.content);
    return (
      <div
        data-component="chat-system-message"
        className={`flex items-center gap-2 rounded-xs border border-dashed px-3 py-1.5 font-mono text-[11px] leading-normal ${
          isError
            ? "border-border-critical-base/60 bg-surface-critical-weak/40 text-text-critical"
            : "border-border-weak-base bg-surface-inset-base/50 text-text-weak"
        }`}
      >
        <span className={`size-1.5 shrink-0 rounded-full ${isError ? "bg-critical" : "bg-brand"}`} />
        <span className="font-semibold text-text-weaker uppercase text-[9.5px] tracking-wider shrink-0">
          {isError ? "[ERROR]" : "[SISTEMA]"}
        </span>
        <div className="flex-1 min-w-0 break-words select-text font-mono text-[11px] text-text-base">
          {message.content}
        </div>
      </div>
    );
  }

  // User prompt message (alineado a la derecha, estilo mensaje personal)
  if (message.role === "user") {
    return (
      <div
        data-component="chat-user-message"
        className="group relative self-end ml-auto max-w-[85%] rounded-md border border-border-base bg-surface-raised-strong/85 px-3.5 py-2.5 shadow-paper-xs"
      >
        <div className="text-[13px] leading-relaxed text-text-strong break-words whitespace-pre-wrap select-text">
          {message.content}
        </div>
        <div className="mt-1 flex justify-end">
          <span className="font-mono text-[9.5px] text-text-weaker tabular-nums opacity-0 transition-opacity duration-fast group-hover:opacity-100 select-none">
            {new Date(message.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
          </span>
        </div>
      </div>
    );
  }

  // Assistant response message
  const copyReport = async () => {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard access error
    }
  };

  return (
    <div
      data-component="chat-assistant-message"
      className="group relative self-start mr-auto w-full max-w-[94%] rounded-sm border border-border-weak-base bg-surface-raised-base p-4 shadow-paper-xs"
    >
      <div className="prose-specter select-text">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={{
            // Sanitized external links (allowlist http/https/mailto)
            a: ({ href, children, node: _node, ...props }) => {
              const safe =
                href && /^(https?:\/\/|mailto:)/i.test(href) ? href : undefined;
              if (!safe) return <span className="text-text-base">{children}</span>;
              return (
                <a
                  href={safe}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-text-brand underline transition-colors hover:text-surface-brand-hover"
                  onClick={(e) => {
                    e.preventDefault();
                    const desktop = (
                      window as unknown as {
                        specterDesktop?: { openExternal?: (u: string) => Promise<boolean> };
                      }
                    ).specterDesktop;
                    void desktop?.openExternal?.(safe);
                  }}
                  {...props}
                >
                  {children}
                </a>
              );
            },
            pre: ({ children, node: _node }) => <CodeBlock>{children}</CodeBlock>,
          }}
        >
          {message.content}
        </ReactMarkdown>
        {message.streaming && (
          <span
            aria-hidden="true"
            className="animate-blink ml-1 inline-block h-[1em] w-[7px] bg-text-brand"
          />
        )}
      </div>

      {/* Acción y hora al pie, en flujo natural para evitar solapamientos */}
      <div className="mt-2 flex items-center justify-end gap-1.5 font-mono text-[9.5px] text-text-weaker opacity-0 transition-opacity duration-fast group-hover:opacity-100 focus-within:opacity-100 select-none">
        <span className="tabular-nums">
          {new Date(message.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
        </span>
        <button
          type="button"
          onClick={copyReport}
          className="flex size-5 items-center justify-center rounded-xs text-text-weak transition-colors hover:bg-surface-base-hover hover:text-text-brand active:translate-y-[1px]"
          title={copied ? "Copiado al portapapeles" : "Copiar informe al portapapeles"}
          aria-label={copied ? "Copiado" : "Copiar informe"}
        >
          <Icon name={copied ? "check" : "copy"} size="small" tone={copied ? "success" : "weak"} />
        </button>
      </div>
    </div>
  );
}
export default ChatMessage;
