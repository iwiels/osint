/**
 * AgentConsole - chat con el agente investigador.
 * Muestra transcripción en vivo vía SSE (tool.started/completed, mensajes)
 * y permite configurar provider/modelo/API key por sesión.
 */

import { useEffect, useRef, useState } from "react";
import type { SpecterClient } from "@specter/sdk";
import { useStore } from "../store";

const PROVIDERS = [
  { id: "anthropic", label: "Anthropic" },
  { id: "openai", label: "OpenAI" },
  { id: "ollama", label: "Ollama (local)" },
];

export default function AgentConsole({ client }: { client: SpecterClient }) {
  const chat = useStore((s) => s.chat);
  const pushMessage = useStore((s) => s.pushMessage);
  const agentBusy = useStore((s) => s.agentBusy);
  const setAgentBusy = useStore((s) => s.setAgentBusy);
  const provider = useStore((s) => s.provider);
  const setProvider = useStore((s) => s.setProvider);
  const activeCaseId = useStore((s) => s.activeCaseId);
  const engineOnline = useStore((s) => s.engineOnline);

  const [input, setInput] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [chat]);

  const send = async () => {
    const message = input.trim();
    if (!message || agentBusy || !engineOnline) return;

    pushMessage({ role: "user", content: message });
    setInput("");
    setAgentBusy(true);
    try {
      const result = await client.agentRun({
        case_id: activeCaseId ?? undefined,
        message,
        provider: provider.provider,
        model: provider.model || undefined,
        api_key: provider.apiKey || undefined,
        base_url: provider.baseUrl || undefined,
      });
      // El último mensaje del asistente llega por SSE; si no llegó, lo añadimos.
      const last = useStore.getState().chat.at(-1);
      if (!last || last.role !== "assistant") {
        pushMessage({ role: "assistant", content: result.final_message || "(sin respuesta)" });
      }
    } catch (err) {
      pushMessage({
        role: "system",
        content: `Error: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setAgentBusy(false);
    }
  };

  return (
    <section className="agent-console">
      <div className="agent-head">
        <span className="agent-title">Agente investigador</span>
        <button className="btn tiny ghost" onClick={() => setShowSettings(!showSettings)}>
          ⚙ {provider.provider}
        </button>
      </div>

      {showSettings && (
        <div className="agent-settings">
          <select
            value={provider.provider}
            onChange={(e) => setProvider({ provider: e.target.value, model: "" })}
          >
            {PROVIDERS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
          <input
            placeholder="Modelo (opcional)"
            value={provider.model}
            onChange={(e) => setProvider({ model: e.target.value })}
          />
          {provider.provider !== "ollama" && (
            <input
              type="password"
              placeholder="API key (o variable de entorno)"
              value={provider.apiKey}
              onChange={(e) => setProvider({ apiKey: e.target.value })}
            />
          )}
        </div>
      )}

      <div className="chat-scroll" ref={scrollRef}>
        {chat.length === 0 && (
          <div className="empty-note pad">
            Pide al agente: <i>"investiga el dominio acme.com y busca huellas de filtración"</i>
          </div>
        )}
        {chat.map((m) => (
          <div key={m.id} className={`chat-msg ${m.role}`}>
            <div className="msg-meta">
              {m.role === "tool" ? `⚙ ${m.tool}` : m.role === "user" ? "Tú" : m.role === "system" ? "sistema" : "Specter"}
            </div>
            <div className="msg-body">
              {m.role === "tool" ? (
                <pre>{m.content}</pre>
              ) : (
                m.content
              )}
            </div>
          </div>
        ))}
        {agentBusy && <div className="thinking">Specter está investigando…</div>}
      </div>

      <div className="chat-input-row">
        <textarea
          placeholder={activeCaseId ? "Mensaje al agente (trabajará en el caso activo)…" : "Sin caso activo: el agente creará o seleccionará uno…"}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
          rows={2}
        />
        <button className="btn primary send-btn" onClick={send} disabled={agentBusy || !engineOnline}>
          ➤
        </button>
      </div>
    </section>
  );
}
