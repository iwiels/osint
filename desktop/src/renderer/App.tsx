/**
 * App - consola forense Specter.
 * Layout: sidebar de casos | vista de caso (grafo + custodia) | consola del agente.
 * Al montar: health-check del engine y suscripción al event bus (SSE).
 */

import { useEffect, useMemo } from "react";
import { SpecterClient } from "@specter/sdk";
import { connectEvents } from "@specter/sdk";
import { useStore } from "./store";
import Sidebar from "./components/Sidebar";
import CaseView from "./components/CaseView";
import AgentConsole from "./components/AgentConsole";

export default function App() {
  const engineUrl = useStore((s) => s.engineUrl);
  const engineOnline = useStore((s) => s.engineOnline);
  const setEngineOnline = useStore((s) => s.setEngineOnline);
  const setCases = useStore((s) => s.setCases);
  const activeCaseId = useStore((s) => s.activeCaseId);
  const pendingPermission = useStore((s) => s.pendingPermission);

  const client = useMemo(() => new SpecterClient({ baseUrl: engineUrl }), [engineUrl]);

  useEffect(() => {
    let dispose: (() => void) | undefined;
    let cancelled = false;

    (async () => {
      try {
        await client.health();
        if (cancelled) return;
        setEngineOnline(true);

        const { cases } = await client.listCases().then((cs) => ({ cases: cs }));
        setCases(cases);

        dispose = connectEvents(engineUrl, {
          "permission.request": (payload) =>
            useStore.getState().setPendingPermission(payload as never),
          "permission.granted": () => useStore.getState().setPendingPermission(null),
          "tool.started": (payload) => {
            const p = payload as { tool: string; arguments?: unknown };
            useStore.getState().pushMessage({
              role: "tool",
              tool: p.tool,
              content: `Ejecutando ${p.tool}...`,
            });
          },
          "tool.completed": (payload) => {
            const p = payload as { tool: string; result?: string };
            useStore.getState().pushMessage({
              role: "tool",
              tool: p.tool,
              content: (p.result ?? "").slice(0, 800),
            });
          },
          "agent.message": (payload) => {
            const p = payload as { role: string; content: string | null };
            if (p.content) {
              useStore.getState().pushMessage({ role: "assistant", content: p.content });
            }
          },
        });
      } catch {
        if (!cancelled) setEngineOnline(false);
      }
    })();

    return () => {
      cancelled = true;
      dispose?.();
    };
  }, [client, engineUrl, setEngineOnline, setCases]);

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">◈</span> SpecterOSINT
          <span className={`conn-dot ${engineOnline ? "on" : "off"}`} title={engineOnline ? "Engine online" : "Engine offline"} />
        </div>
        <div className="header-note">Consola forense · engine local</div>
      </header>

      {!engineOnline && (
        <div className="offline-banner">
          Engine desconectado. Arranca <code>python -m engine.http_server</code> o reinicia la app.
        </div>
      )}

      <div className="app-body">
        <Sidebar client={client} />
        <main className="app-main">{activeCaseId ? <CaseView client={client} /> : <Welcome />}</main>
        <AgentConsole client={client} />
      </div>

      {pendingPermission && <PermissionDialog client={client} />}
    </div>
  );
}

function Welcome() {
  return (
    <div className="welcome">
      <h2>Estación forense Specter</h2>
      <p>
        Crea o selecciona un caso en el panel izquierdo. El grafo de conocimiento, la cadena
        de custodia y el agente investigador aparecen aquí.
      </p>
    </div>
  );
}

function PermissionDialog({ client }: { client: SpecterClient }) {
  const pending = useStore((s) => s.pendingPermission);
  const clear = useStore((s) => s.setPendingPermission);
  if (!pending) return null;

  const decide = async (decision: "allow" | "allow_session" | "deny") => {
    await client.agentPermissionRespond(pending.request_id, decision);
    clear(null);
  };

  return (
    <div className="modal-backdrop">
      <div className="modal permission-modal">
        <h3>⚠ Permiso requerido</h3>
        <p>
          El agente solicita ejecutar <code className="tool-name">{pending.tool}</code>
        </p>
        <pre className="args-preview">{JSON.stringify(pending.arguments, null, 2)}</pre>
        <div className="modal-actions">
          <button className="btn ghost" onClick={() => decide("deny")}>
            Denegar
          </button>
          <button className="btn" onClick={() => decide("allow")}>
            Permitir una vez
          </button>
          <button className="btn primary" onClick={() => decide("allow_session")}>
            Permitir siempre en esta sesión
          </button>
        </div>
      </div>
    </div>
  );
}
