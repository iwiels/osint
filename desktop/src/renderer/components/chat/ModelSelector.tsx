import { useCallback, useEffect, useState } from "react";
import type { SecretEntry, WraithClient } from "@wraith/sdk";
import { useStore } from "../../store";
import {
  Button,
  Checkbox,
  Dialog,
  DialogContent,
  Icon,
  IconButton,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Tag,
  TextField,
} from "../../ui";
import { cn } from "../../ui/lib/cn";

export const PROVIDERS = [
  { id: "opencode", label: "Zen free (HTTP)" },
  { id: "anthropic", label: "Anthropic" },
  { id: "openai", label: "OpenAI" },
  { id: "ollama", label: "Ollama (local)" },
];

export const ZEN_FREE_MODELS = [
  { id: "space-bunny-free", label: "space-bunny-free (Sin API key · Anónimo)" },
  { id: "big-pickle", label: "big-pickle (Requiere API key)" },
  { id: "mimo-v2.6-flash-free", label: "mimo-v2.6-flash-free (Requiere API key)" },
  { id: "mimo-v2.5-free", label: "mimo-v2.5-free (Requiere API key)" },
  { id: "ling-3.0-flash-fin-free", label: "ling-3.0-flash-fin-free (Requiere API key)" },
  { id: "nemotron-3-ultra-free", label: "nemotron-3-ultra-free (Requiere API key)" },
  { id: "nemotron-3.5-lightning-free", label: "nemotron-3.5-lightning-free (Requiere API key)" },
];

/** Fuentes Fase B: solo se usan si su key está en la bóveda (o env). */
export const THIRD_PARTY_KEYS = [
  { id: "virustotal_api_key", label: "VirusTotal (reputación IP/dominio/hash)" },
  { id: "shodan_api_key", label: "Shodan (host + favicon search)" },
  { id: "greynoise_api_key", label: "GreyNoise (ruido vs objetivo)" },
  { id: "abuseipdb_api_key", label: "AbuseIPDB (score de abuso)" },
  { id: "hunter_api_key", label: "Hunter.io (emails + verificación)" },
];

export type SettingsTab = "inference" | "vault" | "params" | "server";

export interface ModelSelectorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  client: WraithClient;
}

export function ModelSelector({ open, onOpenChange, client }: ModelSelectorProps) {
  const provider = useStore((s) => s.provider);
  const setProvider = useStore((s) => s.setProvider);
  const engineOnline = useStore((s) => s.engineOnline);
  const engineUrl = useStore((s) => s.engineUrl);
  const engineHealth = useStore((s) => s.engineHealth);
  const engineToken = useStore((s) => s.engineToken);
  const runOptions = useStore((s) => s.runOptions);
  const setRunOptions = useStore((s) => s.setRunOptions);

  const [activeTab, setActiveTab] = useState<SettingsTab>("inference");
  const [secrets, setSecrets] = useState<SecretEntry[] | null>(null);
  const [secretName, setSecretName] = useState(THIRD_PARTY_KEYS[0].id);
  const [secretValue, setSecretValue] = useState("");
  const [secretMsg, setSecretMsg] = useState<string | null>(null);
  const [isSavingSecret, setIsSavingSecret] = useState(false);

  const loadSecrets = useCallback(async () => {
    try {
      const res = await client.listSecrets();
      setSecrets(res.secrets);
    } catch {
      setSecrets(null);
    }
  }, [client]);

  useEffect(() => {
    if (open && engineOnline) {
      setSecretMsg(null);
      void loadSecrets();
    }
  }, [open, engineOnline, loadSecrets]);

  const saveSecret = async () => {
    if (!secretValue.trim()) return;
    setIsSavingSecret(true);
    try {
      const res = await client.setSecret(secretName, secretValue.trim());
      setSecrets(res.secrets);
      setSecretValue("");
      setSecretMsg("Clave registrada exitosamente en la bóveda.");
    } catch (err) {
      setSecretMsg(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSavingSecret(false);
    }
  };

  const removeSecret = async (name: string) => {
    try {
      const res = await client.deleteSecret(name);
      setSecrets(res.secrets);
      setSecretMsg(`Clave ${name} eliminada.`);
    } catch {
      // refresh will reflect state
    }
  };

  const tabTitle =
    activeTab === "inference"
      ? "Motor de Inferencia & Modelos"
      : activeTab === "vault"
        ? "Bóveda de Credenciales Forenses"
        : activeTab === "params"
          ? "Parámetros de Ejecución del Agente"
          : "Servidor & Estado del Engine";

  const tabSubtitle =
    activeTab === "inference"
      ? "Configura el núcleo LLM analítico para la síntesis de inteligencia e investigación."
      : activeTab === "vault"
        ? "Administra las API keys seguras para enriquecimiento pasivo y activo."
        : activeTab === "params"
          ? "Ajusta la supervisión interactiva, streaming y comportamiento del planificador."
          : "Diagnóstico de conexión con el daemon FastAPI headless y el sidecar.";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="x-large"
        className="p-0 overflow-hidden flex flex-row h-[560px] max-h-[calc(100vh-48px)] w-[780px] max-w-[calc(100vw-32px)]"
      >
        {/* Raíl izquierdo de navegación (Estilo opencode settings-v2) */}
        <div className="w-[210px] shrink-0 border-r border-border-weak-base bg-surface-inset-base/60 flex flex-col justify-between p-3 select-none">
          <div className="flex flex-col gap-3">
            <div className="px-2 pt-1 pb-0.5">
              <span className="font-mono text-[10px] font-semibold tracking-wider text-text-weaker uppercase">
                Ajustes
              </span>
            </div>
            <nav className="flex flex-col gap-1">
              <button
                type="button"
                onClick={() => setActiveTab("inference")}
                className={cn(
                  "flex items-center gap-2.5 rounded-xs px-2.5 py-2 font-mono text-[11px] tracking-tight transition-all duration-base text-left cursor-pointer",
                  activeTab === "inference"
                    ? "bg-surface-raised-strong font-semibold text-text-strong shadow-paper-xs border border-border-base"
                    : "text-text-weak hover:bg-surface-base-hover hover:text-text-base border border-transparent"
                )}
              >
                <Icon name="sparkle" size="small" />
                <span>Inferencia & Modelos</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("vault")}
                className={cn(
                  "flex items-center gap-2.5 rounded-xs px-2.5 py-2 font-mono text-[11px] tracking-tight transition-all duration-base text-left cursor-pointer",
                  activeTab === "vault"
                    ? "bg-surface-raised-strong font-semibold text-text-strong shadow-paper-xs border border-border-base"
                    : "text-text-weak hover:bg-surface-base-hover hover:text-text-base border border-transparent"
                )}
              >
                <Icon name="lock" size="small" />
                <span>Bóveda Forense</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("params")}
                className={cn(
                  "flex items-center gap-2.5 rounded-xs px-2.5 py-2 font-mono text-[11px] tracking-tight transition-all duration-base text-left cursor-pointer",
                  activeTab === "params"
                    ? "bg-surface-raised-strong font-semibold text-text-strong shadow-paper-xs border border-border-base"
                    : "text-text-weak hover:bg-surface-base-hover hover:text-text-base border border-transparent"
                )}
              >
                <Icon name="terminal" size="small" />
                <span>Parámetros Agente</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab("server")}
                className={cn(
                  "flex items-center gap-2.5 rounded-xs px-2.5 py-2 font-mono text-[11px] tracking-tight transition-all duration-base text-left cursor-pointer",
                  activeTab === "server"
                    ? "bg-surface-raised-strong font-semibold text-text-strong shadow-paper-xs border border-border-base"
                    : "text-text-weak hover:bg-surface-base-hover hover:text-text-base border border-transparent"
                )}
              >
                <Icon name="shield" size="small" />
                <span>Servidor & Estado</span>
              </button>
            </nav>
          </div>

          {/* Pie de navegación */}
          <div className="border-t border-border-weak-base pt-2.5 px-2 flex items-center justify-between font-mono text-[10px] text-text-weaker">
            <span>WraithOSINT</span>
            <span>v{__APP_VERSION__}</span>
          </div>
        </div>

        {/* Panel derecho de contenido */}
        <div className="flex-1 flex flex-col min-w-0 bg-surface-raised-stronger overflow-hidden">
          {/* Cabecera del panel */}
          <div className="border-b border-border-weak-base px-6 py-4 pr-12 bg-surface-raised-base/50">
            <h2 className="font-sans text-[14px] font-semibold text-text-strong">
              {tabTitle}
            </h2>
            <p className="font-sans text-[11.5px] text-text-weak mt-0.5">
              {tabSubtitle}
            </p>
          </div>

          {/* Cuerpo con scroll */}
          <div className="flex-1 overflow-y-auto p-6 space-y-4">
            {/* PESTAÑA: INFERENCIA */}
            {activeTab === "inference" && (
              <div className="space-y-4">
                <div className="rounded-md border border-border-weak-base bg-surface-inset-base/40 p-4 space-y-3.5">
                  <div>
                    <label className="mb-1.5 block font-mono text-[11px] font-semibold tracking-wider text-text-weak uppercase">
                      Motor de Inferencia
                    </label>
                    <Select
                      value={provider.provider}
                      onValueChange={(nextProvider) => {
                        const nextModel = nextProvider === "opencode" ? "space-bunny-free" : "";
                        setProvider({ provider: nextProvider, model: nextModel });
                      }}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Seleccionar motor" />
                      </SelectTrigger>
                      <SelectContent>
                        {PROVIDERS.map((p) => (
                          <SelectItem key={p.id} value={p.id}>
                            {p.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  {provider.provider === "opencode" && (
                    <div>
                      <label className="mb-1.5 block font-mono text-[11px] font-semibold tracking-wider text-text-weak uppercase">
                        Modelo de Análisis
                      </label>
                      <Select
                        value={provider.model || "space-bunny-free"}
                        onValueChange={(model) => setProvider({ model })}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Seleccionar modelo" />
                        </SelectTrigger>
                        <SelectContent>
                          {ZEN_FREE_MODELS.map((m) => (
                            <SelectItem key={m.id} value={m.id}>
                              {m.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  )}

                  {provider.provider === "opencode" ? (
                    <TextField
                      label="API Key (Opcional)"
                      type="password"
                      placeholder="sk-opencode-… (dejar vacío para uso anónimo)"
                      value={provider.apiKey}
                      onChange={(e) => setProvider({ apiKey: e.target.value })}
                    />
                  ) : provider.provider === "ollama" ? (
                    <TextField
                      label="URL Base de Ollama"
                      placeholder="http://localhost:11434"
                      value={provider.baseUrl}
                      onChange={(e) => setProvider({ baseUrl: e.target.value })}
                    />
                  ) : (
                    <TextField
                      label="API Key"
                      type="password"
                      placeholder="sk-… o variable de entorno"
                      value={provider.apiKey}
                      onChange={(e) => setProvider({ apiKey: e.target.value })}
                    />
                  )}

                  {provider.provider === "opencode" && (
                    <p className="text-[11px] text-text-weaker leading-relaxed">
                      Dejar en blanco para acceso anónimo con <code className="font-mono text-text-weak">space-bunny-free</code> o ingresar credencial para desbloquear modelos avanzados.
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* PESTAÑA: BÓVEDA FORENSE */}
            {activeTab === "vault" && (
              <div className="space-y-4">
                <p className="text-[11.5px] leading-relaxed text-text-weak">
                  VirusTotal, Shodan, GreyNoise, AbuseIPDB y Hunter.io se consultan únicamente si su clave está registrada en la bóveda cifrada local. Sin clave registrada, el motor continúa la investigación omitiendo dichas fuentes.
                </p>

                {/* Listado de fuentes */}
                <div className="rounded-md border border-border-weak-base bg-surface-inset-base/50 p-2 space-y-1.5">
                  {secrets === null ? (
                    <p className="p-2 text-[11px] text-text-weak">Bóveda no disponible (engine offline).</p>
                  ) : (
                    THIRD_PARTY_KEYS.map((k) => {
                      const entry = secrets.find((s) => s.name === k.id);
                      const on = entry?.configured ?? false;
                      return (
                        <div
                          key={k.id}
                          className="flex items-center justify-between gap-3 rounded px-2.5 py-1.5 text-[11.5px] hover:bg-surface-raised-strong/60 transition-colors"
                        >
                          <div className="flex min-w-0 items-center gap-2.5">
                            <span
                              className={cn(
                                "size-2 shrink-0 rounded-full",
                                on ? "bg-success" : "bg-surface-raised-stronger"
                              )}
                              title={on ? `Configurada (${entry?.masked ?? ""})` : "Sin configurar"}
                            />
                            <div className="min-w-0">
                              <span className="font-medium text-text-base block truncate" title={k.label}>
                                {k.label}
                              </span>
                              <span className="font-mono text-[10px] text-text-weaker block">
                                {on ? `Registrada: ${entry?.masked ?? "••••••••"}` : "No configurada"}
                              </span>
                            </div>
                          </div>
                          {on ? (
                            <IconButton
                              name="trash"
                              label={`Borrar ${k.id} de la bóveda`}
                              size="small"
                              onClick={() => void removeSecret(k.id)}
                              className="size-5 shrink-0 text-text-weak hover:text-text-critical"
                            />
                          ) : (
                            <Tag size="normal" tone="neutral" className="font-mono text-[9px] uppercase">
                              inactivo
                            </Tag>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>

                {/* Formulario de añadir/actualizar */}
                <div className="rounded-md border border-border-weak-base bg-surface-inset-base/40 p-3.5 space-y-3">
                  <span className="block font-mono text-[10.5px] font-semibold tracking-wider text-text-weak uppercase">
                    Registrar o Actualizar Credencial
                  </span>
                  <div className="space-y-2">
                    <Select value={secretName} onValueChange={setSecretName}>
                      <SelectTrigger>
                        <SelectValue placeholder="Seleccionar fuente" />
                      </SelectTrigger>
                      <SelectContent>
                        {THIRD_PARTY_KEYS.map((k) => (
                          <SelectItem key={k.id} value={k.id}>
                            {k.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>

                    <div className="flex gap-2">
                      <div className="flex-1">
                        <TextField
                          type="password"
                          placeholder="pegar API key…"
                          value={secretValue}
                          onChange={(e) => setSecretValue(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") void saveSecret();
                          }}
                        />
                      </div>
                      <Button
                        variant="secondary"
                        onClick={() => void saveSecret()}
                        disabled={!secretValue.trim() || isSavingSecret}
                        title="Guardar en la bóveda local del engine"
                      >
                        {isSavingSecret ? "Guardando…" : "Guardar"}
                      </Button>
                    </div>

                    {secretMsg && (
                      <p className="font-mono text-[11px] text-text-brand mt-1" role="status">
                        {secretMsg}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* PESTAÑA: PARÁMETROS AGENTE */}
            {activeTab === "params" && (
              <div className="space-y-3">
                <div className="rounded-md border border-border-weak-base bg-surface-inset-base/40 divide-y divide-border-weak-base">
                  <div className="p-3.5 flex items-start justify-between gap-4">
                    <div className="space-y-0.5 min-w-0 flex-1">
                      <div className="font-sans text-[12.5px] font-medium text-text-strong">
                        Streaming de tokens en vivo (SSE)
                      </div>
                      <div className="font-sans text-[11px] text-text-weak leading-normal">
                        Transmite la inferencia palabra por palabra en la consola en tiempo real conforme el modelo genera tokens.
                      </div>
                    </div>
                    <Checkbox
                      checked={runOptions.stream}
                      onCheckedChange={(checked) => setRunOptions({ stream: Boolean(checked) })}
                    />
                  </div>

                  <div className="p-3.5 flex items-start justify-between gap-4">
                    <div className="space-y-0.5 min-w-0 flex-1">
                      <div className="font-sans text-[12.5px] font-medium text-text-strong">
                        Supervisión de plan estructurado
                      </div>
                      <div className="font-sans text-[11px] text-text-weak leading-normal">
                        Fuerza al agente a estructurar y publicar un árbol de pasos forenses antes de iniciar recolecciones masivas.
                      </div>
                    </div>
                    <Checkbox
                      checked={runOptions.planFirst}
                      onCheckedChange={(checked) => setRunOptions({ planFirst: Boolean(checked) })}
                    />
                  </div>

                  <div className="p-3.5 flex items-start justify-between gap-4">
                    <div className="space-y-0.5 min-w-0 flex-1">
                      <div className="font-sans text-[12.5px] font-medium text-text-strong">
                        Ejecución autónoma (auto-aprobación)
                      </div>
                      <div className="font-sans text-[11px] text-text-weak leading-normal">
                        Ejecuta colectores pasivos y activos de forma desatendida sin solicitar confirmación manual interactiva por cada herramienta.
                      </div>
                    </div>
                    <Checkbox
                      checked={runOptions.autoApprove}
                      onCheckedChange={(checked) => setRunOptions({ autoApprove: Boolean(checked) })}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* PESTAÑA: SERVIDOR & ESTADO */}
            {activeTab === "server" && (
              <div className="space-y-3">
                <div className="rounded-md border border-border-weak-base bg-surface-inset-base/40 divide-y divide-border-weak-base">
                  <div className="p-3.5 flex items-center justify-between gap-4">
                    <div className="space-y-0.5">
                      <div className="font-sans text-[12.5px] font-medium text-text-strong">
                        Estado del Engine
                      </div>
                      <div className="font-sans text-[11px] text-text-weak">
                        Daemon FastAPI headless responsable de colectores, base de datos y ledger forense.
                      </div>
                    </div>
                    <Tag size="normal" tone={engineOnline ? "success" : "critical"} className="font-mono text-[10px] uppercase">
                      {engineOnline ? "en línea" : "desconectado"}
                    </Tag>
                  </div>

                  <div className="p-3.5 flex items-center justify-between gap-4">
                    <div className="space-y-0.5">
                      <div className="font-sans text-[12.5px] font-medium text-text-strong">
                        URL de Conexión
                      </div>
                      <div className="font-sans text-[11px] text-text-weak">
                        Endpoint HTTP/SSE consumido por el cliente desktop.
                      </div>
                    </div>
                    <span className="font-mono text-[11px] text-text-strong px-2 py-0.5 rounded bg-surface-inset-base border border-border-weak-base">
                      {engineUrl}
                    </span>
                  </div>

                  <div className="p-3.5 flex items-center justify-between gap-4">
                    <div className="space-y-0.5">
                      <div className="font-sans text-[12.5px] font-medium text-text-strong">
                        Versión de Plataforma
                      </div>
                      <div className="font-sans text-[11px] text-text-weak">
                        {engineHealth?.version ? `Build ${engineHealth.version}` : "Versión local activa"}
                      </div>
                    </div>
                    <span className="font-mono text-[11px] text-text-weak px-2 py-0.5 rounded bg-surface-inset-base border border-border-weak-base">
                      v{__APP_VERSION__}
                    </span>
                  </div>

                  <div className="p-3.5 flex items-center justify-between gap-4">
                    <div className="space-y-0.5">
                      <div className="font-sans text-[12.5px] font-medium text-text-strong">
                        Token de Autorización Bearer
                      </div>
                      <div className="font-sans text-[11px] text-text-weak">
                        Aislamiento entre procesos mediante token de sesión generado al vuelo.
                      </div>
                    </div>
                    <span className="font-mono text-[11px] text-text-weak px-2 py-0.5 rounded bg-surface-inset-base border border-border-weak-base">
                      {engineToken ? "•••••••• (activo)" : "sin token (modo dev)"}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Pie de acción */}
          <div className="flex items-center justify-end border-t border-border-weak-base px-6 py-3 bg-surface-raised-base/80">
            <Button variant="primary" size="small" onClick={() => onOpenChange(false)}>
              Listo
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default ModelSelector;
