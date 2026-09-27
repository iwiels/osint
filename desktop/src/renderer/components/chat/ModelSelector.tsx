import { useCallback, useEffect, useState } from "react";
import type { SecretEntry, SpecterClient } from "@specter/sdk";
import { useStore } from "../../store";
import {
  Button,
  Checkbox,
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  IconButton,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  TextField,
} from "../../ui";

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

export interface ModelSelectorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  client: SpecterClient;
}

export function ModelSelector({ open, onOpenChange, client }: ModelSelectorProps) {
  const provider = useStore((s) => s.provider);
  const setProvider = useStore((s) => s.setProvider);
  const engineOnline = useStore((s) => s.engineOnline);
  const runOptions = useStore((s) => s.runOptions);
  const setRunOptions = useStore((s) => s.setRunOptions);

  const [secrets, setSecrets] = useState<SecretEntry[] | null>(null);
  const [secretName, setSecretName] = useState(THIRD_PARTY_KEYS[0].id);
  const [secretValue, setSecretValue] = useState("");
  const [secretMsg, setSecretMsg] = useState<string | null>(null);

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
    try {
      const res = await client.setSecret(secretName, secretValue.trim());
      setSecrets(res.secrets);
      setSecretValue("");
      setSecretMsg("Clave guardada en la bóveda local.");
    } catch (err) {
      setSecretMsg(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const removeSecret = async (name: string) => {
    try {
      const res = await client.deleteSecret(name);
      setSecrets(res.secrets);
    } catch {
      // refresh will reflect state
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title="Motor Analítico y Credenciales"
        description="Configura el núcleo de inferencia y administra las credenciales seguras de fuentes forenses."
        size="normal"
      >
        <DialogBody className="max-h-[70vh] overflow-y-auto space-y-4 pr-1">
          <div className="space-y-3">
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

            {/* API Key field */}
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

            <div className="rounded-md border border-border-weak-base bg-surface-inset-base p-2.5 text-[11.5px] leading-relaxed text-text-weak">
              {provider.provider === "opencode" ? (
                <span>
                  <strong className="text-text-strong">Acceso Anónimo:</strong> El modelo{" "}
                  <code className="rounded bg-surface-raised-strong px-1 py-0.5 font-mono text-text-brand">
                    space-bunny-free
                  </code>{" "}
                  no requiere API key ni cuenta. Si ingresas tu credencial de{" "}
                  <span className="text-text-strong">opencode.ai/zen</span> desbloqueas los modelos
                  avanzados.
                </span>
              ) : (
                <span>
                  Configura la clave del proveedor o asegúrate de haberla definido en las variables de
                  entorno del servidor engine.
                </span>
              )}
            </div>
          </div>

          <div className="border-t border-border-weak-base pt-3">
            <span className="mb-1 block font-mono text-[11px] font-semibold tracking-wider text-text-weak uppercase">
              Bóveda de Credenciales Forenses
            </span>
            <p className="mb-2 text-[11px] leading-relaxed text-text-weak">
              VirusTotal, Shodan, GreyNoise, AbuseIPDB y Hunter.io solo se usan si su key está en la
              bóveda (o en variables de entorno). Sin key, el motor omite esas fuentes de enriquecimiento.
            </p>

            {secrets === null ? (
              <p className="text-[11px] text-text-weak">Bóveda no disponible (engine offline).</p>
            ) : (
              <div className="mb-3 space-y-1.5 rounded-md border border-border-weak-base bg-surface-inset-base p-2">
                {THIRD_PARTY_KEYS.map((k) => {
                  const entry = secrets.find((s) => s.name === k.id);
                  const on = entry?.configured ?? false;
                  return (
                    <div
                      key={k.id}
                      className="flex items-center justify-between gap-2 rounded px-1.5 py-1 text-[11.5px] hover:bg-surface-raised-strong/50"
                    >
                      <div className="flex min-w-0 items-center gap-2">
                        <span
                          className={`size-2 shrink-0 rounded-full ${
                            on ? "bg-success" : "bg-surface-raised-stronger"
                          }`}
                          title={on ? `Configurada ${entry?.masked ?? ""}` : "Sin configurar"}
                        />
                        <span className="truncate text-text-base" title={k.label}>
                          {k.label}
                        </span>
                      </div>
                      {on && (
                        <IconButton
                          name="close"
                          label={`Borrar ${k.id} de la bóveda`}
                          size="small"
                          onClick={() => void removeSecret(k.id)}
                          className="size-5 shrink-0 text-text-weak hover:text-text-critical"
                        />
                      )}
                    </div>
                  );
                })}
              </div>
            )}

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
                  disabled={!secretValue.trim()}
                  title="Guardar en la bóveda local del engine"
                >
                  Guardar
                </Button>
              </div>
              {secretMsg && (
                <p className="font-mono text-[11px] text-text-brand" role="status">
                  {secretMsg}
                </p>
              )}
            </div>
          </div>

          {/* Run Options */}
          <div className="border-t border-border-weak-base pt-3 space-y-2">
            <span className="mb-1 block font-mono text-[11px] font-semibold tracking-wider text-text-weak uppercase">
              Parámetros de Ejecución
            </span>
            <Checkbox
              label="Streaming de tokens en vivo (SSE)"
              checked={runOptions.stream}
              onCheckedChange={(checked) => setRunOptions({ stream: Boolean(checked) })}
            />
            <Checkbox
              label="Supervisión de plan (investigación estructurada)"
              checked={runOptions.planFirst}
              onCheckedChange={(checked) => setRunOptions({ planFirst: Boolean(checked) })}
            />
            <Checkbox
              label="Ejecución autónoma (empezar directo sin pedir permisos)"
              checked={runOptions.autoApprove}
              onCheckedChange={(checked) => setRunOptions({ autoApprove: Boolean(checked) })}
            />
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="primary" onClick={() => onOpenChange(false)}>
            Listo
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
export default ModelSelector;
