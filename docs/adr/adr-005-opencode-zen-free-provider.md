# ADR-005: Provider OpenCode Zen (modelos free) con reintentos ante rate limit

- Estado: aceptada con enmienda (2026-09-26)
- Fecha: 2026-09-24

> Nota 2026-09-26: el bridge por CLI local (`zen`, `engine/zen_bridge.py`) se
> eliminó y también la auto-lectura del `auth.json` de OpenCode. El proyecto no
> usa `opencode auth login` ni comparte sesiones/config. Sigue vigente el
> provider HTTP (`opencode` → `https://opencode.ai/zen/v1`) con free anónimo
> (`Bearer public`) o key propia (petición → env `OPENCODE_API_KEY` → bóveda),
> más los reintentos ante 429 de esta ADR.

## Contexto

Specter Desktop necesita un provider sin coste para que el agente investigador
funcione out-of-the-box. OpenCode publica **Zen**, un gateway con modelos
verificados por su equipo, varios de ellos gratuitos por tiempo limitado
("Big Pickle", "MiMo Free", "Nemotron Free", etc.). La experiencia de usuario
reportada: la cuota free se agota al rato y el gateway responde pidiendo
esperar un tiempo.

Verificado contra la fuente de opencode (docs y `packages/opencode/src/`):

- **Base URL**: `https://opencode.ai/zen/v1`, **OpenAI-compatible**. Los modelos
  de la familia DeepSeek/GLM/Kimi/MiniMax/free se sirven en
  `/chat/completions` (`@ai-sdk/openai-compatible`), que es justo el camino que
  nuestro engine ya tiene (`_step_openai_compatible`).
- **Auth**: `Authorization: Bearer <OPENCODE_API_KEY>`. El CLI guarda la key en
  `auth.json` bajo el data dir de la app (`{"opencode": {"type": "api",
  "key": "…"}}`), respaldado por `packages/opencode/src/auth/index.ts`.
- **Rate limit**: el gateway responde 429 indicando cuánto esperar; el propio
  opencode **respeta el header `retry-after`** al reintentar
  (verificado en su capa de errores `provider/error.ts`).

## Decisión

1. **Provider `opencode`** en `engine/agent.py` reutilizando el camino
   OpenAI-compatible (cero código de protocolo nuevo): solo una entrada en
   `PROVIDERS` (`base_url=https://opencode.ai/zen/v1`,
   `default_model=space-bunny-free`, el único free anónimo verificado) y la
   constante `FREE_ZEN_MODELS` para validar que el default sea free.
2. ~~**Descubrimiento de credenciales en cadena**, igual que hace opencode:
   key explícita en la petición → env `OPENCODE_API_KEY` → `auth.json` local
   del CLI.~~ **Histórico (eliminado 2026-09-26)**: la cadena ahora es petición
   → env `OPENCODE_API_KEY` → bóveda local. El `auth.json` de OpenCode ya no
   se lee; el proyecto no usa `opencode auth login`.
3. **Rate limit como ciudadano de primera clase**: `_call_step_with_retry`
   reintenta 429/5xx (máx. 3) respetando `retry-after` (segundos o HTTP-date,
   con tope de 60 s) y, si no viene, backoff exponencial (1.5 s × 2ⁿ, tope
   60 s). Cada reintento publica el evento SSE **`agent.rate_limited`**
   (attempt, wait_seconds, status) para que la UI muestre el cool-down
   ("⏳ esperando X s…") en vez de fallar en seco.
4. **UI**: opción "OpenCode Zen (free)" en AgentConsole con dropdown de los
   modelos free actuales (la lista vive en un solo lugar y se actualiza con los
   docs de Zen) y hint explicando la cuota. El evento `agent.rate_limited` se
   cablea en `App.tsx` junto al resto de eventos SSE.

## Consecuencias

- ✅ Coste $0 para empezar a investigar; sube la adopción del agente.
- ✅ Sin SDK nuevo: HTTP+JSON como el resto de providers (coherente con ADR-001).
- ✅ El cool-down es observable por el usuario (SSE) y testeado sin red.
- ⚠️ Los model IDs free son efímeros ("available for a limited time"): el
  dropdown puede quedarse corto/limpio; el campo acepta cualquier ID nuevo.
- ⚠️ La cuota free sigue agotándose: los reintentos no saltan límites diarios;
  tras MAX_RETRIES el error original se propaga tal cual.
- ⚠️ Si el usuario nunca se logueó en opencode, tendrá que pegar su key Zen
  (o exportar `OPENCODE_API_KEY`) — no hacemos OAuth propio.
