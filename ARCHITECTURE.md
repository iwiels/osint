# SpecterOSINT — Arquitectura

> Plataforma forense OSINT de escritorio. Motor Python headless + consola Electron.
> Inspirada en la arquitectura cliente/servidor de [opencode](https://github.com/sst/opencode).

## Visión de alto nivel

```
┌──────────────────────────────────────────────────────────────────┐
│                    SpecterOSINT Desktop (.exe NSIS)               │
│                                                                  │
│  ┌──────────────────┐  spawn   ┌───────────────────────────────┐ │
│  │ Electron Main    │─────────▶│  specter-engine.exe (sidecar) │ │
│  │ - ventana        │  :8787   │  Python + FastAPI + uvicorn   │ │
│  │ - ciclo de vida  │◀─────────│  - /health  /tools  /cases    │ │
│  │ - taskkill árbol │  REST+SSE│  - /agent/run  /events (SSE)  │ │
│  │ - token Bearer   │  +Bearer │  - registry MCP (40 tools)    │ │
│  └────────┬─────────┘          │  - ledger HMAC-SHA256 + grafo │ │
│           │ contextBridge      └───────────────────────────────┘ │
│           ▼                                                       │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │ Renderer (React + Zustand) — habla con el engine por HTTP/SSE ││
│  │  Sidebar casos │ Chat central AgentConsole │ Evidencias       ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

## Principios (aprendidos de opencode)

1. **Motor headless, clientes tontos.** El motor (kernel forense) vive en su propio
   proceso y expone una API HTTP local. Electron, el CLI, OpenCode (MCP) o un script
   son solo clientes. Nada de lógica de negocio en la UI.
2. **Registry único de tools.** Las 41 tools forenses MCP se registran una vez y se
   consumen desde tres superficies: UI (REST), agente IA (function-calling) y clientes
   MCP externos (stdio, compatibilidad legada).
   Entre ellas, el navegador sigiloso OSINT (`browser_snapshot`, `browser_screenshot`,
   `browser_interact`, `browser_rotate_identity`, `browser_status`): Chromium real con
   capa anti-bot (huellas rotables, ritmo humano, detección de CAPTCHA/WAF) y cada
   captura sellable en la cadena de custodia (bloque HMAC + SHA-256 del payload).
3. **Nada de navegador en el proceso main.** El navegador sigiloso (Playwright +
   Chromium headless) corre dentro del engine Python (`specter.stealth_browser`),
   aislado de la UI: un crash del subsistema de navegador (0xC0000005) no tumba la
   app; el colector cae a su fallback HTTP y el engine sigue sirviendo /health.
   Antes vivía en Electron (`browser_engine.ts`) y era la causa raíz de los crashes
   recurrentes del proceso principal.
4. **Event bus tipado.** Todo lo que pasa en el motor se publica como evento
   (`agent.*`, `tool.*`, `permission.*`, `case.*`) y se consume por SSE. La UI es una
   proyección del estado del motor.
5. **Permission gate.** El agente no ejecuta herramientas sensibles sin aprobación
   explícita del analista (`Permission.ask`), igual que el gate de bash de opencode.
6. **Provider-agnostic.** Anthropic, OpenAI y cualquier endpoint OpenAI-compatible
   (Ollama, LM Studio, vLLM) sin dependencias de SDK: HTTP + JSON puro.

## Estructura del monorepo

```
specter-osint/
├── engine/                     # MOTOR PYTHON (sidecar headless)
│   ├── http_server.py          #   FastAPI: REST + SSE + agent endpoints
│   ├── agent.py                #   loop agente multi-provider + permissions
│   ├── registry.py             #   acceso unificado al registro MCP
│   └── specter/                #   KERNEL FORENSE (inalterado, antes src/)
│       ├── server.py           #     40 tools MCP (create_case, investigate_*…)
│       ├── osint_core/         #     Database (SQLite/WAL), Graph (NetworkX),
│       │                       #     ForensicLedger (SHA-256), models (Pydantic),
│       │                       #     entity_resolution (Fellegi-Sunter), admiralty
│       │                       #     (6x6 + decay), solar (cronolocalización)
│       ├── collectors/         #     DNS, TLS, crt.sh, RDAP, identidad (WMN 700+
│       │                       #     plataformas), GitHub forensics, dorks, archivos
│       │                       #     warc_capture (ISO 28500 vía CDP)
│       ├── httpx_transport.py  #     transporte curl_cffi con impersonación TLS Chrome
│       └── visualizer/         #     Dossier HTML autónomo + Markdown
├── packages/
│   └── sdk/                    # @specter/sdk — cliente TypeScript tipado
│       ├── src/index.ts        #   SpecterClient (HTTP tipado)
│       ├── src/types.ts        #   dominio espejo de los modelos Pydantic
│       └── src/sse.ts          #   cliente del event bus
├── desktop/                    # APP ELECTRON
│   ├── src/main/               #   proceso principal + EngineSidecar
│   ├── src/preload/            #   contextBridge mínimo (revealInFolder)
│   └── src/renderer/
│       ├── ui/                 #   PRIMITIVAS sin lógica de negocio (button, text-field,
│       │                       #   select, tabs, accordion, dialog, tag…) + CSS hermano
│       ├── styles/             #   colors/theme (tokens) + tailwind.css (@theme) +
│       │                       #   base/legacy/prose/utilities y orden de capas (index.css)
│       └── components/         #   VISTAS: Sidebar / CaseView / AgentConsole / DockPrompt
│           ├── chat/           #   compositor, mensajes e historial de sesión del agente
│           ├── evidence/       #   GraphCanvas (D3/force-graph), LedgerTable, Timeline
│           └── ErrorBoundary.tsx #   frontera de error: un panel caído no tumba la app
├── scripts/
│   ├── postinstall.js          #   prepara venv del engine
│   ├── build-engine.py         #   PyInstaller → dist-engine/specter-engine.exe
│   └── smoke_http.py           #   test E2E del engine HTTP
├── docs/
│   ├── adr/                    #   decisiones de arquitectura (ADRs)
│   ├── agents/                 #   personas y playbooks del agente investigador
│   └── ui-rules.md             #   reglas de diseño de la consola
├── data/                       #   RUNTIME (no versionado): specter_osint.db,
│                              #   ledger.key, cache/ y wmn-data.json
├── reports/                    #   RUNTIME (no versionado): dossiers generados
└── tests/                      #   pytest (kernel+agente) — 37 ficheros verdes
```

## Flujos clave

### 1. Arranque de la app (producción)

```
usuario abre SpecterOSINT.exe
  └─ main process: EngineSidecar.start()
       ├─ probe http://127.0.0.1:8787/health (¿ya corre?)
       ├─ spawn resources/engine/specter-engine.exe --port 8787
       └─ waitForHealth (reintentos ~15s)
  └─ BrowserWindow carga renderer con ?engine=http://127.0.0.1:8787
  └─ renderer: health-check + subscribe SSE + carga de casos
```

### 2. Investigación con el agente

```
usuario: "investiga acme.com"
  └─ POST /agent/run {case_id, message, provider…}
       └─ engine/agent.py:
            ├─ system prompt (rol forense + contexto del caso)
            ├─ POST al provider (anthropic|openai|opencode|ollama) con tools schema
            │    (429 del gateway → retry-after/backoff + evento agent.rate_limited)
            ├─ model devuelve tool_use → ¿sensible?
            │    ├─ sí → publica permission.request (SSE) y BLOQUEA
            │    │        hasta POST /agent/permissions/respond
            │    └─ no → ejecuta vía registry (validación pydantic)
            ├─ publica tool.started / tool.completed (SSE)
            ├─ feed del resultado al modelo … loop hasta respuesta final
            └─ cada recolección queda asegurada en el ledger SHA-256
```

### 3. Cadena de custodia (núcleo forense, sin cambios)

Cada acción de colector añade un bloque al ledger: `SHA-256(prev_hash + payload)`.
`verify_case_integrity` audita la cadena completa. El bloque génesis se crea con el caso.

## Decisiones de diseño

| Decisión | Alternativa descartada | Motivo |
|---|---|---|
| Python como sidecar | Reescribir kernel en TS | El kernel forense (ledger, NetworkX, 10 colectores) está probado; reescribir = meses de riesgo. Mismo patrón que opencode: motor separado del cliente. |
| HTTP+FastAPI (no stdio) | Solo MCP stdio | SSE en vivo, multi-cliente, debuggable con curl; stdio MCP sigue disponible por compatibilidad. |
| Registry MCP interno | Duplicar definiciones de tools | Una sola fuente de verdad: las tools se definen en `specter/server.py` con decoradores (`/tools` y `/health.mcp_tools` lo confirman en vivo). |
| Grafo canvas (force-graph) | Cytoscape.js/d3/SVG propio | Canvas con simulación de fuerzas para cientos de nodos; la tabla del ledger queda como alternativa textual. |
| API keys por sesión | Keytar/credenciales del SO | Simple y explícito; el motor exige Bearer local y corre solo en localhost. Keytar en roadmap. |
| Contrato ejecutable motor↔UI | Tipos TS manuales | La deriva silenciosa (canvas negro por `source` vs `source_id`) se vuelve ruidosa: `response_model` valida en runtime, `tests/test_contract.py` fija las claves y `npm run gen:sdk:check` regenera `generated.ts` desde `/openapi.json` y falla ante deriva. |
| Staleness imposible en dev | Reutilizar puerto ocupado | El sidecar mata al ocupante del :8787 y arranca desde fuente en cada lanzamiento (el flag `--reload` existe pero no se usa por defecto: en Windows el handoff del socket colgó el worker en 2026-09-26); `/health` expone `version` + `build_hash` (git vivo en dev, sellado en el exe) que la UI muestra en el badge. |

## Frontend (renderer)

Arquitectura portada de opencode (`packages/ui`, `packages/session-ui`, `packages/app`),
adaptada a React + Tailwind v4 + zustand:

- **Tres capas**: `ui/` (primitivas sin datos) → `components/` (vistas y dominio) →
  `styles/` (tokens). En `ui/` no hay llamadas al engine ni estado global.
- **Un archivo por primitiva con su CSS hermano** (`ui/button.tsx` + `ui/button.css`) y
  contrato por atributos: el CSS selecciona `[data-component="button"][data-variant="primary"]`
  y `[data-slot="…"]`, así el JSX no acumula clases condicionales.
- **Capas CSS** declaradas una sola vez en `styles/index.css`:
  `theme → base → components → utilities`. Tokens en `styles/colors.css` (primitivas y
  semánticos por rol) y `styles/theme.css` (tipografía, radios, sombras); el mapeo a
  utilidades de Tailwind vive en `styles/tailwind.css` (`@theme`, con la paleta por defecto
  desactivada: si un color no está en el sistema, no existe).
- **Estado de UI** en `store.ts` (zustand) por dominio; el engine se toca siempre vía `@specter/sdk`.
- **Layout chat-first**: raíl de casos (`Sidebar`: expedientes + conversaciones con buscador y borrado) | chat central (`AgentConsole`, máx. 840px)
  | panel de evidencias (`CaseView`, 540px plegable con Ctrl+J). Una sola navegación por tabs WCAG en el header (Chat/Grafo/Timeline/Correlaciones/Custodia, con conteos y atajos Ctrl+1..5); las vistas de evidencia se manejan por prop (`hideTabs`), sin tab-bars duplicados. El chat funciona sin
  caso activo (runs globales); el token Bearer del engine llega por IPC, nunca en la URL.
- **Migración en curso**: `Sidebar` y la cabecera de `App` ya usan `ui/`; `AgentConsole`,
  `CaseView` y `DockPrompt` siguen sobre el puente de compatibilidad (`styles/legacy.css`),
  que se elimina cuando terminen de migrarse (el hook `useAutoScroll` de `ui/` ya se usa).

### Accesibilidad y ventana estrecha

- **Contraste**: `npm run a11y:contrast` (`scripts/a11y-contrast.mjs`) resuelve los tokens de
  `styles/colors.css` (`var()`, `light-dark()`, `color-mix()`) y audita los pares texto/fondo
  y control/fondo en claro y oscuro contra WCAG 2.2 AA (4.5 texto, 3.0 gráficos y controles,
  1.2 hairlines decorativas). Es un gate de `npm run verify`: un token mal elegido rompe la CI.
- **Foco**: anillo sólido global `--focus-ring` (no translúcido, para que se vea sobre
  cualquier superficie) + `scroll-margin-block` para que el foco nunca quede bajo la cabecera
  (2.4.11). Plegar un panel que contiene el foco lo devuelve al botón que lo gobierna.
- **ARIA en las primitivas**: Radix aporta los roles de diálogo/menú/pestaña/tooltip; encima,
  `TextField` asocia etiqueta/descripción/error (`role="alert"`), `Checkbox`/`Switch` generan
  id si no se les pasa uno, `DialogContent` avisa si falta título, `Spinner` es `role="status"`,
  `Keybind` oculta las teclas sueltas y publica el atajo como una sola cadena.
  En las vistas: `role="log"` con `aria-relevant="additions"` en el chat (anuncia mensajes
  nuevos, no cada token del streaming), `role="tablist"`/`tabpanel` con foco móvil (sólo la
  pestaña activa es tabulable, las flechas mueven el foco) en `CaseView`, docks con
  `role="group"`+nombre y foco al aparecer, tablas con `caption` sr-only
  y `scope="col"`, y el canvas del grafo anunciado como grupo con su resumen.
- **Ventana estrecha**: los paneles son plegables (`store.panels`) con atajos `Ctrl+B`
  (casos) y `Ctrl+J` (consola), botones en la cabecera con `aria-expanded`/`aria-controls`,
  y plegado automático al cruzar los umbrales de `PANEL_BREAKPOINTS` (sidebar < 1100px,
  consola < 900px) para que el expediente conserve el ancho útil. Además el raíl de casos
  cede ancho (`max-width: 38vw`) y la consola se limita a `46vw` antes de plegarse.

## Calidad y CI/CD

La calidad no es un deseo: es un pipeline ejecutable. `npm run verify` reproduce
localmente lo que la CI hace cumplir (gates en paralelo):

| Job | Gates |
|---|---|
| `engine` (Python) | `ruff check` + `ruff format` + pytest con cobertura ≥ 80% |
| `web` (TypeScript) | typecheck estricto + vitest con cobertura (SDK ~99%) + build |
| `release` (tag `v*`) | PyInstaller del engine → electron-builder → GitHub Release con .exe |

Los umbrales siguen la **estrategia ratchet** ([ADR-004](docs/adr/adr-004-quality-ratchet.md)):
solo suben, nunca bajan. Las decisiones de arquitectura viven en
[docs/adr/](docs/adr/README.md) y las convenciones para contribuir en
[CONTRIBUTING.md](CONTRIBUTING.md) (incluye la Definition of Done).

## Roadmap

- **H1 (actual)** — plataforma desktop: engine HTTP, agente multi-provider, grafo,
  custodia, dossiers, instalador NSIS.
- **H2** — mapa de grafo interactivo (drag, filtros por tipo, timeline de
  correlaciones), edición manual de entidades, importación de evidencias.
- **H3** — multi-caso con etiquetas/ETL y exportación STIX 2.1 (ya disponible);
  integración TAXII, compartimentación por investigación y modo equipo (engine remoto
  opcional con auth).
- **H4** — plugins (hooks pre/post tool como opencode), marketplace de colectores,
  actualizador automático (electron-updater) y firma de código.
