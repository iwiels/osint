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
│  └────────┬─────────┘          │  - registry MCP (15 tools)    │ │
│           │ contextBridge      │  - ledger SHA-256 + grafo     │ │
│           ▼                    └───────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────┐│
│  │ Renderer (React + Zustand) — habla con el engine por HTTP/SSE ││
│  │  Sidebar casos │ CaseView (grafo SVG + ledger) │ AgentConsole ││
│  └──────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

## Principios (aprendidos de opencode)

1. **Motor headless, clientes tontos.** El motor (kernel forense) vive en su propio
   proceso y expone una API HTTP local. Electron, el CLI, OpenCode (MCP) o un script
   son solo clientes. Nada de lógica de negocio en la UI.
2. **Registry único de tools.** Las 15 tools forenses MCP se registran una vez y se
   consumen desde tres superficies: UI (REST), agente IA (function-calling) y clientes
   MCP externos (stdio, compatibilidad legada).
3. **Event bus tipado.** Todo lo que pasa en el motor se publica como evento
   (`agent.*`, `tool.*`, `permission.*`, `case.*`) y se consume por SSE. La UI es una
   proyección del estado del motor.
4. **Permission gate.** El agente no ejecuta herramientas sensibles sin aprobación
   explícita del analista (`Permission.ask`), igual que el gate de bash de opencode.
5. **Provider-agnostic.** Anthropic, OpenAI y cualquier endpoint OpenAI-compatible
   (Ollama, LM Studio, vLLM) sin dependencias de SDK: HTTP + JSON puro.

## Estructura del monorepo

```
specter-osint/
├── engine/                     # MOTOR PYTHON (sidecar headless)
│   ├── http_server.py          #   FastAPI: REST + SSE + agent endpoints
│   ├── agent.py                #   loop agente multi-provider + permissions
│   ├── registry.py             #   acceso unificado al registro MCP
│   └── specter/                #   KERNEL FORENSE (inalterado, antes src/)
│       ├── server.py           #     15 tools MCP (create_case, investigate_*…)
│       ├── osint_core/         #     Database (SQLite/WAL), Graph (NetworkX),
│       │                       #     ForensicLedger (SHA-256), models (Pydantic)
│       ├── collectors/         #     DNS, TLS, crt.sh, RDAP, identidad (WMN 700+
│       │                       #     plataformas), GitHub forensics, dorks, archivos
│       └── visualizer/         #     Dossier HTML autónomo + Markdown
├── packages/
│   └── sdk/                    # @specter/sdk — cliente TypeScript tipado
│       ├── src/index.ts        #   SpecterClient (HTTP tipado)
│       ├── src/types.ts        #   dominio espejo de los modelos Pydantic
│       └── src/sse.ts          #   cliente del event bus
├── desktop/                    # APP ELECTRON
│   ├── src/main/               #   proceso principal + EngineSidecar
│   ├── src/preload/            #   contextBridge mínimo (revealInFolder)
│   └── src/renderer/           #   React: Sidebar / CaseView / AgentConsole
├── scripts/
│   ├── postinstall.js          #   prepara venv del engine
│   ├── build-engine.py         #   PyInstaller → dist-engine/specter-engine.exe
│   └── smoke_http.py           #   test E2E del engine HTTP
├── data/                       #   specter_osint.db + wmn-data.json (runtime)
├── reports/                    #   dossiers generados
└── tests/                      #   pytest (kernel) — 9 tests verdes
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
            ├─ POST al provider (anthropic|openai|ollama) con tools schema
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
| Registry MCP interno | Duplicar definiciones de tools | Una sola fuente de verdad: las 15 tools se definen en `specter/server.py` con decoradores. |
| Grafo SVG propio | Cytoscape.js/d3 | Cero dependencias en el primer hito; el layout radial es determinista y suficiente. Revisitables con el hito de análisis. |
| API keys por sesión | Keytar/credenciales del SO | Simple y explícito; el motor corre solo en localhost. Keytar en roadmap. |

## Calidad y CI/CD

La calidad no es un deseo: es un pipeline ejecutable. `npm run verify` reproduce
localmente lo que la CI hace cumplir (gates en paralelo):

| Job | Gates |
|---|---|
| `engine` (Python) | `ruff check` + `ruff format` + pytest con cobertura ≥ 55% |
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
- **H3** — multi-caso con etiquetas/ETL de exportación (STIX/TAXII), compartimentación
  por investigación, modo equipo (engine remoto opcional con auth).
- **H4** — plugins (hooks pre/post tool como opencode), marketplace de colectores,
  actualizador automático (electron-updater) y firma de código.
