# SpecterOSINT

> Plataforma forense de inteligencia OSINT de escritorio.
> Motor Python headless + consola Electron instalable (.exe), con cadena de custodia
> criptográfica, grafo de conocimiento y agente investigador IA multi-provider.

[![tests](https://img.shields.io/badge/tests-265%2B-brightgreen)]() [![license](https://img.shields.io/badge/license-MIT-blue)]()

## Qué es

SpecterOSINT dejó de ser una capa que depende de OpenCode: ahora es una plataforma
autónoma con su propio motor y su propia interfaz desktop, al estilo Claude Desktop,
Antigravity u otras apps Electron profesionales.

- **Motor forense** (Python, headless): 32 herramientas de recolección y análisis —
  DNS/TLS forense, Certificate Transparency, RDAP, huella de identidad en +700
  plataformas (WhatsMyName), forensia de GitHub, caza de documentos y leaks, análisis
  de metadatos de archivos, grafo de conocimiento (NetworkX) y **ledger inmutable
  SHA-256** por caso.
- **Consola desktop** (Electron + React): gestión de casos, visualización del grafo,
  auditoría de cadena de custodia y **consola de agente IA** que orquesta las
  herramientas forenses con approval humana (permission gate).
- **Multi-provider**: Anthropic, OpenAI, **OpenCode Zen (modelos free con
  reintento automático ante rate limit)**, Ollama (local) o cualquier endpoint
  OpenAI-compatible.
- **Compatibilidad MCP**: las mismas herramientas siguen consumibles desde OpenCode
  u otro cliente MCP por stdio.

## Arquitectura en 30 segundos

```
┌─────────────────────────────────────────────┐
│         SpecterOSINT Desktop (.exe)         │
│                                             │
│  Electron UI  ◀──HTTP/SSE──▶  Engine :8787  │
│  (React)        REST + SSE    (Python       │
│                               sidecar)      │
└─────────────────────────────────────────────┘
```

Detalle completo en [ARCHITECTURE.md](ARCHITECTURE.md).

## Inicio rápido (desarrollo)

Requisitos: Node 20+, Python 3.11+ (o [uv](https://docs.astral.sh/uv/)).

```bash
# 1. Instalar dependencias JS + preparar venv del engine (postinstall)
npm install

# 2. Dependencias Python (si usas uv, o pip con el venv del engine)
uv pip install --python .venv/Scripts/python.exe -e . 
#    –o–  pip install -r engine/requirements.txt

# 3. Ejecutar la app en modo dev (arranca el engine automáticamente)
npm run dev
```

## Empaquetar el .exe de Windows

```bash
# 1. Binario del engine (PyInstaller onefile)
.venv/Scripts/python.exe scripts/build-engine.py
#    → dist-engine/specter-engine.exe

# 2. Instalador NSIS
npm run dist:win
#    → desktop/release/SpecterOSINT-<version>-setup.exe
```

El instalador es por-usuario (no pide admin), crea acceso directo y empaqueta el
motor como recurso: no requiere Python instalado en la máquina destino.

## Engine standalone (sin Electron)

El motor es útil por sí mismo (CI, servidores, scripting):

```bash
python -m engine.http_server --port 8787
# REST:   curl http://127.0.0.1:8787/cases
# SSE:    curl -N http://127.0.0.1:8787/events
# OpenAPI (Swagger UI): http://127.0.0.1:8787/docs
```

## Uso del agente desde la API

```bash
curl -X POST http://127.0.0.1:8787/agent/run \
  -H "Content-Type: application/json" \
  -d '{
    "case_id": "case-20260924-481a75",
    "message": "Investiga el dominio acme.com y enumera subdominios",
    "provider": "anthropic"
  }'
```

Las herramientas sensibles disparan `permission.request` por SSE; el analista
responde con `POST /agent/permissions/respond {request_id, decision}`.

## Estructura del repo

| Ruta | Contenido |
|---|---|
| `engine/` | Motor Python: FastAPI (`http_server.py`), agente (`agent.py`), registro (`registry.py`) y kernel forense (`specter/`) |
| `packages/sdk` | `@specter/sdk`, cliente TypeScript tipado (HTTP + SSE) |
| `desktop/` | App Electron (main / preload / renderer React) |
| `scripts/` | postinstall, build del engine (PyInstaller), smoke test |
| `tests/` | Suite pytest (kernel + agente + contrato HTTP, 27 ficheros) |

## Scripts

| Comando | Acción |
|---|---|
| `npm run dev` | App Electron en modo desarrollo (spawn del engine incluido) |
| `npm run build` | Build de producción de la app |
| `npm run typecheck` | TypeScript en SDK + desktop |
| `npm test` | Tests del SDK (vitest) |
| `npm run lint` | Ruff check + format del engine |
| `npm run test:py` | Suite pytest del engine |
| `npm run gen:sdk` / `gen:sdk:check` | Regenera / verifica tipos del SDK desde `/openapi.json` |
| `npm run a11y:contrast` | Auditoría de contraste WCAG 2.2 AA |
| `npm run engine:build` | Empaqueta el engine (PyInstaller) |
| `npm run smoke:engine` | Smoke test E2E del engine HTTP |
| `npm run verify` | Todo lo anterior en cadena (puerta de release) |
| `pytest` | Tests del kernel forense |
| `npm run dist:win` | Instalador Windows (.exe NSIS) |
| `python -m engine.http_server` | Motor headless standalone |

## Estado y roadmap

**H1 (actual)**: plataforma desktop operativa — engine HTTP con SSE, agente
multi-provider con permission gate, grafo, cadena de custodia y dossiers.

Pendientes en [ARCHITECTURE.md](ARCHITECTURE.md#roadmap): grafo interactivo
(drag/filtros/timeline), export STIX/TAXII, modo equipo, plugins y firma de código.

## Licencia

MIT
