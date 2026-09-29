# WraithOSINT

> Plataforma forense de inteligencia OSINT de escritorio.
> Motor Python headless + consola Electron instalable, con cadena de custodia
> criptográfica, grafo de conocimiento y agente investigador IA multi-provider.

[![CI](https://github.com/iwiels/osint/actions/workflows/ci.yml/badge.svg)](https://github.com/iwiels/osint/actions/workflows/ci.yml)
[![Release](https://github.com/iwiels/osint/actions/workflows/release.yml/badge.svg)](https://github.com/iwiels/osint/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-584-brightgreen.svg)](#calidad)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#instaladores)

> [!WARNING]
> **Uso responsable.** WraithOSINT recopila información de fuentes abiertas y
> tiene capacidades de doble uso (impersonación TLS, navegador sigiloso,
> enumeración de cuentas opt-in). Úsalo solo con base legal y finalidad
> legítima: periodismo, respuesta a incidentes, threat intel, derechos humanos
> o due diligence. **No** está destinado a stalking, doxing ni vigilancia no
> consentida. Lee [LEGAL.md](LEGAL.md) antes de operarlo.

## Qué es

WraithOSINT es una plataforma autónoma con su propio motor y su propia interfaz
desktop, al estilo de otras apps Electron profesionales.

- **Motor forense** (Python, headless): 47 herramientas MCP de recolección y
  análisis — DNS/TLS, Certificate Transparency, RDAP, perfiles en +700 sitios
  (WhatsMyName), forensia de GitHub, caza de documentos, metadatos de archivos y
  grafo de conocimiento. Cada caso tiene un ledger encadenado SHA-256 con firma
  HMAC local opcional. La captura WARC 1.1 se puede reproducir en
  ReplayWeb.page; su manifiesto identifica cuerpos ausentes o truncados. El
  formato WARC no certifica por sí solo la custodia. El motor también incluye
  transporte curl_cffi con suplantación de la huella TLS de Chrome, scoring
  explicable de enlaces Fellegi-Sunter (aún sin calibración empírica), helpers
  inspirados en Almirantazgo y ventanas temporales solares calculadas a partir
  de sombras (UTC).
- **Consola desktop** (Electron + React): gestión de casos, visualización del
  grafo, auditoría de cadena de custodia y **consola de agente IA** que orquesta
  las herramientas forenses con approval humana (diálogo de permisos del agente +
  permission gate fail-closed en las llamadas directas a la API).
- **Multi-provider**: Anthropic, OpenAI, **OpenCode Zen (modelos free con
  reintento automático ante rate limit)**, Ollama (local) o cualquier endpoint
  OpenAI-compatible.
- **Compatibilidad MCP**: las mismas herramientas siguen consumibles desde otro
  cliente MCP por stdio.

## Arquitectura en 30 segundos

```
┌─────────────────────────────────────────────┐
│           WraithOSINT Desktop (Win/mac/Linux) │
│                                             │
│  Electron UI  ◀──HTTP/SSE──▶  Engine :8787  │
│  (React)        REST + SSE    (Python       │
│                               sidecar)      │
└─────────────────────────────────────────────┘
```

Detalle completo en [ARCHITECTURE.md](ARCHITECTURE.md).

## Instaladores

Cada release publica instaladores nativos para las tres plataformas. El motor
viaja dentro del paquete (PyInstaller onefile): **no hace falta tener Python
instalado**.

| Plataforma | Artefacto | Notas |
|---|---|---|
| **Windows** | `WraithOSINT-<ver>-win-x64-setup.exe` | NSIS por-usuario, no pide admin, crea acceso directo |
| **macOS** | `WraithOSINT-<ver>-mac-<arch>.dmg` / `.zip` | x64 y arm64. Sin firmar ni notarizar todavía |
| **Linux** | `WraithOSINT-<ver>-linux-x64.AppImage` / `.deb` | AppImage portable y paquete Debian |

Descárgalos desde la página de [Releases](../../releases). La CI de release los
compila en runners nativos (PyInstaller no cross-compila).

> **macOS**: los instaladores no están firmados ni notarizados todavía. Al abrir
> la app por primera vez hay que permitirla en Ajustes → Privacidad y seguridad.
> Para distribución sin fricción hace falta un certificado Developer ID y
> notarización (ver [roadmap](ARCHITECTURE.md#roadmap)).

Los datos del usuario (casos, dossiers, clave del ledger) viven en el directorio
de datos de la app (`%APPDATA%` en Windows, `~/Library/Application Support` en
macOS, `~/.config` en Linux), fuera del bundle, y sobreviven a las
actualizaciones.

## Inicio rápido (desarrollo)

Requisitos: Node 20+ y Python 3.11+ (o [uv](https://docs.astral.sh/uv/)).
Funciona en Windows, macOS y Linux.

```bash
# 1. Instalar dependencias JS + preparar venv del engine (postinstall)
npm install

# 2. Dependencias Python (si usas uv, o pip con el venv del engine)
uv pip install --python .venv/Scripts/python.exe -e .   # Windows
uv pip install --python .venv/bin/python -e .           # macOS / Linux
#    –o–  pip install -r engine/requirements.txt

# 3. Ejecutar la app en modo dev (arranca el engine automáticamente)
npm run dev
```

## Empaquetar instaladores

```bash
# 1. Binario del engine (PyInstaller onefile)
#    Windows: dist-engine/wraith-engine.exe
#    macOS / Linux: dist-engine/wraith-engine
npm run engine:build

# 2. Instalador de la plataforma en la que estás
npm run dist:win     # → desktop/release/WraithOSINT-<ver>-win-x64-setup.exe (NSIS)
npm run dist:mac     # → desktop/release/WraithOSINT-<ver>-mac-<arch>.dmg / .zip
npm run dist:linux   # → desktop/release/WraithOSINT-<ver>-linux-x64.AppImage / .deb
```

Empaqueta en la plataforma destino, o deja que la CI de release lo haga por ti
en runners nativos creando un tag `vX.Y.Z`.

## Engine standalone (sin Electron)

El motor es útil por sí mismo (CI, servidores, scripting):

```bash
# Genera un token para esta sesión (bash / zsh / PowerShell).
export SPECTER_ENGINE_TOKEN=$(python -c "import secrets; print(secrets.token_hex(32))")
python -m engine.http_server --port 8787
# En otra terminal, reutiliza el mismo token:
curl -H "Authorization: Bearer $SPECTER_ENGINE_TOKEN" http://127.0.0.1:8787/cases
curl -N "http://127.0.0.1:8787/events?token=$SPECTER_ENGINE_TOKEN"
# OpenAPI (Swagger UI): http://127.0.0.1:8787/docs
```

En PowerShell el equivalente es `$env:SPECTER_ENGINE_TOKEN = python -c "..."` y
`curl.exe` en lugar de `curl`.

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

## Convención de nombres

El producto se llama **WraithOSINT**, pero el motor conserva `specter` como
nombre interno del kernel forense. La regla es:

| Ámbito | Identificador | Ejemplo |
|---|---|---|
| Producto, UI, instaladores, docs | `Wraith*` | `WraithOSINT`, `@wraith/sdk`, `WraithClient` |
| Binario del motor | `wraith-engine` | `dist-engine/wraith-engine.exe` |
| Paquete Python del kernel | `specter` (interno) | `from specter.osint_core import ledger` |
| Variables de entorno | `SPECTER_*` | `SPECTER_ENGINE_TOKEN`, `SPECTER_DATA_DIR` |

Las variables de entorno y el paquete Python mantienen el nombre interno para no
romper scripts, tests y despliegues existentes. Están documentadas en
[.env.example](.env.example).

## Estructura del repo

| Ruta | Contenido |
|---|---|
| `engine/` | Motor Python: FastAPI (`http_server.py`), agente (`agent.py`), registro (`registry.py`) y kernel forense (`specter/`) |
| `packages/sdk` | `@wraith/sdk`, cliente TypeScript tipado (HTTP + SSE) |
| `desktop/` | App Electron (main / preload / renderer React) |
| `scripts/` | postinstall, build del engine (PyInstaller), smoke test, gate de contraste |
| `tests/` | Suite pytest (kernel + agente + contrato HTTP, 70 ficheros) |
| `docs/` | ADRs, personas del agente y reglas de UI |
| `skills/` | Playbooks investigativos que el agente puede cargar |

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
| `npm run dist:win` / `dist:mac` / `dist:linux` | Instaladores por plataforma |
| `python -m engine.http_server` | Motor headless standalone |

## Calidad

`npm run verify` reproduce localmente lo que la CI hace cumplir. La estrategia de
cobertura es **ratchet** ([ADR-004](docs/adr/adr-004-quality-ratchet.md)): los
umbrales solo suben.

| Gate | Herramienta | Umbral |
|---|---|---|
| Lint + formato Python | Ruff | sin deuda |
| Tests del engine | pytest (584 tests) | cobertura ≥ 80% |
| Contrato motor↔SDK | `gen_sdk_types.py --check` | sin deriva de `/openapi.json` |
| Contraste | `a11y-contrast.mjs` | WCAG 2.2 AA |
| Tipos TypeScript | `tsc --noEmit` | estricto |
| Tests del SDK | vitest | cobertura ~99% |

Las decisiones de arquitectura viven en [docs/adr/](docs/adr/README.md) y las
convenciones para contribuir en [CONTRIBUTING.md](CONTRIBUTING.md).

## Estado y roadmap

**H1 (actual)**: plataforma desktop operativa — engine HTTP con SSE, agente
multi-provider con diálogo de permisos, permission gate en la API directa,
grafo, cadena de custodia y dossiers. El borrado de casos por vía directa está
denegado por defecto (regla `delete/case:*`); se habilita por caso con
`add_permission_rule` (`action=delete`, `resource=case:<id>`, `effect=allow`).

**Preservación y análisis implementados**: hash WARC registrado en el ledger,
transporte TLS impersonado en los colectores que usan `httpx_transport`,
resolución Fellegi-Sunter explicable, puntuación Almirantazgo y
cronolocalización solar. Consulta los límites de integridad y uso en
[LEGAL.md](LEGAL.md).

Pendientes en [ARCHITECTURE.md](ARCHITECTURE.md#roadmap): grafo interactivo
(drag/filtros/timeline), integración TAXII, modo equipo, plugins y firma de
código.

## Créditos y terceros

- Dataset de [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) (MIT),
  redistribuido en `data/wmn-data.json`.
- Inspirado en el patrón cliente/servidor de [opencode](https://github.com/sst/opencode).
- Se apoya en [curl_cffi](https://github.com/lexiforest/curl_cffi),
  [patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright),
  [warcio](https://github.com/webrecorder/warcio),
  [NetworkX](https://networkx.org/), [FastAPI](https://fastapi.tiangolo.com/) y
  [Electron](https://www.electronjs.org/).

## Licencia

MIT — ver [LICENSE](LICENSE). La licencia cubre el código; el uso que hagas con
él es tuyo. [LEGAL.md](LEGAL.md) es parte del diseño, no un anexo: si
redistribuyes el proyecto, mantenlo.
