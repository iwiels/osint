# WraithOSINT

> A desktop OSINT forensics platform: a headless Python engine and an installable
> Electron console, with a cryptographic chain of custody, knowledge graph, and
> multi-provider AI investigator.

[![CI](https://github.com/iwiels/osint/actions/workflows/ci.yml/badge.svg)](https://github.com/iwiels/osint/actions/workflows/ci.yml)
[![Release](https://github.com/iwiels/osint/actions/workflows/release.yml/badge.svg)](https://github.com/iwiels/osint/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](#installers)

> [!WARNING]
> **Responsible use.** WraithOSINT collects information from open sources and
> includes dual-use capabilities (TLS impersonation, a stealth browser, and
> opt-in account enumeration). Use it only when you have a lawful basis and a
> legitimate purpose, such as journalism, incident response, threat intelligence,
> human rights work, or due diligence. It is not intended for stalking, doxing,
> or non-consensual surveillance. Read [LEGAL.md](LEGAL.md) before use.

## What it is

WraithOSINT is a standalone platform with its own engine and desktop interface.

- **Forensics engine** (Python, headless): MCP tools for DNS/TLS, Certificate
  Transparency, RDAP, profiles across 700+ sites (WhatsMyName), GitHub
  forensics, document discovery, file metadata, and knowledge graphs. Each case
  has a SHA-256 hash-chained ledger with optional local HMAC signing. WARC 1.1
  captures can be replayed in ReplayWeb.page; their manifest identifies missing
  or truncated bodies. WARC format alone does not certify chain of custody. The
  engine also includes curl_cffi transport with Chrome TLS fingerprint
  impersonation, explainable Fellegi-Sunter link scoring (not yet empirically
  calibrated), Admiralty-inspired helpers, and solar shadow timing windows
  calculated in UTC.
- **Desktop console** (Electron + React): case management, graph visualization,
  chain-of-custody auditing, and an **AI agent console** that orchestrates
  forensics tools. Agent actions use an analyst permission dialog; direct API
  calls are protected by a fail-closed permission gate.
- **Multiple AI providers**: Anthropic, OpenAI, OpenCode Zen (free models with
  automatic rate-limit retries), Ollama (local), and OpenAI-compatible
  endpoints.
- **MCP compatibility**: the same tools can be used from another MCP client over
  stdio.

## Architecture at a glance

    ┌───────────────────────────────────────────────┐
    │       WraithOSINT Desktop (Win/macOS/Linux)    │
    │                                               │
    │   Electron UI  ◀──HTTP/SSE──▶  Engine :8787   │
    │   (React)          REST + SSE   (Python sidecar)│
    └───────────────────────────────────────────────┘

See [ARCHITECTURE.md](ARCHITECTURE.md) for details.

## Installers

Each release provides native installers for all three platforms. The engine is
bundled with the app as a PyInstaller one-file executable, so Python is not
required to run an installed build.

| Platform | Artifact | Notes |
|---|---|---|
| **Windows** | WraithOSINT-<version>-win-x64-setup.exe | Per-user NSIS installer; no admin rights required |
| **macOS** | WraithOSINT-<version>-mac-<arch>.dmg / .zip | x64 and arm64; not signed or notarized yet |
| **Linux** | WraithOSINT-<version>-linux-x64.AppImage / .deb | Portable AppImage and Debian package |

Download installers from [Releases](../../releases). The release workflow
builds each artifact on a native runner because PyInstaller does not cross
compile.

> **macOS:** Installers are not signed or notarized yet. The first time you open
> the app, allow it in System Settings → Privacy & Security. Frictionless
> distribution requires a Developer ID certificate and notarization (see the
> [roadmap](ARCHITECTURE.md#roadmap)).

User data (cases, dossiers, and the ledger key) lives outside the app bundle in
the platform's application data directory (%APPDATA% on Windows,
~/Library/Application Support on macOS, and ~/.config on Linux), and persists
across updates.

## Quick start (development)

Requirements: Node.js 22+ and Python 3.11+. Development is supported on Windows,
macOS, and Linux.

    # Install JavaScript dependencies. The postinstall script also prepares the
    # engine virtual environment when Python 3.11+ is available.
    npm ci

    # Start the desktop app in development mode. The engine starts automatically.
    npm run dev

If the postinstall script could not install the engine dependencies, install
them in the engine virtual environment:

    # Windows
    engine\.venv\Scripts\python.exe -m pip install -r engine\requirements.txt

    # macOS / Linux
    engine/.venv/bin/python -m pip install -r engine/requirements.txt

## Build installers

    # Build the engine binary (PyInstaller one-file).
    npm run engine:build

    # Package for the platform you're using.
    npm run dist:win
    npm run dist:mac
    npm run dist:linux

Build on the target platform, or let the release workflow build native packages
after a vX.Y.Z tag is pushed.

## Run the engine without Electron

The engine can also run on its own for CI, servers, and scripts:

    # Create a token for this shell session (bash or zsh).
    export SPECTER_ENGINE_TOKEN=$(python -c "import secrets; print(secrets.token_hex(32))")
    python -m engine.http_server --port 8787

    # In another terminal, reuse the same token.
    curl -H "Authorization: Bearer $SPECTER_ENGINE_TOKEN" http://127.0.0.1:8787/cases
    curl -N "http://127.0.0.1:8787/events?token=$SPECTER_ENGINE_TOKEN"

    # OpenAPI (Swagger UI): http://127.0.0.1:8787/docs

In PowerShell, set the token with
$env:SPECTER_ENGINE_TOKEN = python -c "import secrets; print(secrets.token_hex(32))"
and use curl.exe instead of curl.

## Use the agent API

    curl -X POST http://127.0.0.1:8787/agent/run \
      -H "Content-Type: application/json" \
      -d '{
        "case_id": "case-20260929-000001",
        "message": "Investigate example.com and enumerate subdomains",
        "provider": "anthropic"
      }'

Sensitive tools emit permission.request over SSE. The analyst responds with
POST /agent/permissions/respond {request_id, decision}.

## Naming convention

The product is **WraithOSINT**, while the engine retains specter as its
internal kernel name:

| Scope | Identifier | Example |
|---|---|---|
| Product, UI, installers, docs | Wraith* | WraithOSINT, @wraith/sdk, WraithClient |
| Engine binary | wraith-engine | dist-engine/wraith-engine.exe |
| Python kernel package | specter (internal) | from specter.osint_core import ledger |
| Environment variables | SPECTER_* | SPECTER_ENGINE_TOKEN, SPECTER_DATA_DIR |

The environment variables and Python package keep their internal names to avoid
breaking existing scripts, tests, and deployments. See [.env.example](.env.example).

## Repository layout

| Path | Contents |
|---|---|
| engine/ | Python engine: FastAPI (http_server.py), agent (agent.py), registry, and forensic kernel (specter/) |
| packages/sdk | @wraith/sdk, typed TypeScript client (HTTP + SSE) |
| desktop/ | Electron app (main / preload / React renderer) |
| scripts/ | postinstall, engine build (PyInstaller), smoke test, and contrast gate |
| tests/ | pytest suite for the kernel, agent, and HTTP contract |
| docs/ | ADRs, agent personas, and UI rules |
| skills/ | Investigation playbooks the agent can load |

## Useful scripts

| Command | Action |
|---|---|
| npm run dev | Run the Electron app in development mode (starts the engine too) |
| npm run build | Build the desktop app for production |
| npm run typecheck | Typecheck the SDK and desktop app |
| npm test | Run SDK tests (Vitest) |
| npm run test:desktop | Run desktop renderer tests |
| npm run lint | Run Ruff checks and formatting checks for the engine |
| npm run test:py | Run the engine's pytest suite |
| npm run gen:sdk / npm run gen:sdk:check | Generate / verify SDK types from /openapi.json |
| npm run a11y:contrast | Check WCAG 2.2 AA color contrast |
| npm run engine:build | Package the engine with PyInstaller |
| npm run smoke:engine | Run the engine HTTP smoke test |
| npm run verify | Run the project's release checks |
| npm run dist:win / dist:mac / dist:linux | Build platform installers |
| python -m engine.http_server | Run the standalone engine |

## Quality checks

npm run verify runs the quality gates defined by the project. Coverage follows
a **ratchet** policy ([ADR-004](docs/adr/adr-004-quality-ratchet.md)): thresholds
only increase.

| Gate | Tool | Threshold |
|---|---|---|
| Python lint and formatting | Ruff | No outstanding violations |
| Engine tests | pytest | Coverage ≥ 80% |
| Engine ↔ SDK contract | gen_sdk_types.py --check | In sync with /openapi.json |
| Color contrast | a11y-contrast.mjs | WCAG 2.2 AA |
| TypeScript types | tsc --noEmit | Strict |
| SDK tests | Vitest | Coverage gate |
| Desktop renderer tests | Node test runner | All renderer tests |

Architecture decisions are recorded in [docs/adr/](docs/adr/README.md); see
[CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Status and roadmap

**Current:** an operational desktop platform with an HTTP/SSE engine, a
multi-provider agent with an analyst permission dialog, a direct API permission
gate, a graph, chain-of-custody ledger, and case dossiers. Direct case deletion
is denied by default (delete/case:*) and can be enabled per case with
add_permission_rule (action=delete, resource=case:<id>, effect=allow).

**Preservation and analysis:** WARC hashes recorded in the ledger, TLS
impersonation transport in collectors using httpx_transport, explainable
Fellegi-Sunter resolution, Admiralty scoring, and solar chronolocation. Review
the limitations and responsible-use guidance in [LEGAL.md](LEGAL.md).

Planned work is listed in the [architecture roadmap](ARCHITECTURE.md#roadmap):
interactive graph controls (drag, filters, timeline), TAXII integration, team
mode, plugins, and code signing.

## Credits and third-party data

- The [WhatsMyName dataset](https://github.com/WebBreacher/WhatsMyName) is
  licensed under **Creative Commons Attribution-ShareAlike 4.0 International
  (CC BY-SA 4.0)**; see the embedded attribution in data/wmn-data.json.
- Inspired by the client/server pattern in
  [OpenCode](https://github.com/sst/opencode).
- Built with [curl_cffi](https://github.com/lexiforest/curl_cffi),
  [patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright),
  [warcio](https://github.com/webrecorder/warcio), [NetworkX](https://networkx.org/),
  [FastAPI](https://fastapi.tiangolo.com/), and [Electron](https://www.electronjs.org/).

## License

The project code is licensed under the MIT License; see [LICENSE](LICENSE).
Third-party data and dependencies may have separate licenses. Your use of the
software is your responsibility. [LEGAL.md](LEGAL.md) is part of the project's
design and should be retained when redistributing the project.
