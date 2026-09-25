# Contribuir a SpecterOSINT

Gracias por interesarte. Este documento define las convenciones que mantiene el
proyecto escalable: las mismas que aplica la CI.

## Setup rápido

```bash
# 1. JS + prep del venv del engine (postinstall automático)
npm install

# 2. Dependencias Python del engine + herramientas de calidad
pip install -r engine/requirements.txt pytest pytest-cov ruff
#    Si usas uv sobre el .venv del repo:
#    uv pip install --python .venv/Scripts/python.exe pytest pytest-cov ruff
```

## Definition of Done (lo que la CI hace cumplir)

Un PR se considera listo cuando **todo** esto pasa en local:

| Gate | Comando | Gate en CI |
|---|---|---|
| Lint Python | `ruff check engine/ tests/` | job `engine` |
| Formato Python | `ruff format --check engine/ tests/` | job `engine` |
| Tests + cobertura ≥ 55% | `pytest tests/ -q` | job `engine` |
| Typecheck TS | `npm run typecheck` | job `web` |
| Tests SDK + cobertura | `npm test` | job `web` |
| Build producción | `npm run build` | job `web` |

```bash
# Atajo para pasar todo antes de pushear:
ruff check engine/ tests/ && ruff format engine/ tests/ && pytest tests/ -q \
  && npm run typecheck && npm test && npm run build
```

## Convenciones

### Código Python (engine/)

- **Rutas**: siempre vía `specter.config` (`data_dir()`, `reports_dir()`,
  `database_path()`). Nunca paths relativos al cwd ni resueltos en import-time.
- **Tools forenses**: se definen una sola vez como decoradores MCP en
  `specter/server.py`; los consumidores van a través de `engine/registry.py`.
- **Tests**: aíslan almacenamiento con el fixture `engine_env` (tmp_path + env
  vars) y sin red real. Los mocks de colectores van por el seam del collector.
- Estilo: `line-length = 100`, imports ordenados por ruff, tipado moderno
  (`list[str]`, `X | None`).

### Código TypeScript (packages/sdk, desktop)

- El **contrato del motor** vive en `@specter/sdk`; la UI no llama a `fetch` a pelo.
- El renderer habla con el engine por HTTP/SSE; el proceso main solo gestiona el
  sidecar y APIs nativas (ver `desktop/src/preload`).
- Componentes React: sin lógica de negocio; el estado del engine vive en el store
  Zustand y llega por eventos del bus.

### Commits y PRs

- Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.
  Ejemplo: `feat(engine): añade collector de whois histórico`.
- Un PR = una intención. Describe el *porqué*, no solo el *qué*.
- Si tocas arquitectura (transporte, storage, seguridad): escribe o actualiza un
  [ADR](docs/adr/README.md) en el mismo PR.

### Cobertura

La estrategia es **ratchet** (ver [ADR-004](docs/adr/adr-004-quality-ratchet.md)):
los umbrales solo suben. Si tu PR baja la cobertura, añade tests; si el código es
un test de relleno sin valor, propón en el PR qué cubrir en su lugar.

## Roadmap de calidad

Las mejoras de cobertura y tests se planifican por fases en
[ARCHITECTURE.md](ARCHITECTURE.md#roadmap). Antes de añadir un colector nuevo,
revisa cómo están estructurados los existentes (`specter/collectors/base.py`).
