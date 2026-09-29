# Contributing to WraithOSINT

Thank you for your interest in contributing. This guide documents the
conventions that keep the project maintainable and that CI checks.

## Quick setup

Requirements: **Node.js 22+** and **Python 3.11 or 3.12** (the versions checked
by CI).

    # 1. Install JavaScript dependencies. The postinstall hook prepares the engine
    # virtual environment when Python is available.
    npm ci

    # 2. Install Python quality tools in the engine virtual environment.
    engine/.venv/bin/python -m pip install pytest pytest-cov ruff

On Windows, use engine\.venv\Scripts\python.exe instead of
engine/.venv/bin/python.

npm ci is what CI runs. It requires package-lock.json to match the package.json
files. If you add a dependency, commit the updated lockfile too.

## Definition of Done

A pull request is ready when all of these checks pass locally:

| Gate | Command | CI job |
|---|---|---|
| Python lint | ruff check engine/ tests/ | engine |
| Python formatting | ruff format --check engine/ tests/ | engine |
| Tests and coverage ≥ 80% | pytest tests/ -q | engine (Python 3.11 and 3.12) |
| Engine ↔ SDK contract | npm run gen:sdk:check | engine |
| WCAG AA contrast | npm run a11y:contrast | web |
| TypeScript typecheck | npm run typecheck | web |
| SDK tests and coverage | npm test | web |
| Desktop tests | npm run test:desktop | web |
| Production build | npm run build | web |

    # Run all project checks before pushing.
    npm run verify

## No real investigation data

This is a forensic tool and its repository is public. **Never commit:**

- Identifying information about real people (usernames, email addresses, phone
  numbers, national ID numbers, or real target domains) in code, tests,
  fixtures, docstrings, or documentation.
- Case artifacts such as databases, ledger.key, WARC captures, or dossiers.
- API keys or other credentials.

Use synthetic, clearly fictional examples. Existing tests are a model (for
example, person@example.test). The
[Pull Request template](.github/PULL_REQUEST_TEMPLATE.md) includes this check.

## Conventions

### Python code (engine/)

- **Names:** The product is **WraithOSINT**, but the Python kernel package is
  specter and environment variables use the SPECTER_* prefix. Do not partially
  rename these. Use Wraith* for user-visible changes and keep specter for kernel
  changes. See the naming table in the
  [README](README.md#naming-convention).
- **Paths:** Use specter.config (data_dir(), reports_dir(), database_path()).
  Do not use paths relative to the current working directory or resolve them at
  import time.
- **Forensics tools:** Define tools once as MCP decorators in
  specter/server.py; consumers should use engine/registry.py.
- **Tests:** Isolate storage with the engine_env fixture (tmp_path and
  environment variables) and avoid the real network. Collector mocks should
  use the collector seam.
- **Style:** 100-character line length, Ruff-sorted imports, modern type hints
  (list[str], X | None).

### TypeScript code (packages/sdk, desktop)

- The engine contract lives in @wraith/sdk; the UI should not call fetch
  directly.
- The renderer talks to the engine over HTTP/SSE. The main process manages only
  the sidecar and native APIs (see desktop/src/preload).
- React components should not contain business logic. Engine state belongs in
  the Zustand store and arrives through the event bus.

### Commits and pull requests

- Use Conventional Commits: feat:, fix:, docs:, refactor:, test:, chore:.
  Example: feat(engine): add a historical WHOIS collector.
- One pull request should have one purpose. Explain why the change is needed,
  not only what it changes.
- If you change architecture (transport, storage, security), add or update an
  [ADR](docs/adr/README.md) in the same pull request.

### Coverage

Coverage follows a **ratchet** policy (see
[ADR-004](docs/adr/adr-004-quality-ratchet.md)): thresholds only increase. If
your pull request lowers coverage, add tests. If a test adds no meaningful
coverage, explain in the pull request what should be covered instead.

## Quality roadmap

Coverage and test improvements are planned in
[ARCHITECTURE.md](ARCHITECTURE.md#roadmap). Before adding a collector, review
the structure of existing collectors in specter/collectors/base.py.
