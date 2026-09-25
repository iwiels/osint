# ADR-004: Gates de calidad con estrategia ratchet

- Estado: aceptada
- Fecha: 2026-09-24

## Contexto

El repo llegó a la plataforma con 9 tests sobre el kernel y sin linter. Imponer un
umbral de cobertura ideal (80-90%) habría obligado a escribir tests de bajo valor
sobre colectores de red en el primer día, o a desactivar el gate por impracticable.
El objetivo es que la calidad **no retroceda** y avance de forma sostenida cuando el
proyecto crezca.

## Decisión

**Ratchet**: cada gate de calidad se fija ligeramente por encima del estado actual
del código y solo puede subir:

| Gate | Valor actual | Dónde |
|---|---|---|
| Cobertura Python | 55% (real: 56.9%) | `pyproject.toml → --cov-fail-under` |
| Cobertura SDK | 90% lines/stmts, 85% branches/functions | `packages/sdk/vitest.config.ts` |
| Lint Python | 0 errores (`E,W,F,I,B,UP,SIM`) | `pyproject.toml → [tool.ruff.lint]` |
| Formato | `ruff format --check` | CI |
| Typecheck TS estricto | 0 errores | CI |

Núcleo crítico bien cubierto desde el día 1: config (96%), registry (94%),
database (93%), ledger (90%) — la lógica de custodia e integridad. Los colectores
de red (I/O externo) se cubrirán con mocks de HTTP por fases (H2).

## Consecuencias

- ✅ CI impide que la cobertura baje; cualquier código nuevo debe nacer probado.
- ✅ Sin tests de relleno: las excepciones están justificadas y documentadas
  (`cli.py` demo omitido, `types.ts` sin runtime).
- ✅ Subir un umbral es un cambio de una línea y se celebra en el changelog.
- ⚠️ Requiere disciplina: los umbrales no se tocan para "arreglar" un PR rojo.
- ⚠️ El ratchet no sustituye tests de integración E2E del flujo agente→colección
  (pendiente en H2 con proveedor mockeado).
