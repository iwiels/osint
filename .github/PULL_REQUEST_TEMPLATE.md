# Descripción

<!-- Qué cambia y, sobre todo, POR QUÉ. -->

## Tipo de cambio

- [ ] `feat` — funcionalidad nueva
- [ ] `fix` — corrección de bug
- [ ] `refactor` — sin cambio de comportamiento
- [ ] `docs` — documentación
- [ ] `test` — tests
- [ ] `chore` — mantenimiento, dependencias, CI

## Checklist

- [ ] `npm run verify` pasa en local (lint, tests, contrato, a11y, tipos, build).
- [ ] Si toqué arquitectura (transporte, almacenamiento, seguridad, empaquetado),
      añadí o actualicé un [ADR](docs/adr/README.md) en este mismo PR.
- [ ] Si añadí un colector o una capacidad de doble uso, actualicé
      [LEGAL.md](LEGAL.md).
- [ ] No incluí datos de investigaciones reales (dossiers, capturas, base de
      datos, claves) ni identificadores de personas reales en código, tests,
      fixtures o documentación.
- [ ] Si toqué el contrato del motor, regeneré el SDK (`npm run gen:sdk`).

## Notas para quien revisa

<!-- Decisiones discutibles, partes que quieres que se miren con lupa, dudas abiertas. -->
