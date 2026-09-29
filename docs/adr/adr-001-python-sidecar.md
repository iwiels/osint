# ADR-001: Kernel Python como sidecar en vez de reescritura TypeScript

- Estado: aceptada
- Fecha: 2026-09-24

## Contexto

WraithOSINT era un kernel forense Python maduro (ledger SHA-256, grafo NetworkX,
10 colectores, 15 tools MCP) cuya interfaz dependía de OpenCode. Para convertirse en
plataforma desktop independiente había dos caminos: reescribir todo en TypeScript
dentro de Electron, o mantener el kernel como proceso separado.

Reescribir implicaba portar y re-validar lógica forense sensible (cálculo de hashes
de custodia, resolución DNS, análisis de certificados) con riesgo de regresiones
invisibles y meses de trabajo sin valor visible para el usuario.

## Decisión

Mantener el kernel Python como **sidecar headless**: Electron lo gestiona como
proceso hijo (spawn + health-check + taskkill del árbol), y ambos se comunican por
HTTP local. Es el mismo patrón cliente/servidor de opencode: motor separado,
clientes intercambiables.

## Consecuencias

- ✅ El código forense validado no se toca; el riesgo se concentra en la capa de UI.
- ✅ El motor es reutilizable sin Electron (CI, servidores, scripts) y por cualquier
  lenguaje cliente.
- ✅ Los tests del kernel y de la UI evolucionan y fallan de forma independiente.
- ⚠️ El instalador debe empaquetar un binario del engine (PyInstaller) → resuelto con
  `scripts/build-engine.py` + `extraResources` de electron-builder.
- ⚠️ Dos runtimes en el repo → mitigado con CI por jobs y tooling unificado.
