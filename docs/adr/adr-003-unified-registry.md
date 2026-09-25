# ADR-003: Registro único de tools MCP + configuración call-time

- Estado: aceptada
- Fecha: 2026-09-24

## Contexto

Las 15 tools forenses estaban definidas como decoradores MCP en `specter/server.py`.
La plataforma necesitaba consumirlas desde tres superficies (UI REST, agente IA por
function-calling, clientes MCP externos) sin duplicar definiciones, y los tests
necesitaban redirigir el almacenamiento (`data/`, `reports/`) sin tocar el repo.

Dos males menores se detectaron al implementarlo: rutas resueltas en import-time
(`Database("data/specter_osint.db")` relativa al cwd) y helpers de ruta duplicados
en `identity.py` y `exporter.py`.

## Decisión

1. **Registro único**: `engine/registry.py` accede al registro interno del
   `MCPServer` (`_tool_manager`) y expone `get_registry_tools()`,
   `call_tool_validated()` (validación pydantic oficial vía `fn_metadata`) y
   `get_tool_schemas()`. Toda superficie consume de ahí. El carácter privado de
   `_tool_manager` se aísla en este único módulo para minimizar el acoplamiento con
   la versión de `mcp`.
2. **Configuración call-time**: `specter/config.py` es la única fuente de verdad de
   rutas (`data_dir()`, `reports_dir()`, `database_path()`, `wmn_data_path()`); lee
   env vars en cada llamada con fallback al repo. `specter/server.py` ofrece
   `reset_services()` como seam de testabilidad.

## Consecuencias

- ✅ Una sola definición por tool; schemas, descripciones y validación consistentes.
- ✅ Tests aislados en tmp_path con monkeypatch de env vars (sin cwd frágil).
- ✅ La app empaquetada (PyInstaller) redirige almacenamiento a `%APPDATA%`.
- ⚠️ El acceso a `_tool_manager` puede romperse con actualizaciones mayores de
  `mcp` → mitigado: está encapsulado en `registry.py` con fallback de invocación
  directa; el resto del código no lo toca.
- ⚠️ Los globals del kernel se reasignan en tests → confinado a `reset_services()`
  y documentado; no usar como mecanismo general de configuración.
