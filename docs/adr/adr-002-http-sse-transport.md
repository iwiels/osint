# ADR-002: HTTP + SSE (FastAPI) como transporte del motor

- Estado: aceptada
- Fecha: 2026-09-24

## Contexto

El kernel ya exponía sus tools por MCP stdio. La plataforma necesitaba: progreso en
vivo para la UI (tool.started/completed, peticiones de permiso), multi-cliente, y
debuggabilidad. Alternativas: dejar solo stdio (sin push, mono-cliente), WebSockets
(duplex completo pero sin reconexión nativa ni caché de proxy) o SSE + REST.

## Decisión

**REST + Server-Sent Events sobre HTTP local** con FastAPI/uvicorn:

- REST para comandos y consultas (`/cases`, `/tools/{name}/call`, `/agent/run`).
- SSE (`/events`) como event bus: todo evento del motor (`agent.*`, `tool.*`,
  `permission.*`, `case.*`) se serializa tipado y los clientes se suscriben.
- MCP stdio se conserva para compatibilidad con OpenCode y clientes externos.

## Consecuencias

- ✅ Progreso en vivo sin librerías extra; reconexión nativa de EventSource.
- ✅ El motor se prueba con `httpx.ASGITransport` sin sockets (ver tests HTTP).
- ✅ La UI es una proyección del bus: añadir clientes (web, CLI) no toca el motor.
- ⚠️ SSE es unidireccional → las respuestas de permisos entran por REST
  (`POST /agent/permissions/respond`), patrón request/response complementario.
- ⚠️ Solo escucha en 127.0.0.1: no es un servicio de red; el modo multi-usuario
  requerirá auth y un ADR propio (roadmap H3).
