# Architecture Decision Records

Registro de decisiones de arquitectura con su contexto y consecuencias.
Cada ADR es inmutable: para cambiar una decisión se escribe una nueva que la
reemplace (estado: `reemplazado por ADR-XXX`).

## Índice

| ADR | Título | Estado |
|---|---|---|
| [ADR-001](adr-001-python-sidecar.md) | Kernel Python como sidecar en vez de reescritura TypeScript | Aceptada |
| [ADR-002](adr-002-http-sse-transport.md) | HTTP + SSE (FastAPI) como transporte del motor | Aceptada |
| [ADR-003](adr-003-unified-registry.md) | Registro único de tools MCP + configuración call-time | Aceptada |
| [ADR-004](adr-004-quality-ratchet.md) | Gates de calidad con estrategia ratchet | Aceptada |
| [ADR-005](adr-005-opencode-zen-free-provider.md) | Gateway Zen HTTP como provider free (bridge CLI eliminado después) | Aceptada con enmienda |

## Plantilla

```markdown
# ADR-NNN: <título>

- Estado: propuesta | aceptada | reemplazada por ADR-XXX
- Fecha: YYYY-MM-DD

## Contexto
¿Qué fuerza el problema? ¿Qué alternativas existen?

## Decisión
¿Qué se decidió, en una frase clara?

## Consecuencias
Positivas, negativas y qué se deja de hacer.
```
