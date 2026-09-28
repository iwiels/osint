# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y este proyecto adhiere a [Versionado Semántico](https://semver.org/lang/es/).

## [Sin publicar]

### Seguridad y privacidad

- Eliminados datos de investigación real del repositorio (base de datos de caso,
  clave del ledger, capturas WARC y dossiers/STIX en `reports/`). Los artefactos
  de caso ahora se generan en runtime y están excluidos por `.gitignore`.
- `.gitignore` endurecido: cubre `.env*`, `reports/*`, journals/WAL de SQLite y
  el directorio `engine/data/` (una DB trackeada escapaba al patrón `data/*.db`).
- CORS del engine restringido a orígenes localhost (dev server y preview); ya
  no responde preflights de sitios web públicos.
- `/health` ya no expone rutas del filesystem local; se consultan vía endpoints
  autenticados.
- Anonimizados tests y docstrings: toda persona de ejemplo es sintética
  (`Carlos Andres Mendoza Garcia`, `cmendozagarcia@ejemplo.test`).

### Añadido

- `LICENSE` (MIT), `.env.example` documentando todas las variables del motor,
  `CHANGELOG.md` y `CODE_OF_CONDUCT.md`.
- Error Boundary de React envolviendo Consola del agente, Panel de evidencias y
  Grafo de conocimiento: un crash en un canvas no tumba la aplicación.
- Metadata de paquete (`repository`, `author`, `keywords`) en `package.json` y
  `pyproject.toml`.

## [0.2.0] - 2026-09-27

### Añadido

- Agente forense multi-proveedor (Anthropic, OpenAI y endpoints
  OpenAI-compatibles) con gate de permisos y preguntas al analista.
- Sesiones persistentes del agente con historial consultable desde la UI.
- Navegador sigiloso in-process (patchright) para colectores que necesitan
  Chromium real, con captura WARC ISO 28500 sellable en custodia.
- Colector de personas con derivación dinámica de usernames, pivot loop
  documental (emails/códigos hallados disparan búsquedas propias) y recuperación
  de PDFs caídos vía Wayback.
- Resolución de identidad Fellegi-Sunter con penalización por frecuencia y
  campo `alias_of_name` (cobertura de tokens del nombre completo).
- Dossier ejecutivo HTML y exportación STIX 2.1.

### Cambiado

- El motor de navegación salió del proceso main de Electron: ahora vive en el
  engine Python y un crash del navegador no tumbea la app.

## [0.1.0] - 2026-09-24

### Añadido

- Kernel forense: casos, grafo de conocimiento (NetworkX), ledger de custodia
  HMAC-SHA256 y modelos Pydantic.
- Colectores: DNS, TLS, Certificate Transparency (crt.sh), RDAP, identidad
  (WhatsMyName 700+ plataformas), GitHub forensics, dorks y threat intel.
- Engine HTTP (FastAPI, REST + SSE) con registry único de tools MCP y
  autenticación Bearer local.
- Desktop Electron: consola del agente, grafo de evidencias, timeline,
  correlaciones y tabla de custodia.
- SDK TypeScript tipado (`@specter/sdk`) generado desde el schema OpenAPI.

[Sin publicar]: https://github.com/iwiels/osint/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/iwiels/osint/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/iwiels/osint/releases/tag/v0.1.0
