# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/)
y este proyecto adhiere a [Versionado Semántico](https://semver.org/lang/es/).

> **Primera publicación pública.** Las versiones 0.1.0 y 0.2.0 fueron hitos de
> desarrollo anteriores a la publicación: no tienen etiqueta en este repositorio
> y se conservan como historial del proyecto.

## [0.3.0] - 2026-09-29

### Seguridad y privacidad

- **Eliminados del repositorio los scripts de exploración con datos de una
  investigación real** (`run_batch_investigation.py`, `test_wmn_full.py`,
  `test_wmn_eval.py`, `diagnose_users.py`, `test_dork.py`): contenían la misma
  lista de identificadores de personas reales y el registro de un análisis en
  lote sobre ellas. No formaban parte del producto ni los referenciaba ningún
  script del proyecto.
- **Sustituido el DNI real que se usaba como ejemplo** en `skills/dni-ar.md` y en
  la suite de tests por uno sintético, y corregidos los CUIT del ejemplo del
  playbook, que estaban mal calculados. La documentación y los tests usan ahora
  identificadores ficticios por convención.
- **Sustituidos los correos con dominio real usados como fixture** en los tests
  (`analista.cero@ejemplo.test`, `juan.perez@ejemplo.test`) por direcciones en el
  dominio reservado `.test`, que no puede pertenecer a nadie.
- **Purgado el historial de git.** Los datos anteriores seguían alcanzables en
  commits antiguos, así que se reescribió la historia para eliminarlos: borrarlos
  del árbol de trabajo no basta, porque publicar el repositorio los expondría
  igualmente. Se eliminaron también `engine/data/specter_osint.db` (una base de
  datos de caso vacía, pero artefacto de runtime que nunca debió versionarse) y
  `.coverage`.
- **Eliminado el hardcode de una universidad concreta** en
  `collectors/person.py`: la detección de instituciones académicas tenía un caso
  especial para una universidad real, lo que ataba el colector a un único caso
  de uso y dejaba entrever el objetivo de la investigación. Ahora el nombre de
  la institución se deriva del host del hallazgo y sirve para cualquier país.
  Los fixtures de test que usaban ese dominio real pasan a `universidad.test`.
- Anonimizados tests y docstrings: toda persona de ejemplo es sintética
  (`Carlos Andres Mendoza Garcia`, `cmendozagarcia@ejemplo.test`).
- Eliminados datos de investigación real del repositorio (base de datos de caso,
  clave del ledger, capturas WARC y dossiers/STIX en `reports/`). Los artefactos
  de caso se generan en runtime y están excluidos por `.gitignore`.
- `.gitignore` endurecido: cubre `.env*`, `reports/*`, journals/WAL de SQLite y
  el directorio `engine/data/` (una DB trackeada escapaba al patrón `data/*.db`).
- CORS del motor restringido a orígenes localhost (dev server y preview); ya no
  responde preflights de sitios web públicos.
- `/health` ya no expone rutas del filesystem local; se consultan vía endpoints
  autenticados.
- Añadido [SECURITY.md](SECURITY.md) con política de divulgación, alcance del
  modelo de amenaza y límites explícitos (sin cifrado en reposo, sin sandbox del
  motor, sin aislamiento entre casos).

### Cambiado

- **Rebranding completo a WraithOSINT.** El producto se llamaba SpecterOSINT en
  la documentación mientras la aplicación, el instalador y el SDK ya usaban
  Wraith. Ahora todo lo visible al usuario es coherente:
  - paquete raíz `wraith-osint`, SDK `@wraith/sdk`, binario del motor
    `wraith-engine`, servidor MCP `wraith-osint`, `productName: WraithOSINT`.
  - El paquete Python `specter`, las variables de entorno `SPECTER_*` y el
    fichero `specter_osint.db` **conservan** el nombre interno del motor para no
    romper scripts, tests y despliegues. La convención está documentada en el
    [README](README.md#convención-de-nombres).
- **El release ahora compila un instalador por plataforma y arquitectura.** El
  motor viaja dentro de la app y PyInstaller no cross-compila, así que macOS
  necesita dos binarios (Intel x64 y Apple Silicon arm64) y cada .dmg lleva el
  suyo. El workflow anterior producía ambos .dmg con un único motor arm64.
- `electron-builder.yml` ya no fija arquitecturas: las decide el host (o la CI
  con `--x64` / `--arm64`), de modo que el paquete y su motor siempre coinciden.
- CI: `npm ci` en lugar de `npm install` (el lock pasa a ser vinculante), Node 22
  (Node 20 está fuera de soporte) y matriz de Python 3.11 / 3.12 para verificar
  el suelo que declara `pyproject.toml`.
- `README.md` reescrito: badges de CI y release, tabla de instaladores por
  plataforma, aviso de uso responsable destacado, sección de convención de
  nombres y atribución de terceros.
- Añadido `timeout-minutes` y `permissions: contents: read` a los workflows.

### Corregido

- **El release publicaba instaladores sin motor.** El workflow de release subía
  el artefacto con el patrón `dist-engine/specter-engine*` cuando
  `scripts/build-engine.py` produce `wraith-engine*`. El artefacto salía vacío,
  el job del instalador se quedaba sin binario y electron-builder empaquetaba
  una app que no podía arrancar el motor. Ahora el patrón es correcto y falla en
  voz alta (`if-no-files-found: error`) en vez de publicar algo roto.
- **Los .dmg de macOS Intel embebían un motor arm64.** El runner `macos-latest`
  es Apple Silicon, pero `electron-builder.yml` empaquetaba `arch: [x64, arm64]`.
  El instalador x64 quedaba inservible en Macs Intel.
- **"Revelar dossier" no funcionaba en ninguna plataforma.** `reportsDir()` en el
  proceso main resolvía `%APPDATA%/wraith-osint/reports` mientras el motor
  escribe en el directorio de datos de Electron; en macOS y Linux `%APPDATA%` no
  existe, así que la ruta caía dentro del bundle (solo lectura). Ambas partes
  usan ahora `app.getPath("userData")`.
- Eliminado `scripts/smoke_binary.py`: no lo invocaba ningún script del proyecto
  y buscaba el binario del motor con el nombre antiguo, por lo que no podía
  pasar nunca.
- `package-lock.json` y `uv.lock` resincronizados con los `package.json` y el
  `pyproject.toml` reales; declaraban `specter-osint`, `specter-desktop` y
  `@specter/sdk`, que ya no existen (rompía `npm ci`).
- Corregidas las cifras de la documentación: 47 herramientas MCP (no 40 ni 41),
  584 tests (no 265+), 70 ficheros de test (no 37) y rutas de datos coherentes
  con las que usa el motor.
- **La UI y el motor mostraban la versión 0.2.0** en un build 0.3.0 (`/health`, el
  `info.version` del OpenAPI y tres literales en el renderer). La UI toma ahora la
  versión de `desktop/package.json` en tiempo de build, y un test comprueba que
  `pyproject.toml`, el motor y los tres `package.json` declaran la misma versión.
- **El workflow de release nunca había llegado a compilar un instalador.** Solo se
  ejecutó una vez, con el tag `v0.3.0`, y los cuatro jobs del motor fallaron en
  `pip install`; el tag se empujó antes de fijar `maigret==0.1.7`. Además, el
  paquete `.deb` exige el email del mantenedor y `desktop/package.json` no tenía
  `author` ni `homepage`.
- **La CI no instalaba `pytest-asyncio`**: todos los tests `async` fallaban y la
  cobertura caía al 42 %. Ahora se instala en CI y en la guía de contribución, y
  `pyproject.toml` lo declara en `required_plugins` para abortar con un mensaje
  claro si falta.

### Añadido

- Smoke test del binario del motor (`scripts/smoke_engine_binary.py`) en el release,
  justo después de PyInstaller y en cada plataforma: arranca el ejecutable y
  comprueba `/health`, que la autenticación se exige y que puede crear un caso con
  ledger firmado. Un motor roto ya no llega a un instalador.
- Icono de la aplicación (`desktop/build/icon.png`) y notas de release propias
  (`.github/release-notes.md`) con descargas, primer arranque y uso responsable.
- `LICENSE` (MIT), `.env.example` documentando todas las variables del motor,
  `CHANGELOG.md` y `CODE_OF_CONDUCT.md`.
- Configuración de Dependabot para npm, pip, uv y GitHub Actions, con agrupación
  de actualizaciones menores y de parche.
- Plantillas de issue (bug y propuesta) y de pull request. Ambas exigen redactar
  cualquier dato personal o de caso real antes de publicarlo.
- Error Boundary de React envolviendo Consola del agente, Panel de evidencias y
  Grafo de conocimiento: un crash en un canvas no tumba la aplicación.
- Metadata de paquete (`repository`, `author`, `homepage`, `bugs`, `engines`,
  `keywords`) en `package.json` y `pyproject.toml`.

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
  motor Python y un crash del navegador no tumbea la app.

## [0.1.0] - 2026-09-24

### Añadido

- Kernel forense: casos, grafo de conocimiento (NetworkX), ledger de custodia
  HMAC-SHA256 y modelos Pydantic.
- Colectores: DNS, TLS, Certificate Transparency (crt.sh), RDAP, identidad
  (WhatsMyName 700+ plataformas), GitHub forensics, dorks y threat intel.
- Motor HTTP (FastAPI, REST + SSE) con registry único de tools MCP y
  autenticación Bearer local.
- Desktop Electron: consola del agente, grafo de evidencias, timeline,
  correlaciones y tabla de custodia.
- SDK TypeScript tipado (`@wraith/sdk`) generado desde el schema OpenAPI.

[0.3.0]: https://github.com/iwiels/osint/releases/tag/v0.3.0
