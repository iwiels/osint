# Playbook: DNI argentino suelto (7-8 dígitos sin letra)

Úsalo cuando el objetivo sea un número como `99999999` y `triage_entity` lo
clasifique como `DOCUMENT_ID`. Un DNI por sí solo es un identificador
administrativo, no digital: el objetivo es derivar pivotes buscables o
cerrar con NO-ATRIBUCIÓN honesta (nunca inventar una persona).

## Fase 1 — Búsqueda literal (ya la hace `hunt_documents_and_leaks`)

Verifica `pdfs_analyzed`, `web_mentions` y `official_mentions` (Boletín
Oficial, InfoLEG, PJN). Si todo es 0, no insistas con el literal: pasa a
fase 2.

## Fase 2 — Derivar candidatos CUIT y buscarlos

El CUIT es `PP-XXXXXXXX-D` (prefijo + DNI + dígito verificador) y SÍ aparece
en padrones, facturas y designaciones indexadas. Prefijos: `20` (masc.),
`27` (fem.), `23`/`24` (casos especiales). Calcula el dígito así:

1. Forma los 10 dígitos `PP + DNI` (DNI con 8 dígitos, rellena con 0 a la
   izquierda si tiene 7).
2. Multiplica por `5 4 3 2 7 6 5 4 3 2`, suma, calcula `resto = suma mod 11`,
   `dig = 11 - resto`.
3. Si `dig == 11` → `0`. Si `dig == 10` → descarta ese prefijo y prueba con
   `23` (recalcula).
4. Repite para `20` y `27` (y `23` si aplica): obtienes 2-3 CUIT candidatos.

Ejemplo: DNI `99999999` → `20-99999999-?` y `27-99999999-?` (calcúlalos,
no los adivines). Luego **una sola** llamada a `parallel_search` con:

- `"20-99999999-3"` (cada CUIT candidato entre comillas)
- `"99999999" (site:boletinoficial.gob.ar | site:infoleg.gob.ar)`
- `"99999999" (site:pjn.gov.ar | site:argentina.gob.ar)`

Si un CUIT aparece en una fuente oficial, úsalo como pivote principal
(es mucho más selectivo que el DNI desnudo).

## Fase 3 — Pivote de identidad (solo con hit real)

`investigate_identity` / `investigate_person` SOLO si la fase 1-2 dio un
nombre, alias o email concreto. Prohibido:

- Buscar el número desnudo como username: los hits numéricos son IDs
  secuenciales de plataforma (Dailymotion, ImageShack, Vivino), no personas.
- Atribuir con confianza > 0.5 cualquier perfil puramente numérico.
- Citar edges `REGISTERED_WITH` numéricos como evidencia de identidad.

## Fase 4 — Prueba de control (ante cualquier hit numérico)

Busca 1-2 números arbitrarios de igual longitud con `investigate_identity`.
Si devuelven las mismas plataformas con igual o mayor tasa, el hallazgo es
artefacto técnico: descártalo por escrito y no lo cites.

## Fase 5 — Cierre

- Con nombre/alias/email verificado: `investigate_person` o `investigate_email`,
  correlaciona (`query_graph`, `correlate_cases`), sella (`attest_case_ledger`).
- Sin nada: informa NO-ATRIBUCIÓN con lo intentado y usa `ask_analyst` para
  pedir dato de anclaje (nombre y apellido, alias conocido o correo). No
  ejecutes fase 2 de correos ni fase 3 de GitHub sin objetivo derivado:
  solo producen falsos positivos.
