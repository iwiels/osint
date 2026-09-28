# Nota legal y de uso responsable — SpecterOSINT

> **Aviso**: este documento no es asesoramiento legal. Antes de publicar o usar
> esta herramienta en una jurisdicción concreta, consultá con un abogado. Las
> leyes citadas son referencias para orientar decisiones de diseño, no una
> guía de cumplimiento exhaustiva.

SpecterOSINT es una plataforma forense de fuentes abiertas (OSINT) para
investigadores de seguridad, periodistas, defensores de derechos humanos y
abogados. Su propósito legítimo es documentar evidencia pública de forma
reproducible y verificable. Este documento explica qué capacidades del motor
son sensibles, qué decisiones de diseño se tomaron para reducirlas al mínimo,
y qué NO hace la herramienta a propósito.

## 1. Principio de diseño: recolección pasiva por defecto

El motor está construido sobre fuentes abiertas y pasivas: registros DNS,
Certificate Transparency, RDAP, archivos públicos, APIs de feeds de
amenazas y páginas indexadas. La verificación de corrupción sobre
sistemas de terceros está fuera de alcance por diseño, y las pruebas del
kernel lo hacen cumplir (`tests/test_netguard.py` bloquea SSRF, loopback y
rangos privados).

## 2. Capacidades sensibles y su tratamiento

### 2a. Impersonación TLS (`httpx_transport.py`, curl_cffi)

**Qué hace**: iguala la huella criptográfica (JA4/JA3) del cliente HTTP a la
de un navegador Chrome real, para que la recolección no sea bloqueada por
simple discriminar la pila TLS de Python.

**Marco**: la impersonación TLS no accede a sistemas ajenos ni sortea
autenticación: iguala la presentación de un cliente estándar. Es la misma
técnica que usan navegadores headless y librerías de scraping de amplio uso
(curl-impersonate, curl_cffi, MIT). Puede violar los Términos de Servicio de
un sitio concreto: revisá los ToS de cada fuente y respetá robots.txt cuando
aplique. No sortea CAPTCHAs ni controles de identidad: si un sitio exige
verificación humana, el colector devuelve `blocked` y se detiene.

### 2b. Navegador sigiloso (`stealth_browser.py`, patchright)

**Qué hace**: automatiza Chromium con huellas coherentes (UA, client hints,
WebGL, timezone) para renderizar páginas con JS y detectar bloqueos.

**Marco**: mismo análisis que 2a. La herramienta **no** resuelve CAPTCHAs
automáticamente, **no** crea cuentas, **no** interactúa con contenido behind
-login y **no** suplanta personas. La rotación de identidad (`browser_rotate_identity`
) existe para hygiene operativa (no correlacionar casos por cookies), no
para evasión de prohibiciones. Los datos de sock puppets, warming-up y
números VoIP son responsabilidad exclusiva del analista y quedan fuera del
motor.

### 2c. Verificación de cuentas por email: opt-in explícito

Herramientas tipo Holehe consultan endpoints de "¿existe una cuenta con este
email?" (password reset, login) para enumerar presencia de una persona en
servicios de terceros. Specter incluye Holehe dentro de `identity_collector`,
pero queda **desactivado por defecto**. Para activarlo, el operador debe pasar
`{"use_holehe": true}` como `options` en `run_collector`. El agente pide
aprobación para ejecutar `run_collector`; quien invoque MCP directamente debe
obtener su propia autorización y revisar la base legal y los términos de cada
proveedor. Esta opción no se activa desde la herramienta normal `investigate_email`.

La técnica sigue siendo sensible por tres motivos:

1. **Legal**: en la UE puede constituir procesamiento de datos personales
   sin base jurídica (RGPD art. 6); en EEUU puede rozar CFAA según el sitio
   y la escala. Consultas masivas a endpoints de autenticación pueden ser
   interpretadas como intento de acceso no autorizado.
2. **Ético**: el titular del correo no sabe ni consiente; el proceso deja
   rastro en los sistemas del proveedor.
3. **Operativo**: es *activo* por definición — contamina la cadena de
   custodia y alerta al objetivo (trigger de seguridad, notificaciones).

Si un caso lo exige legítimamente, documéntalo como acción activa separada y
con base legal propia antes de habilitarla.

### 2d. Búsqueda facial inversa: **NO incluida, deliberadamente**

PimEyes/FaceCheck.ID procesan biometría de terceros sin consentimiento.
La extracción de vectores biométricos y su comparación a escala está sujeta
a: RGPD art. 9 (datos biométricos = categoría especial), BIPA (Illinois,
daños privados de US$1.000-5.000 por violación), Ley 25.326 (Argentina),
LGPD (Brasil). Varias de estas plataformas enfrentan sanciones regulatorias
en la UE. El motor procesa metadatos de imágenes (EXIF, ELA, hashes) pero
**no** extrae ni compara plantillas biométricas.

### 2e. Cronolocalización (`solar.py`)

**Qué hace**: acota la hora de una foto a partir de su propia sombra y
efemérides astronómicas públicas. No toca datos personales: es física y
matemática. El analista es responsable del uso (verificación de UGC legítima
vs. localización de individuos sin consentimiento).

### 2f. Pool de proxies (`tempo.py`)

**Qué hace**: rota la salida de red si el analista configura un pool
(`SPECTER_PROXY_POOL`). El motor **no** incluye, recomienda ni vende
proxies residenciales/móviles: esas redes (CGNAT, residencial rotativa)
tienen su propia cadena legal de proveniencia — algunos proveedores operan
con consentimiento de SDKs de apps; otros, discutible. Elegir proveedor y
usar el pool es decisión documentable del analista.

## 3. Datos personales y proporcionalidad

- La plataforma almacena artefactos públicos (dominios, IPs, perfiles
  públicos) vinculados a un caso con investigación declarada.
- El concepto de **caso** (`create_case`) permite registrar una descripción e
  investigador. Ese registro ayuda a documentar la finalidad, pero no demuestra
  por sí solo una base legal ni el cumplimiento de una obligación de privacidad.
- El ledger es una cadena de hashes SHA-256 con HMAC si hay clave local; detecta
  cambios, pero no es almacenamiento inmutable ni una firma pública. Una
  atestación HMAC sólo se valida compartiendo la clave, lo que también permite
  a su receptor crear firmas. La API permite borrar permanentemente el caso y
  su ledger; la decisión de retención o eliminación debe documentarse por
  separado cuando la jurisdicción lo requiera.

## 4. Referencias normativas citadas en el diseño

| Norma | Aplicación en el motor |
|---|---|
| ISO/IEC 27037 | Referencia de diseño para preservación; el proyecto no certifica cumplimiento |
| ISO/IEC 27043 | Referencia para organizar el proceso investigativo |
| ISO 28500 (WARC) | `browser_capture_warc`: formato de archivo web para replay |
| Protocolo de Berkeley (HRC/UC Berkeley) | Referencia metodológica; no certifica la captura ni sus resultados |
| Reglamento (UE) 2016/679 (RGPD) | Decisiones de exclusión: sin biometría; consulta de cuentas opt-in |
| Convenio de Budapest | Uso legítimo vs. acceso ilegal a sistemas (SSRF guard, sin intrusión) |

## 5. Responsabilidad del operador

El motor registra lo que hace (ledger hash-chain con HMAC local cuando hay
clave, `rate_source` por colector, manifiesto WARC). El analista es responsable de:

1. Tener base legal para procesar los datos del caso (mandato, consentimiento,
   interés legítimo documentado).
2. Respetar ToS de cada plataforma fuente cuando la investigación lo permita.
3. No usar la herramienta para stalking, doxxing, vigilancia de parejas,
   acoso ni discriminación — usos que además de ilícitos destruyen la
   legitimidad de la evidencia.
4. Custodiar `data/ledger.key`: quien tenga la clave puede re-firmar una
   cadena y verificar una atestación. Perderla impide verificar HMAC de forma
   independiente; los hashes encadenados aún permiten revisar consistencia,
   pero no prueban quién creó el ledger.

## 6. Licencia y aviso

Proyecto bajo licencia MIT (ver LICENSE). La licencia cubre el código; el
uso que hagas con él es tuyo. Si redistribuís el proyecto, mantené este
archivo: es parte del diseño, no un anexo.
