# Política de seguridad

## Versiones soportadas

Solo la última release publicada recibe correcciones de seguridad.

| Versión | Soporte |
|---|---|
| Última release (`vX.Y.Z`) | ✅ |
| Anteriores | ❌ |

## Cómo reportar una vulnerabilidad

**No abras un issue público.** Usa el
[reporte privado de vulnerabilidades](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
de GitHub: pestaña **Security** → **Report a vulnerability**.

Incluye, si puedes:

- Descripción del impacto y del vector de ataque.
- Pasos mínimos para reproducirlo (versión, plataforma, configuración).
- Prueba de concepto, si existe.
- Si lo deseas, una propuesta de mitigación.

### Qué esperar

Es un proyecto mantenido por una sola persona sin financiación: no hay SLA. El
objetivo es **acuse de recibo en 7 días** y una evaluación inicial en 30. Si el
reporte es válido, se publica un GitHub Security Advisory y se te acredita salvo
que prefieras lo contrario.

## Alcance

**Dentro de alcance:**

- El motor Python (`engine/`) y su API HTTP: autenticación Bearer, permission
  gate, SSRF guard (`netguard.py`), rutas de filesystem, manejo de secretos.
- La app Electron (`desktop/`): `contextBridge`, IPC, aislamiento del renderer.
- El SDK TypeScript (`packages/sdk/`).
- El ledger de custodia y su verificación HMAC.
- Ejecución de código no confiable a través de los colectores o del agente.

**Fuera de alcance:**

- Vulnerabilidades en dependencias de terceros: repórtalas aguas arriba
  (Dependabot ya vigila este repositorio).
- El hecho de que el motor pueda consultar fuentes públicas: es su función.
  Consulta [LEGAL.md](LEGAL.md).
- Ingeniería social contra el maintainer.
- Ataques que requieran que el analista ejecute código malicioso en su propia
  máquina con los mismos privilegios.
- Reportes automáticos de scanners sin prueba de explotabilidad.

## Modelo de amenaza (resumen)

WraithOSINT está diseñado como una aplicación **local de un solo usuario**:

- El motor escucha **solo en loopback** por defecto y exige un Bearer por
  arranque. Exponerlo en una interfaz no loopback requiere definir el token a
  mano y es responsabilidad del operador.
- Las herramientas sensibles están detrás de un permission gate **fail-closed**:
  lo que no está permitido explícitamente se deniega.
- Las salidas a red pasan por un guard SSRF que bloquea loopback y rangos
  privados.
- La clave HMAC del ledger y las API keys viven en el directorio de datos del
  usuario, fuera del bundle, con permisos `0600` donde el sistema los soporta.

Lo que **no** ofrece: cifrado en reposo de la base de datos de casos, sandbox
del proceso del motor respecto al usuario, ni aislamiento entre casos. No lo
ejecutes con datos que no puedas permitirte procesar en claro.

## Buenas prácticas para operadores

1. No expongas el puerto del motor a la red.
2. No compartas tu `data/ledger.key`: quien la tenga puede re-firmar y validar
   atestaciones.
3. Trata la base de datos de casos como material sensible (contiene datos
   personales de terceros).
4. Revisa [LEGAL.md](LEGAL.md) antes de usar capacidades de doble uso
   (impersonación TLS, navegador sigiloso, enumeración de cuentas opt-in).
