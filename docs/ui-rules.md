# Reglas UI/UX — obligatorias para cada componente

Estética de referencia: **illoca.com** (papel cálido, tinta carbón, índigo, arcilla, radios mínimos, hairlines, cero decoración). Primitivas en `desktop/src/renderer/styles/illoca.css`. Incumplir estas reglas rompe la revisión igual que romper un test.

## R0 — Gates (no negociables)

1. `npm run typecheck` verde.
2. `npm run a11y:contrast` verde (WCAG 2.2 AA: 4.5 texto, 3.0 controles/hairlines gráficas).
3. `npm run build --workspace desktop` verde.
4. Sin `console.log` de debug; sin texto de relleno.

## R1 — Solo tokens, nunca valores sueltos

- Colores: semánticos de `colors.css` (`text-strong`, `surface-raised-base`…) o primitivas `ill-*` de `illoca.css`. **Prohibidos**: hex literales, `rgb()` sueltos y la paleta por defecto de Tailwind (está desactivada a propósito).
- Tipo/espaciado/radios/sombras: `theme.css`. Prohibido `px` mágicos fuera de tokens.
- Un componente nuevo = un archivo en `ui/` + su CSS hermano con contrato por atributos (`data-component`, `data-slot`, `data-variant`). Prohibido acumular condicionales de clase en el JSX.
- Iconos: solo `Icon`/`IconButton` de `ui/`. **Prohibidos los emojis como iconos** y los caracteres decorativos (`↵`, `▲`, `✕` como único affordance) en texto visible.

## R2 — Tipografía con roles fijos

- Display/títulos: sans, tight (`tracking-tight`), semibold. Sin serifas decorativas.
- Etiquetas de sección: caps 11px, `tracking-caps`, color débil.
- Datos forenses (ids, hashes, fechas, conteos): mono, tabular-nums.
- Cuerpo 13px/150%. Nada de microcopy gritando: un tamaño, un peso por nivel.

## R3 — Silencio informativo (anti-cháchara)

- **Prohibidos los hints obvios en la UI** ("Enter envía", "clic para detalle", volcado de versión/hash/fechas en tooltips). Los atajos van en `title`, los diagnósticos en `/health` o consola del proceso main.
- Placeholders que enseñan con ejemplo, no con instrucciones.
- Errores accionables en una línea (qué pasó + qué hacer). Nada de stack traces al analista.
- Contadores solo si deciden algo (tabs con badge). Nada de "0 sesiones" decorativo sin acción.

## R4 — Anti "hecho con IA"

- Superficies planas + hairline. Sombras solo en flotantes (`--shadow-pop`).
- Sin gradientes decorativos, sin glows (salvo el punto vivo de streaming), sin negro `#000` ni blanco `#fff` puros, sin bordes arcoíris.
- Un acento por vista. La arcilla (`ill-clay`) es para peligro real y marca puntual; el índigo (`ill-indigo`), para acciones serias y sellos. El resto, tinta sobre papel.
- Radios `ill-r-*` (2/4/8). Nada redondeado tipo píldora salvo contadores.
- Espacio en blanco generoso: una idea por bloque, gap consistente, nada pegado.

## R5 — Una sola fuente de verdad por concepto

- Navegación: tabs O raíl, nunca ambos para lo mismo.
- Proveedor/modelo: SOLO la píldora del composer.
- Historial: SOLO el raíl. Bóveda: SOLO ajustes. Sin duplicar paneles.
- Una acción primaria por superficie; secundarias en ghost/icono; destructivas en dos pasos con estado armado inequívoco (rojo + texto, no solo borde).

## R6 — Accesibilidad WCAG 2.2 AA (siempre)

- Botones solo-icono con `aria-label`; toggles con `aria-expanded`/`aria-pressed`; tablists con roving tabindex + flechas/Home/End y `tabpanel` asociado.
- Streams en `role="log"` con `aria-relevant="additions"`; el foco nunca se pierde (al cerrar/plegar, vuelve al control que abrió).
- Foco visible sólido (`--focus-ring`) en todo lo interactivo, incl. canvas con `tabIndex` si recibe acciones.
- `prefers-reduced-motion`: sin animaciones decorativas (ver `base.css`).
- Contraste validado por el gate, no a ojo.

## R7 — Estados completos o no se entrega

Cada vista de datos: carga, vacío (con acción), error (accionable), offline, deshabilitado. Nada de paneles en blanco silenciosos ni spinners eternos.

## R8 — Densidad con criterio

- Listas: una línea por item (título + meta mínima); el id técnico va en `title`, no en la fila.
- Tablas: `caption` sr-only, `scope="col"`, mono tabular para cifras.
- Leyendas y ayudas: plegadas por defecto; el filtro vive junto a los datos, no duplicado.
- Máximo una barra de estado por vista (conteo + estado, nada más).

## R9 — Playbook de componentes illoca (extraído de su CSS/HTML real)

Fuente: `illoca.com/_nuxt/entry.*.css` + HTML (Nuxt/Tailwind v4, base 1px: `px-12` = 12px, `h-48` = 48px, `rounded-2/4` = 2/4px). Todo lo nuevo lo replica:

- **Botones**: altura fija 48px (`h-12` Tailwind), `inline-flex gap-2`, radio 4px, peso medium (500, jamás bold). Variantes: índigo sólido + texto crema / papel + tinta / arena + índigo. Sombra dura `2px 2px 0 rgb(0 0 0 / 0.18)` en primario (sin blur); al presionar, `translate(1px,1px)` + sombra 1px. Ver `ui/button.css`.
- **Chips/tags**: mono 11px/16px, tracking 0, radio 2px, padding 12/8, texto tenue. Para conteos, no para decorar.
- **Items de menú/lista**: columna flexible, gap 4px, radio 4px, padding 12/8; hover = lavado plano de superficie (sin bordes nuevos ni sombras).
- **Toggles de acordeón**: botón CUADRADO 2rem, fondo arena (`bg-sand`), chevron que rota 180° con la expansión (`data-[open]:rotate-180`). Nada de "ver ▲/ocultar ▼" en texto.
- **Links**: subrayado punteado arcilla 2px (puntos cada 4px, ver `prose.css`), no línea continua. El color del texto ya cumple contraste; el punteado es firma, no señal.
- **Cards**: papel + hairline arena + sombra dura `4px 4px 0 rgb(0 0 0 / 0.1)` en flotantes. Nada de `shadow-lg` con blur en superficies normales.
- **Tipo**: display 56→102px, leading 1.0, sin kerning, centrado y balanceado solo en héroes; H3 20→24px medium, tracking −0.02em, margen inferior 12px; peso 500 como techo salvo datos tabulares.
- **Espaciado**: ritmo 8/12/24/32, se permite full-bleed con gutters negativos en secciones, nunca relleno decorativo.
- **Movimiento**: una curva `cubic-bezier(0.4,0,0.2,1)`, 150ms interacciones / 200ms color. Sin bounces, sin shimmer salvo streaming real.
- **Convención de clases**: custom `nombre-bloque__elemento` + utilidades tras `|` solo en CSS propio, nunca en JSX del renderer (aquí manda el contrato `data-*` de `ui/`).

## R10 — Anti-slop (que no parezca generado por IA)

Checklist de delatores investigados (925studios, mania.design, r/webdesign). Ninguno puede existir en la UI:

1. **Tipografía con opinión**: display decidido (Space Grotesk) + mono técnica (Geist Mono). Prohibido Inter/sistema sin rol y pesos bold decorativos (techo: semibold, tabular en datos).
2. **Color semántico, nunca decorativo**: sin gradientes púrpura/azul en héroes, botones o acentos; cada color significa algo (acción, estado, dato). Nombres de token por rol, no `gradient-start`.
3. **Copy específico con voz**: nada de "Build the future" ni titulares intercambiables. Cada pantalla dice qué hace el producto con sus términos (expediente, custodia, sellar). Pregunta de control: ¿lo diría el fundador en voz alta?
4. **Jerarquía intencional**: romper la uniformidad a propósito (tamaños/pesos/espaciado distintos por importancia). Prohibido mismo radio + mismo padding en todo.
5. **Sin barras laterales de color** como único recurso (`border-l-2`): los estados llevan wash completo + icono + texto.
6. **Sin emojis ni glifos decorativos** (`⚡📋◔⧉↓↑■▍▲▼⌖◈»`) en texto visible: solo componente `Icon`. El cursor de streaming es un bloque CSS, no un carácter.
7. **Sin glows ni blur decorativos** (`shadow-[0_0_8px…]`): sombras duras con offset o hairlines. El pulso del punto vivo comunica estado, no decora.
8. **Movimiento con propósito**: animación solo en montaje de paneles y cambios de estado; jamás la misma entrada en cada mensaje/item de lista.
9. **Progressive disclosure**: nada de "todo visible a la vez". Leyendas, ayudas y secundarios plegados; el filtro junto a los datos.
10. **Estados reales**: vacío (con acción), carga, error accionable, offline, deshabilitado. Nada de pantallas en blanco silenciosas.
11. **Micro-interacciones en primarios y campos** (press, focus, hover con sentido). Nada que se mueva por decorar.
12. **Nada de imágenes placeholder/stock**: la app no usa imágenes; el grafo y los datos reales son la visual.
