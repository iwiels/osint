/**
 * Guarda de contraste WCAG 2.2 para los tokens del renderer.
 *
 * Lee `desktop/src/renderer/styles/colors.css`, resuelve var()/light-dark()/
 * color-mix() y verifica los pares que la interfaz usa de verdad, en los dos
 * esquemas. Falla (exit 1) si un par baja del mínimo exigido.
 *
 *   node scripts/a11y-contrast.mjs        # o: npm run a11y:contrast
 *
 * Notas de criterio:
 *  - Texto normal: ≥4.5:1 (WCAG 1.4.3 AA).
 *  - Elementos gráficos/controles: ≥3:1 (WCAG 1.4.11).
 *  - Los separadores decorativos (hairlines) se comprueban a ≥1.2:1 sólo como
 *    "siguen siendo visibles": no identifican ningún control, por lo que no
 *    les aplica 1.4.11. Si un hairline pasa a ser el borde de un control, hay
 *    que usar `--input-border-base`.
 */
import fs from "node:fs";

const CSS_PATH = "desktop/src/renderer/styles/colors.css";
const css = fs.readFileSync(CSS_PATH, "utf8");

/** Declaraciones `--nombre: valor;` (el valor puede contener comas/paréntesis). */
function parseVars(text) {
  const out = new Map();
  const re = /--([a-z0-9-]+)\s*:\s*([^;]+);/gi;
  let match;
  while ((match = re.exec(text))) out.set(match[1], match[2].trim());
  return out;
}
const VARS = parseVars(css);

/** Divide argumentos por comas respetando paréntesis anidados. */
function splitArgs(input) {
  const parts = [];
  let depth = 0;
  let current = "";
  for (const ch of input) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) {
      parts.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function rawToken(name, scheme) {
  const value = VARS.get(name);
  if (!value) throw new Error(`token no definido: --${name}`);
  if (value.startsWith("light-dark(")) {
    const [dark, light] = splitArgs(value.slice("light-dark(".length, -1));
    return scheme === "dark" ? dark : light;
  }
  return value;
}

function hexToRgb(hex) {
  const h = hex.replace("#", "");
  const full = h.length === 3 ? h.split("").map((c) => c + c).join("") : h;
  return [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16));
}

/** Valor CSS → { rgb, a }. Resuelve var() y color-mix(). */
function resolve(value, scheme, seen = new Set()) {
  const v = value.trim();

  if (v.startsWith("var(")) {
    const name = v.slice(4, v.lastIndexOf(")")).trim().replace(/^-+/, "");
    if (seen.has(name)) throw new Error(`referencia circular en --${name}`);
    seen.add(name);
    return resolve(rawToken(name, scheme), scheme, seen);
  }

  if (v.startsWith("#")) return { rgb: hexToRgb(v), a: 1 };

  if (v.startsWith("rgb(") || v.startsWith("rgba(")) {
    const inner = v.slice(v.indexOf("(") + 1, -1).replace(/\//, " ");
    const nums = inner.trim().split(/[\s,]+/).filter(Boolean);
    const [r, g, b] = nums.slice(0, 3).map(Number);
    return { rgb: [r, g, b], a: nums.length > 3 ? Number(nums[3]) : 1 };
  }

  if (v.startsWith("color-mix(")) {
    const [space, ...operands] = splitArgs(v.slice("color-mix(".length, -1));
    if (!/oklab|srgb/.test(space)) throw new Error(`espacio de color no soportado: ${space}`);
    const operand = (raw) => {
      const parts = raw.trim().split(/\s+/);
      if (parts.length === 1) return { value: parts[0], pct: null };
      const pct = parts.find((p) => p.endsWith("%"));
      return { value: parts.filter((p) => p !== pct).join(" "), pct: pct ? Number(pct.replace("%", "")) : null };
    };
    const [left, right] = operands.map(operand);
    const pctLeft = left.pct ?? 100 - (right.pct ?? 0);
    const pctRight = right.pct ?? 100 - (left.pct ?? 0);

    if (right.value === "transparent" || left.value === "transparent") {
      const solid = right.value === "transparent" ? left : right;
      const base = resolve(solid.value, scheme, seen);
      const pct = right.value === "transparent" ? pctLeft : pctRight;
      return { rgb: base.rgb, a: base.a * (pct / 100) };
    }
    const ca = resolve(left.value, scheme, seen);
    const cb = resolve(right.value, scheme, seen);
    const weight = pctLeft / (pctLeft + pctRight);
    return {
      rgb: ca.rgb.map((c, i) => Math.round(c * weight + cb.rgb[i] * (1 - weight))),
      a: ca.a * weight + cb.a * (1 - weight),
    };
  }

  throw new Error(`valor no soportado: ${v}`);
}

const composite = (fg, bgRgb) => fg.rgb.map((c, i) => Math.round(c * fg.a + bgRgb[i] * (1 - fg.a)));

function luminance([r, g, b]) {
  const channel = (c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(fgRgb, bgRgb) {
  const [l1, l2] = [luminance(fgRgb), luminance(bgRgb)];
  const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1];
  return (hi + 0.05) / (lo + 0.05);
}

const toHex = (rgb) => "#" + rgb.map((c) => Math.max(0, Math.min(255, c)).toString(16).padStart(2, "0")).join("");

/** [etiqueta, primer plano, fondo, mínimo exigido] */
const PAIRS = [
  // Texto (4.5:1) sobre todas las superficies donde aparece.
  ["texto fuerte / fondo", "--text-strong", "--background-base", 4.5],
  ["texto fuerte / panel", "--text-strong", "--surface-raised-base", 4.5],
  ["texto base / fondo", "--text-base", "--background-base", 4.5],
  ["texto base / panel", "--text-base", "--surface-raised-base", 4.5],
  ["texto base / elevado", "--text-base", "--surface-raised-strong", 4.5],
  ["texto base / flotante", "--text-base", "--surface-float-base", 4.5],
  ["texto débil / fondo", "--text-weak", "--background-base", 4.5],
  ["texto débil / panel", "--text-weak", "--surface-raised-base", 4.5],
  ["texto débil / diálogo", "--text-weak", "--surface-raised-stronger", 4.5],
  ["texto débil / flotante", "--text-weak", "--surface-float-base", 4.5],
  ["texto débil / campo", "--text-weak", "--input-base", 4.5],
  ["texto más débil / panel", "--text-weaker", "--surface-raised-base", 4.5],
  ["texto más débil / elevado", "--text-weaker", "--surface-raised-strong", 4.5],
  ["texto más débil / flotante", "--text-weaker", "--surface-float-base", 4.5],
  ["placeholder / campo", "--input-placeholder", "--input-base", 4.5],
  ["texto invertido / botón primario", "--text-invert", "--button-primary-base", 4.5],

  // Colores semánticos de texto sobre el fondo y sobre su propio tinte.
  ["marca / fondo", "--text-brand", "--background-base", 4.5],
  ["éxito / fondo", "--text-success", "--background-base", 4.5],
  ["aviso / fondo", "--text-warning", "--background-base", 4.5],
  ["crítico / fondo", "--text-critical", "--background-base", 4.5],
  ["info / fondo", "--text-info", "--background-base", 4.5],
  ["crítico sobre su tinte", "--text-critical", "--surface-critical-base", 4.5],
  ["éxito sobre su tinte", "--text-success", "--surface-success-base", 4.5],
  ["aviso sobre su tinte", "--text-warning", "--surface-warning-base", 4.5],
  ["info sobre su tinte", "--text-info", "--surface-info-base", 4.5],
  ["marca sobre su tinte", "--text-brand", "--surface-brand-weak", 4.5],
  ["terracota / fondo", "--text-draft-terracotta", "--background-base", 4.5],
  ["cobalto / fondo", "--text-draft-cobalt", "--background-base", 4.5],

  // Componentes y estados (3:1).
  ["icono / fondo", "--icon-base", "--background-base", 3],
  ["icono débil / fondo", "--icon-weak-base", "--background-base", 3],
  ["borde de campo / campo", "--input-border-base", "--input-base", 3],
  ["borde de campo activo / campo", "--input-border-focus", "--input-base", 3],
  ["anillo de foco / fondo", "--focus-ring-color", "--background-base", 3],
  ["anillo de foco / panel", "--focus-ring-color", "--surface-raised-strong", 3],
  ["anillo de foco / diálogo", "--focus-ring-color", "--surface-raised-stronger", 3],

  // Separadores decorativos (no identifican controles → no aplica 1.4.11).
  ["hairline / fondo", "--border-weak-base", "--background-base", 1.2],
  ["hairline fuerte / fondo", "--border-base", "--background-base", 1.2],
];

const norm = (name) => name.replace(/^-+/, "");

function backgroundColor(name, scheme) {
  const color = resolve(`var(--${norm(name)})`, scheme);
  if (color.a >= 1) return color.rgb;
  const base = resolve("var(--background-base)", scheme).rgb;
  return composite(color, base);
}

function audit(scheme) {
  console.log(`\n=== esquema ${scheme.toUpperCase()} ===`);
  let failures = 0;
  for (const [label, fgName, bgName, min] of PAIRS) {
    const bgRgb = backgroundColor(bgName, scheme);
    const fgRgb = composite(resolve(`var(--${norm(fgName)})`, scheme), bgRgb);
    const ratio = contrast(fgRgb, bgRgb);
    const ok = ratio >= min;
    if (!ok) failures++;
    const detail = ok ? "" : `  → ${fgName}=${toHex(fgRgb)} sobre ${bgName}=${toHex(bgRgb)}`;
    console.log(`${ok ? "ok  " : "FALLA"} ${ratio.toFixed(2).padStart(5)}:1 (min ${min})  ${label}${detail}`);
  }
  return failures;
}

try {
  const failures = audit("dark") + audit("light");
  console.log(
    `\nTotal de pares por debajo del mínimo: ${failures}` +
      (failures === 0 ? " — contraste WCAG AA en orden." : ""),
  );
  process.exit(failures === 0 ? 0 : 1);
} catch (err) {
  console.error(`\nNo se pudo auditar el contraste: ${err.message}`);
  process.exit(1);
}
