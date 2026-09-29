// Publica el final de un log como anotación de error de GitHub Actions, para que el motivo
// de un fallo se lea en el resumen del run sin abrir los logs (que exigen iniciar sesión).
//
// Uso: node scripts/annotate-log.mjs <fichero> [título]
import { readFileSync } from "node:fs";

const [file, title = "Log"] = process.argv.slice(2);
let tail = "(el log no llegó a crearse)";
try {
  tail = readFileSync(file, "utf8")
    .replace(/\x1b\[[0-9;]*m/g, "") // colores ANSI
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(-25)
    .join("\n");
} catch {
  // sin log: el propio aviso ya es informativo
}
const escaped = tail.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
process.stdout.write(`::error title=${title}::${escaped.slice(0, 3800)}\n`);
