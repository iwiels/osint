/**
 * Wrapper multiplataforma para ejecutar comandos Python del proyecto.
 * Resuelve el intérprete en orden: venv del repo → venv del engine → global.
 * Uso: node scripts/run-python.js -m ruff check engine/ tests/
 */
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const win = process.platform === "win32";
const repoRoot = path.join(__dirname, "..");

const candidates = [
  path.join(repoRoot, ".venv", win ? "Scripts" : "bin", win ? "python.exe" : "python"),
  path.join(repoRoot, "engine", ".venv", win ? "Scripts" : "bin", win ? "python.exe" : "python"),
];

function resolvePython() {
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return "python"; // global (CI instala deps antes de llamar a los scripts)
}

const python = resolvePython();
const args = process.argv.slice(2);

const res = spawnSync(python, args, { stdio: "inherit", cwd: repoRoot });
process.exit(res.status ?? 1);
