/**
 * Postinstall del monorepo.
 * Prepara el entorno del motor Python (sidecar) si hay Python disponible.
 * En CI o cuando no hay Python, no falla: el .exe final empaqueta el engine.
 */
const { execSync, spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const ENGINE_DIR = path.join(__dirname, "..", "engine");

function tryPython(cmd) {
  const res = spawnSync(cmd, ["--version"], { encoding: "utf8" });
  return res.status === 0;
}

function main() {
  if (process.env.SPECTER_SKIP_ENGINE_SETUP === "1") return;

  // Orden por plataforma: en Windows "python"/"py"; en macOS/Linux "python3"
  // (a menudo no existe un "python" a secas). Se prueba el primero que responda.
  const python = ["python", "python3", "py"].find(tryPython);
  if (!python) {
    console.warn("[specter] Python 3.11+ no encontrado; omitiendo setup del engine.");
    return;
  }

  const venvDir = path.join(ENGINE_DIR, ".venv");
  if (!fs.existsSync(venvDir)) {
    console.log("[specter] Creando venv del engine...");
    execSync(`${python} -m venv "${venvDir}"`, { stdio: "inherit" });
  }

  const pipArgs = [
    "-m",
    "pip",
    "install",
    "-q",
    "-r",
    path.join(ENGINE_DIR, "requirements.txt"),
  ];
  console.log("[specter] Instalando dependencias del engine...");
  try {
    execSync(`${python} ${pipArgs.join(" ")}`, { stdio: "inherit", cwd: ENGINE_DIR });
  } catch (e) {
    console.warn("[specter] pip install fallo (continuando):", e.message);
  }

  // El navegador sigiloso (specter.stealth_browser) necesita el Chromium de
  // patchright. Si falla la descarga, el engine degrada a fallback HTTP.
  try {
    execSync(`${python} -m patchright install chromium`, {
      stdio: "inherit",
      timeout: 10 * 60 * 1000,
    });
  } catch (e) {
    console.warn("[specter] patchright install fallo (el engine usara fallback HTTP):", e.message);
  }
}

main();
