/**
 * EngineSidecar - gestiona el proceso del motor forense Python.
 * - Dev:    python -m engine.http_server (desde el repo)
 * - Prod:   engine/specter-engine.exe (PyInstaller onefile) junto a la app
 * Health-check con reintentos antes de declarar listo el motor.
 */

import { spawn, execSync, ChildProcess } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import http from "node:http";

const ENGINE_PORT = Number(process.env.SPECTER_ENGINE_PORT || 8787);
const BASE_URL = `http://127.0.0.1:${ENGINE_PORT}`;

export interface EngineInfo {
  baseUrl: string;
  port: number;
  mode: "dev" | "packaged" | "external";
}

function probeHealth(timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(`${BASE_URL}/health`, { timeout: timeoutMs }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.on("error", () => resolve(false));
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export class EngineSidecar {
  private child: ChildProcess | null = null;
  private stopping = false;

  constructor(private readonly isDev: boolean) {}

  async start(): Promise<EngineInfo> {
    // 1) ¿Engine ya corriendo? (lanzador externo o instancia previa)
    if (await probeHealth(1500)) {
      return { baseUrl: BASE_URL, port: ENGINE_PORT, mode: "external" };
    }

    if (this.isDev) {
      this.spawnDevEngine();
    } else {
      this.spawnPackagedEngine();
    }

    // 2) Esperar /health con reintentos (~15s)
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      if (await probeHealth(1000)) {
        return { baseUrl: BASE_URL, port: ENGINE_PORT, mode: this.isDev ? "dev" : "packaged" };
      }
      await delay(600);
    }
    throw new Error(`Engine no respondio en ${BASE_URL}/health tras 15s`);
  }

  stop(): void {
    this.stopping = true;
    const child = this.child;
    this.child = null;
    if (!child || !child.pid) return;
    try {
      if (process.platform === "win32") {
        // Mata el arbol (uvicorn hijo incluido)
        execSync(`taskkill /pid ${child.pid} /T /F`, { stdio: "ignore" });
      } else {
        child.kill("SIGTERM");
      }
    } catch {
      // el proceso ya no existe
    }
  }

  /**
   * Resuelve el ejecutable Python a usar en dev, en orden de prioridad:
   *  1. SPECTER_PYTHON (override manual)
   *  2. <repo>/.venv (venv del proyecto, creado con uv)
   *  3. <repo>/engine/.venv (creado por scripts/postinstall.js)
   *  4. "python" del sistema (último recurso: probablemente sin dependencias)
   */
  private resolvePython(repoRoot: string): string {
    if (process.env.SPECTER_PYTHON) return process.env.SPECTER_PYTHON;
    const win = process.platform === "win32";
    const candidates = [
      path.join(repoRoot, ".venv", win ? "Scripts\\python.exe" : "bin/python"),
      path.join(repoRoot, "engine", ".venv", win ? "Scripts\\python.exe" : "bin/python"),
    ];
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) return candidate;
    }
    console.warn(
      "[engine] No se encontro venv del proyecto; usando python del sistema " +
        "(instala dependencias con: pip install -r engine/requirements.txt)",
    );
    return "python";
  }

  private spawnDevEngine(): void {
    // __dirname = desktop/out/main → 3 niveles arriba = raíz del repo
    const repoRoot = path.resolve(__dirname, "../../..");
    const python = this.resolvePython(repoRoot);
    console.log(`[engine] spawn: ${python} -m engine.http_server (cwd: ${repoRoot})`);
    this.child = spawn(
      python,
      ["-m", "engine.http_server", "--port", String(ENGINE_PORT)],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          PYTHONUNBUFFERED: "1",
          // Refuerzo: garantiza que 'engine' y 'specter' sean importables
          // aunque el cwd no fuera la raíz del repo.
          PYTHONPATH: repoRoot,
          SPECTER_DATA_DIR: path.join(repoRoot, "data"),
          SPECTER_REPORTS_DIR: path.join(repoRoot, "reports"),
        },
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      },
    );
    this.child.stdout?.on("data", (d: Buffer) => console.log(`[engine] ${d.toString().trim()}`));
    this.child.stderr?.on("data", (d: Buffer) => console.error(`[engine] ${d.toString().trim()}`));
    this.child.on("error", (err) => {
      console.error("[engine] fallo al spawn del proceso:", err.message);
    });
    this.child.on("exit", (code) => {
      if (!this.stopping) console.warn(`[engine] proceso termino con codigo ${code}`);
    });
  }

  private spawnPackagedEngine(): void {
    const base = process.resourcesPath || path.dirname(process.execPath);
    const exe = path.join(base, "engine", "specter-engine.exe");
    if (!fs.existsSync(exe)) {
      throw new Error(`Binario del engine no encontrado: ${exe}`);
    }
    const userData = process.env.APPDATA || base;
    this.child = spawn(exe, ["--port", String(ENGINE_PORT)], {
      env: {
        ...process.env,
        SPECTER_DATA_DIR: path.join(userData, "specter-osint", "data"),
        SPECTER_REPORTS_DIR: path.join(userData, "specter-osint", "reports"),
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    this.child.stdout?.on("data", (d: Buffer) => console.log(`[engine] ${d.toString().trim()}`));
    this.child.stderr?.on("data", (d: Buffer) => console.error(`[engine] ${d.toString().trim()}`));
  }
}
