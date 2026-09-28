/**
 * EngineSidecar - gestiona el proceso del motor forense Python.
 * - Dev:    python -m engine.http_server (desde el repo)
 * - Prod:   engine/specter-engine.exe (PyInstaller onefile) junto a la app
 * Health-check con reintentos antes de declarar listo el motor.
 */

import { spawn, execFileSync, execSync, ChildProcess } from "node:child_process";
import { app } from "electron";
import path from "node:path";
import fs from "node:fs";
import http from "node:http";
import { randomBytes } from "node:crypto";

const ENGINE_PORT = Number(process.env.SPECTER_ENGINE_PORT || 8787);
const BASE_URL = `http://127.0.0.1:${ENGINE_PORT}`;

/** Nombre del binario del motor según plataforma (PyInstaller añade .exe en Windows). */
const ENGINE_BINARY = process.platform === "win32" ? "specter-engine.exe" : "specter-engine";

export interface EngineInfo {
  baseUrl: string;
  port: number;
  mode: "dev" | "packaged" | "external";
  /** Bearer del engine: el renderer lo manda en cada llamada (C1). */
  token: string;
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

function probeAuthenticated(timeoutMs: number, token: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(
      `${BASE_URL}/cases`,
      { headers: { Authorization: `Bearer ${token}` }, timeout: timeoutMs },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
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
  /** Token Bearer del engine: aleatorio por arranque (C1). */
  readonly token: string =
    process.env.SPECTER_ENGINE_TOKEN || randomBytes(32).toString("hex");

  constructor(private readonly isDev: boolean) {}

  async start(): Promise<EngineInfo> {
    const info = (mode: EngineInfo["mode"]): EngineInfo => ({
      baseUrl: BASE_URL,
      port: ENGINE_PORT,
      mode,
      token: this.token,
    });
    // En dev el engine SIEMPRE se lanza desde fuente: un ocupante previo
    // (proceso de ayer, exe viejo) es staleness garantizada. Se mata antes
    // de arrancar; si no se puede, se falla en voz alta en vez de enganchar
    // código viejo en modo "external".
    if (this.isDev) {
      await this.killPortOccupant();
      this.spawnDevEngine();
    } else if (await probeHealth(1500)) {
      // /health es público: solo reutilizar un motor externo si la app recibió
      // explícitamente su token y una ruta autenticada confirma que coincide.
      if (!process.env.SPECTER_ENGINE_TOKEN) {
        throw new Error(
          `Ya hay un engine en ${BASE_URL}, pero no se configuró ` +
            "SPECTER_ENGINE_TOKEN para autenticarlo.",
        );
      }
      if (!(await probeAuthenticated(1500, this.token))) {
        throw new Error(
          `Ya hay un engine en ${BASE_URL}, pero rechazó el token configurado. ` +
            "Configura el mismo SPECTER_ENGINE_TOKEN en ambos procesos.",
        );
      }
      return info("external");
    } else {
      this.spawnPackagedEngine();
    }

    // 2) Esperar /health con reintentos (~15s)
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      if (await probeHealth(1000)) {
        return info(this.isDev ? "dev" : "packaged");
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
        // POSIX: el hijo se lanza con detached=true, así que encabeza su
        // propio grupo de procesos; matar el grupo (-pid) alcanza al uvicorn
        // hijo igual que taskkill /T en Windows.
        try {
          process.kill(-child.pid, "SIGTERM");
        } catch {
          child.kill("SIGTERM");
        }
      }
    } catch {
      // el proceso ya no existe
    }
  }

  /**
   * Mata al ocupante del puerto (solo dev). Best-effort multiplataforma:
   * si el puerto sigue ocupado se lanza igual y el health-check dirá la
   * verdad (o el engine nuevo falla al bindear y se ve el error).
   */
  private async killPortOccupant(): Promise<void> {
    if (!(await probeHealth(800))) return;
    try {
      if (process.platform === "win32") {
        const out = execFileSync("netstat", ["-ano"], {
          stdio: ["ignore", "pipe", "ignore"],
        }).toString();
        const pids = new Set<string>();
        for (const line of out.split("\n")) {
          const [protocol, localAddress, , state, pid] = line.trim().split(/\s+/);
          const localPort = localAddress?.slice(localAddress.lastIndexOf(":") + 1);
          if (
            protocol === "TCP" &&
            state === "LISTENING" &&
            localPort === String(ENGINE_PORT) &&
            pid
          ) {
            pids.add(pid);
          }
        }
        for (const pid of pids) {
          if (Number(pid) !== process.pid) {
            console.log(`[engine] matando ocupante stale del puerto ${ENGINE_PORT}: pid ${pid}`);
            execFileSync("taskkill", ["/pid", pid, "/T", "/F"], { stdio: "ignore" });
          }
        }
      } else {
        execSync(`lsof -ti :${ENGINE_PORT} | xargs kill -9`, { stdio: "ignore" });
      }
    } catch {
      // sin ocupante localizable o sin permisos: el arranque lo dirá
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
          // C1: el engine exige este Bearer en todo salvo /health.
          SPECTER_ENGINE_TOKEN: this.token,
          // C4: el gate de permisos es opt-out; el sidecar no lo anula.
        },
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
        // POSIX: grupo de procesos propio para poder matar el árbol en stop().
        detached: process.platform !== "win32",
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
    const exe = path.join(base, "engine", ENGINE_BINARY);
    if (!fs.existsSync(exe)) {
      throw new Error(`Binario del engine no encontrado: ${exe}`);
    }
    // Directorio de datos por usuario, multiplataforma: app.getPath("userData")
    // resuelve %APPDATA% en Windows, ~/Library/Application Support en macOS y
    // ~/.config en Linux. Los secretos y la clave del ledger viven ahí, fuera
    // del bundle, y sobreviven a las actualizaciones de la app.
    const userData = app.getPath("userData");
    this.child = spawn(exe, ["--port", String(ENGINE_PORT)], {
      env: {
        ...process.env,
        SPECTER_DATA_DIR: path.join(userData, "data"),
        SPECTER_REPORTS_DIR: path.join(userData, "reports"),
        // C1: el engine exige este Bearer en todo salvo /health.
        SPECTER_ENGINE_TOKEN: this.token,
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      // POSIX: grupo de procesos propio para poder matar el árbol en stop().
      detached: process.platform !== "win32",
    });
    this.child.stdout?.on("data", (d: Buffer) => console.log(`[engine] ${d.toString().trim()}`));
    this.child.stderr?.on("data", (d: Buffer) => console.error(`[engine] ${d.toString().trim()}`));
  }
}
