/**
 * Specter Desktop - Main Process
 *  - Ventana BrowserWindow con preload sandboxed (contextIsolation on)
 *  - Ciclo de vida de la app
 *  - Spawn + health-check del sidecar del engine (Python HTTP)
 *  - IPC mínimo y seguro: abrir carpeta de reportes en el explorador
 */

import { app, BrowserWindow, crashReporter, ipcMain, Menu, MenuItem, shell } from "electron";
import path from "node:path";
import fs from "node:fs";
import { EngineSidecar } from "./sidecar";

let mainWindow: BrowserWindow | null = null;
let sidecar: EngineSidecar | null = null;
let engineBaseUrl = "http://127.0.0.1:8787";
/** Bearer del engine (generado por el sidecar por arranque; C1). */
let engineToken = "";

/** Carpeta de dossiers: el IPC reveal solo abre rutas bajo este árbol (A5). */
function reportsDir(): string {
  if (!app.isPackaged) return path.resolve(__dirname, "../../..", "reports");
  const base = process.env.APPDATA || path.dirname(process.execPath);
  return path.join(base, "specter-osint", "reports");
}

const isDev = !app.isPackaged;

// Forense de crashes: sin esto, un 0xC0000005 del proceso principal muere sin
// dejar rastro (ni WER ni dump). Con dumpDir, Chromium escribe un .dmp en
// %APPDATA%/specter-desktop/crash-dumps y el dump nombra el módulo exacto.
app.setPath("crashDumps", path.join(app.getPath("appData"), "specter-desktop", "crash-dumps"));
try {
  fs.mkdirSync(app.getPath("crashDumps"), { recursive: true });
} catch {
  // si no se puede crear, crashDumps sin dump es igual al status quo
}
try {
  crashReporter.start({
    uploadToServer: false,
    compress: false,
    submitURL: "",
  });
} catch (err) {
  console.warn("[specter] crashReporter no disponible:", err);
}

// Desactivar bloqueo de redes privadas en Chromium para comunicación dev local
// (renderer en localhost:5173 -> engine en 127.0.0.1:8787).
app.commandLine.appendSwitch("disable-features", "BlockInsecurePrivateNetworkRequests");

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 680,
    backgroundColor: "#0b0e14",
    show: false,
    title: "SpecterOSINT",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      // A4: sandbox del renderer. El preload solo usa contextBridge+ipcRenderer.
      sandbox: true,
    },
  });

  // Registrar menú de aplicación nativo con aceleradores estándar (Zoom, Portapapeles, DevTools)
  const appMenu = Menu.buildFromTemplate([
    {
      label: "Archivo",
      submenu: [{ role: "quit", label: "Salir" }],
    },
    {
      label: "Edición",
      submenu: [
        { role: "undo", label: "Deshacer" },
        { role: "redo", label: "Rehacer" },
        { type: "separator" },
        { role: "cut", label: "Cortar" },
        { role: "copy", label: "Copiar" },
        { role: "paste", label: "Pegar" },
        { role: "selectAll", label: "Seleccionar todo" },
      ],
    },
    {
      label: "Ver",
      submenu: [
        { role: "reload", label: "Recargar" },
        { role: "forceReload", label: "Forzar recarga" },
        { role: "toggleDevTools", label: "Alternar herramientas de desarrollo" },
        { type: "separator" },
        { role: "resetZoom", label: "Restablecer zoom" },
        { role: "zoomIn", label: "Acercar zoom" },
        { role: "zoomOut", label: "Alejar zoom" },
        { type: "separator" },
        { role: "togglefullscreen", label: "Pantalla completa" },
      ],
    },
  ]);
  Menu.setApplicationMenu(appMenu);

  // Soporte directo para F12, Ctrl+Shift+I y atajos de zoom (Ctrl/Cmd +, -, 0)
  mainWindow.webContents.on("before-input-event", (event, input) => {
    if (input.type === "keyDown") {
      if (input.key === "F12" || (input.control && input.shift && input.key.toLowerCase() === "i")) {
        mainWindow?.webContents.toggleDevTools();
        event.preventDefault();
        return;
      }

      const isCtrlOrCmd = input.control || input.meta;
      if (isCtrlOrCmd && !input.alt) {
        const currentZoom = mainWindow?.webContents.getZoomFactor() ?? 1;
        // Zoom in: '+' or '=' or 'Add' or Equal or NumpadAdd or BracketRight (Spanish/ISO layout)
        if (
          input.key === "+" ||
          input.key === "=" ||
          input.key === "Add" ||
          input.code === "Equal" ||
          input.code === "NumpadAdd" ||
          input.code === "BracketRight" ||
          input.code === "Plus"
        ) {
          mainWindow?.webContents.setZoomFactor(Math.min(currentZoom + 0.1, 3.0));
          event.preventDefault();
          return;
        }
        // Zoom out: '-' or '_' or 'Subtract' or Minus or NumpadSubtract or Slash (Spanish/ISO layout)
        if (
          input.key === "-" ||
          input.key === "_" ||
          input.key === "Subtract" ||
          input.code === "Minus" ||
          input.code === "NumpadSubtract" ||
          input.code === "Slash"
        ) {
          mainWindow?.webContents.setZoomFactor(Math.max(currentZoom - 0.1, 0.5));
          event.preventDefault();
          return;
        }
        // Zoom reset: '0' or Digit0 or Numpad0
        if (input.key === "0" || input.code === "Digit0" || input.code === "Numpad0") {
          mainWindow?.webContents.setZoomFactor(1.0);
          event.preventDefault();
          return;
        }
      }
    }
  });

  // Menú contextual para copiar, cortar, pegar y seleccionar todo
  mainWindow.webContents.on("context-menu", (_event, params) => {
    const menu = new Menu();

    if (params.isEditable) {
      menu.append(new MenuItem({ label: "Cortar", role: "cut" }));
      menu.append(new MenuItem({ label: "Copiar", role: "copy" }));
      menu.append(new MenuItem({ label: "Pegar", role: "paste" }));
      menu.append(new MenuItem({ type: "separator" }));
      menu.append(new MenuItem({ label: "Seleccionar todo", role: "selectAll" }));
    } else {
      if (params.selectionText) {
        menu.append(new MenuItem({ label: "Copiar", role: "copy" }));
        menu.append(new MenuItem({ type: "separator" }));
      }
      menu.append(new MenuItem({ label: "Seleccionar todo", role: "selectAll" }));
    }

    if (isDev) {
      menu.append(new MenuItem({ type: "separator" }));
      menu.append(
        new MenuItem({
          label: "Inspeccionar elemento",
          click: () => mainWindow?.webContents.inspectElement(params.x, params.y),
        })
      );
    }

    if (mainWindow) {
      menu.popup({ window: mainWindow });
    }
  });

  // Reenviar consola del renderer a la terminal del proceso principal
  mainWindow.webContents.on("console-message", (_event, level, message, line, sourceId) => {
    console.log(`[renderer:${level}] ${message} (${sourceId}:${line})`);
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow?.show();
    if (isDev) {
      mainWindow?.webContents.openDevTools({ mode: "detach" });
    }
  });

  // Interceptar navegación directa a URLs externas y abrirlas en el navegador del sistema.
  // A4: denegar por defecto (incluye file:/data:/blob:); solo la URL del
  // renderer puede cargar en la ventana.
  const rendererOrigin = (): string | null => {
    if (isDev && process.env.ELECTRON_RENDERER_URL) {
      try {
        const u = new URL(process.env.ELECTRON_RENDERER_URL);
        if (u.hostname === "localhost" || u.hostname === "127.0.0.1") return u.origin;
      } catch {
        return null;
      }
      return null;
    }
    return "file://";
  };
  mainWindow.webContents.on("will-navigate", (event, url) => {
    const origin = rendererOrigin();
    const allowed =
      origin !== null &&
      (origin === "file://" ? url.startsWith("file://") : url.startsWith(origin));
    if (!allowed) {
      event.preventDefault();
      if (url.startsWith("http://") || url.startsWith("https://") || url.startsWith("mailto:")) {
        shell.openExternal(url);
      }
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  const engineQuery = `engine=${encodeURIComponent(engineBaseUrl)}`;
  if (isDev && process.env.ELECTRON_RENDERER_URL) {
    mainWindow.loadURL(`${process.env.ELECTRON_RENDERER_URL}?${engineQuery}`);
  } else {
    mainWindow.loadFile(path.join(__dirname, "../renderer/index.html"), {
      search: engineQuery,
    });
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
    if (process.platform !== "darwin") {
      app.quit();
    }
  });

}

// IPC: revelar un dossier en el explorador de archivos (A5: confinado a reports/).
ipcMain.handle("specter:reveal", async (_evt, fsPath: string) => {
  try {
    const root = path.resolve(reportsDir());
    const target = path.resolve(String(fsPath ?? ""));
    const inside = target === root || target.startsWith(root + path.sep);
    if (inside && fs.existsSync(target)) {
      shell.showItemInFolder(target);
      return true;
    }
  } catch {
    // ruta inválida: denegar en silencio
  }
  return false;
});

// IPC: token Bearer del engine para el renderer (C1: nunca va en la URL).
ipcMain.handle("specter:engine-token", async () => engineToken);

// IPC: verificación directa de salud desde Node.js (inmune a CORS del navegador)
ipcMain.handle("specter:check-health", async () => {
  try {
    const res = await fetch(`${engineBaseUrl}/health`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
});

// IPC: abrir enlaces y páginas web en el navegador predeterminado del sistema operativo
ipcMain.handle("specter:open-external", async (_evt, url: string) => {
  if (url && (url.startsWith("http://") || url.startsWith("https://") || url.startsWith("mailto:"))) {
    try {
      await shell.openExternal(url);
      return true;
    } catch (err) {
      console.error("[specter] fallo al abrir url externa:", err);
      return false;
    }
  }
  return false;
});

app.whenReady().then(async () => {
  // Sin inyección de Allow-Private-Network: el engine ya no participa en PNA
  // (M1) y el renderer lleva el switch de Chromium que desactiva esos
  // preflights en su lado. Inyectar el header aquí solo ampliaba superficie.
  // El navegador sigiloso vive en el engine Python (specter.stealth_browser,
  // Playwright): fuera del proceso main de Electron. Un crash del subsistema de
  // navegador ya no puede tumbar la app (causa raíz de los 0xC0000005 previos).
  sidecar = new EngineSidecar(isDev);
  try {
    const info = await sidecar.start();
    engineBaseUrl = info.baseUrl;
    engineToken = info.token;
    console.log("[specter] engine listo:", { ...info, token: "<redactado>" });
  } catch (err) {
    console.error("[specter] engine no disponible, la UI mostrara banner offline:", err);
  }

  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

let isQuitting = false;

// Diagnóstico: cualquier proceso hijo de Chromium que muera (GPU, renderers,
// utility) queda registrado en la terminal principal con su motivo.
app.on("child-process-gone", (_event, details) => {
  console.warn(
    `[specter] Proceso ${details.type} terminado (${details.reason}` +
      `${details.exitCode ? `, exit ${details.exitCode}` : ""}), continuando...`,
  );
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  if (isQuitting) return;
  isQuitting = true;
  sidecar?.stop();
});
