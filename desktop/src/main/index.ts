/**
 * Specter Desktop - Main Process
 *  - Ventana BrowserWindow con preload sandboxed (contextIsolation on)
 *  - Ciclo de vida de la app
 *  - Spawn + health-check del sidecar del engine (Python HTTP)
 *  - IPC mínimo y seguro: abrir carpeta de reportes en el explorador
 */

import { app, BrowserWindow, ipcMain, shell } from "electron";
import path from "node:path";
import { EngineSidecar } from "./sidecar";

let mainWindow: BrowserWindow | null = null;
let sidecar: EngineSidecar | null = null;
let engineBaseUrl = "http://127.0.0.1:8787";

const isDev = !app.isPackaged;

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
      sandbox: false,
    },
  });

  mainWindow.once("ready-to-show", () => mainWindow?.show());

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
  });
}

// IPC: revelar un dossier en el explorador de archivos
ipcMain.handle("specter:reveal", async (_evt, fsPath: string) => {
  shell.showItemInFolder(fsPath);
  return true;
});

app.whenReady().then(async () => {
  sidecar = new EngineSidecar(isDev);
  try {
    const info = await sidecar.start();
    engineBaseUrl = info.baseUrl;
    console.log("[specter] engine listo:", info);
  } catch (err) {
    console.error("[specter] engine no disponible, la UI mostrara banner offline:", err);
  }

  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  sidecar?.stop();
});
