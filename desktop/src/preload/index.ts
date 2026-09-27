/**
 * Preload - puente mínimo y seguro entre renderer y main.
 * El renderer habla con el engine por HTTP directo; aquí solo exponemos
 * APIs nativas necesarias (explorador de archivos).
 */

import { contextBridge, ipcRenderer } from "electron";

const api = {
  platform: process.platform,
  revealInFolder: (fsPath: string): Promise<boolean> =>
    ipcRenderer.invoke("specter:reveal", fsPath),
  checkHealth: (): Promise<unknown> =>
    ipcRenderer.invoke("specter:check-health"),
  openExternal: (url: string): Promise<boolean> =>
    ipcRenderer.invoke("specter:open-external", url),
  /** Bearer del engine (C1). Null fuera de Electron / sin sidecar. */
  getEngineToken: (): Promise<string | null> =>
    ipcRenderer.invoke("specter:engine-token").catch(() => null),
};

export type SpecterDesktopApi = typeof api;

contextBridge.exposeInMainWorld("specterDesktop", api);
