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
};

export type SpecterDesktopApi = typeof api;

contextBridge.exposeInMainWorld("specterDesktop", api);
