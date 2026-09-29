import { defineConfig, externalizeDepsPlugin } from "electron-vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { readFileSync } from "node:fs";
import path from "node:path";

// La versión que muestra la UI sale de desktop/package.json: un literal en el JSX se
// queda obsoleto en cada release (la cabecera decía v0.2.0 en un build 0.3.0).
const { version } = JSON.parse(readFileSync(path.resolve(__dirname, "package.json"), "utf-8"));

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
  },
  renderer: {
    define: { __APP_VERSION__: JSON.stringify(version) },
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        // El SDK vive en el workspace; se compila desde fuente.
        "@wraith/sdk": path.resolve(__dirname, "../packages/sdk/src/index.ts"),
        "@renderer": path.resolve(__dirname, "src/renderer"),
      },
    },
    optimizeDeps: {
      exclude: ["@wraith/sdk"],
    },
  },
});
