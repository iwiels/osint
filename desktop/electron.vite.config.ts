import { defineConfig, externalizeDepsPlugin } from "electron-vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
  },
  renderer: {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        // El SDK vive en el workspace; se compila desde fuente.
        "@specter/sdk": path.resolve(__dirname, "../packages/sdk/src/index.ts"),
        "@renderer": path.resolve(__dirname, "src/renderer"),
      },
    },
    optimizeDeps: {
      exclude: ["@specter/sdk"],
    },
  },
});
