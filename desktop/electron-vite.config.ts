import { defineConfig, externalizeDepsPlugin } from "electron-vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
  },
  renderer: {
    plugins: [react()],
    resolve: {
      alias: {
        // El SDK vive en el workspace; se compila desde fuente.
        "@specter/sdk": path.resolve(__dirname, "../../packages/sdk/src/index.ts"),
      },
    },
    optimizeDeps: {
      exclude: ["@specter/sdk"],
    },
  },
});
