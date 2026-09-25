import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/**/*.test.ts", "src/types.ts"], // types.ts: solo tipos, sin runtime
      // Ratchet: umbrales del SDK; CI falla si bajan. (2026-09: subidos tras
      // alcanzar 98.9% real; línea 46 pendiente de cubrir con test de error.)
      thresholds: {
        lines: 95,
        functions: 90,
        branches: 88,
        statements: 95,
      },
    },
  },
});
