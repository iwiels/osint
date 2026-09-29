// Envuelve electron-builder para pasarle la versión de Electron que hay instalada.
//
// Con workspaces de npm, `electron` queda hoisteado en la raíz y electron-builder, que
// corre desde desktop/, solo lo busca en desktop/node_modules. Al no encontrarlo lee la
// versión de package.json ("^33.0.0") y aborta porque un rango no es una versión fija:
// "Cannot compute electron version from installed node modules".
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { version } = require("electron/package.json");
const cli = require.resolve("electron-builder/cli.js");

const result = spawnSync(
  process.execPath,
  [cli, `--config.electronVersion=${version}`, ...process.argv.slice(2)],
  { stdio: "inherit" },
);
process.exit(result.status ?? 1);
