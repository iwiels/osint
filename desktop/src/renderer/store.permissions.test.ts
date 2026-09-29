/**
 * Cola de permisos de herramientas.
 *
 * REGRESIÓN — dos permisos en paralelo y un solo hueco en la UI.
 *   El agente ejecuta los tool calls de un turno con `asyncio.gather`: si el
 *   modelo pide a la vez `link_entities` y `run_correlations` (ambas "ask"),
 *   emite DOS `permission.request` seguidas. El store guardaba un único
 *   `pendingPermission`, así que la segunda petición TAPABA a la primera: el
 *   dock mostraba sólo una, el analista respondía esa, y la otra se quedaba
 *   esperando en el motor hasta el timeout de 300s
 *   ("Permiso 'link_entities' sin respuesta del analista").
 *
 * Se ejecutan con el runner nativo de Node: `node --test`.
 */

import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import type { PermissionRequestPayload } from "@wraith/sdk";
import { useStore } from "./store.ts";

const store = () => useStore.getState();

const req = (request_id: string, tool: string): PermissionRequestPayload => ({
  request_id,
  tool,
  arguments: {},
});

beforeEach(() => {
  store().clearChat();
  store().clearPermissions();
});

describe("permisos concurrentes no se pisan", () => {
  it("conserva las dos peticiones y muestra la primera", () => {
    store().enqueuePermission(req("p-link", "link_entities"));
    store().enqueuePermission(req("p-corr", "run_correlations"));

    assert.equal(store().permissionQueue.length, 2, "las dos peticiones deben vivir");
    assert.equal(
      store().pendingPermission?.request_id,
      "p-link",
      "el dock muestra la primera petición, no la última en llegar",
    );
  });

  it("responder la cabeza revela la que estaba tapada", () => {
    store().enqueuePermission(req("p-link", "link_entities"));
    store().enqueuePermission(req("p-corr", "run_correlations"));

    store().resolvePermission("p-link");

    assert.equal(store().permissionQueue.length, 1);
    assert.equal(store().pendingPermission?.request_id, "p-corr");
  });

  it("caducar una petición que no es la cabeza no afecta a la visible", () => {
    store().enqueuePermission(req("p-link", "link_entities"));
    store().enqueuePermission(req("p-corr", "run_correlations"));

    store().resolvePermission("p-corr");

    assert.equal(store().pendingPermission?.request_id, "p-link");
  });

  it("una petición repetida no se encola dos veces", () => {
    store().enqueuePermission(req("p-link", "link_entities"));
    store().enqueuePermission(req("p-link", "link_entities"));

    assert.equal(store().permissionQueue.length, 1);
  });

  it("vaciar la cola deja el dock sin petición visible", () => {
    store().enqueuePermission(req("p-link", "link_entities"));
    store().clearPermissions();

    assert.equal(store().permissionQueue.length, 0);
    assert.equal(store().pendingPermission, null);
  });
});
