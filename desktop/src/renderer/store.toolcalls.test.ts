/**
 * Emparejamiento de tool calls en la UI.
 *
 * REGRESIÓN 1 — "Parámetros de entrada" y "Resultado" mostraban lo mismo.
 *   `startToolCall` sembraba `content` con `JSON.stringify(args)`, y la tarjeta
 *   se renderiza bajo un encabezado que dice "Resultado". Mientras la llamada
 *   corría eso ya era un mentón, pero si la llamada NUNCA se completaba (el
 *   analista detuvo el run y el `tool.completed` ya no llega) quedaba congelada
 *   para siempre con los parámetros duplicados como si fueran la salida.
 *
 * REGRESIÓN 2 — dos llamadas PARALELAS de la misma tool se pisaban.
 *   La deduplicación y el emparejamiento caían a un fallback por nombre cuando
 *   no había `callId` usable: con dos `web_fetch` a la vez, el segundo
 *   `tool.started` se descartaba (su tarjeta nunca existía) y su
 *   `tool.completed` acababa en la tarjeta del primero.
 *
 * Se ejecutan con el runner nativo de Node: `node --test`.
 */

import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import { useStore } from "./store.ts";

const store = () => useStore.getState();

beforeEach(() => {
  store().clearChat();
});

describe("tool calls en vuelo no deben mostrar parámetros como resultado", () => {
  it("no siembra el resultado con los argumentos de entrada", () => {
    store().startToolCall("call-1", "web_search", { query: "zavaleta" });

    const card = store().chat[0];
    assert.equal(card.status, "running");
    // El contenido real llega con `tool.completed`. Mientras tanto debe estar
    // vacío: si se siembra con los args, "Resultado" muestra los parámetros.
    assert.equal(card.content, "", "content no debe sembrarse con los argumentos");
    // Y los parámetros siguen disponibles para el bloque de entrada.
    assert.deepEqual(card.args, { query: "zavaleta" });
  });
});

describe("llamadas paralelas de la misma tool", () => {
  it("crea una tarjeta por llamada, no una sola", () => {
    store().startToolCall("call-a", "web_fetch", { url: "https://a.example" });
    store().startToolCall("call-b", "web_fetch", { url: "https://b.example" });

    assert.equal(store().chat.length, 2, "cada llamada en vuelo necesita su tarjeta");
    assert.deepEqual(
      store().chat.map((c) => c.callId),
      ["call-a", "call-b"],
    );
  });

  it("el resultado va a la tarjeta de SU callId, no a la primera del mismo nombre", () => {
    store().startToolCall("call-a", "web_fetch", { url: "https://a.example" });
    store().startToolCall("call-b", "web_fetch", { url: "https://b.example" });

    // Completan en orden invertido, que es lo normal en paralelo.
    store().completeToolCall("call-b", "web_fetch", '{"ok": "B"}');
    store().completeToolCall("call-a", "web_fetch", '{"ok": "A"}');

    const [a, b] = store().chat;
    assert.equal(a.content, '{"ok": "A"}', "call-a conserva SU resultado");
    assert.equal(b.content, '{"ok": "B"}', "call-b conserva SU resultado");
    assert.equal(store().chat.length, 2, "no debe aparecer una tarjeta huérfana");
    assert.ok(
      store().chat.every((c) => c.status === "completed"),
      "ninguna tarjeta debe quedarse en running",
    );
  });

  it("no duplica la tarjeta cuando llega un `tool.started` repetido", () => {
    store().startToolCall("call-a", "web_search", { query: "x" });
    store().startToolCall("call-a", "web_search", { query: "x" });

    assert.equal(store().chat.length, 1, "el reenvío del mismo callId es idempotente");
  });
});

describe("calls interrumpidas al detener el run", () => {
  it("cierra las que estaban en vuelo y respeta las completadas", () => {
    store().startToolCall("call-a", "web_fetch", { url: "https://a.example" });
    store().startToolCall("call-b", "browser_snapshot", { url: "https://b.example" });
    store().completeToolCall("call-a", "web_fetch", '{"ok": "A"}');

    store().interruptRunningTools();

    const [a, b] = store().chat;
    assert.equal(a.status, "completed", "una call ya completada no se toca");
    assert.equal(b.status, "interrupted", "la que seguía en vuelo se cierra");
    assert.equal(b.content, "", "no se inventa un resultado para la interrumpida");
    assert.ok(
      store().chat.every((c) => c.status !== "running"),
      "no debe quedar ninguna call colgada en running",
    );
  });

  it("es idempotente: llamarlo dos veces no rompe nada", () => {
    store().startToolCall("call-a", "web_fetch", { url: "https://a.example" });
    store().interruptRunningTools();
    const after = [...store().chat];
    store().interruptRunningTools();
    assert.deepEqual(store().chat, after);
  });
});
