/**
 * Tests del cliente SSE con un EventSource stub: verifica suscripción por
 * tipo de evento, parseo de payload y limpieza de listeners al cerrar.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { connectEvents, type EventHandlers } from "./sse";

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  url: string;
  closed = false;
  listeners = new Map<string, EventListener>();

  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: EventListener) {
    this.listeners.set(type, listener);
  }

  removeEventListener(type: string) {
    this.listeners.delete(type);
  }

  close() {
    this.closed = true;
  }

  /** Emite con el contrato real del engine: envelope {seq, type, payload, ts}. */
  emit(type: string, payload: unknown) {
    this.listeners.get(type)?.({
      data: JSON.stringify({ seq: 1, type, payload, ts: new Date().toISOString() }),
    } as MessageEvent);
  }
}

describe("connectEvents", () => {
  const OriginalEventSource = globalThis.EventSource;

  afterEach(() => {
    globalThis.EventSource = OriginalEventSource;
    FakeEventSource.instances = [];
  });

  it("se suscribe a los tipos de eventos registrados y parsea payloads", () => {
    globalThis.EventSource = FakeEventSource as unknown as typeof EventSource;
    const onPermission = vi.fn();
    const handlers: EventHandlers = { "permission.request": onPermission };

    const dispose = connectEvents("http://127.0.0.1:8787", handlers);
    const es = FakeEventSource.instances[0];
    expect(es.url).toBe("http://127.0.0.1:8787/events");

    es.emit("permission.request", { request_id: "p1", tool: "investigate_domain", arguments: {} });
    expect(onPermission).toHaveBeenCalledTimes(1);
    expect(onPermission.mock.calls[0][0]).toMatchObject({ request_id: "p1" });

    dispose();
    expect(es.closed).toBe(true);
  });

  it("ignora eventos sin handler y JSON malformado sin lanzar", () => {
    globalThis.EventSource = FakeEventSource as unknown as typeof EventSource;
    const handlers: EventHandlers = {};

    const dispose = connectEvents("http://127.0.0.1:8787", handlers);
    const es = FakeEventSource.instances[0];

    expect(() => {
      es.emit("tool.started", { tool: "x" }); // sin handler
      es.listeners.get("tool.started")?.({ data: "{invalid" } as MessageEvent); // JSON roto
    }).not.toThrow();

    dispose();
  });
});
