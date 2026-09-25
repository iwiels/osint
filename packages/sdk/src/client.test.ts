import { describe, expect, it, vi } from "vitest";
import { SpecterClient, SpecterError } from "./index";

function makeClient(jsonResponse: unknown, status = 200) {
  // mockImplementation (no mockResolvedValue): cada llamada necesita una
  // Response nueva porque su body solo puede leerse una vez.
  const fetchImpl = vi.fn().mockImplementation(async () =>
    new Response(JSON.stringify(jsonResponse), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
  const client = new SpecterClient({ baseUrl: "http://127.0.0.1:8787/", fetchImpl });
  return { client, fetchImpl };
}

describe("SpecterClient", () => {
  it("normaliza la baseUrl y hace health()", async () => {
    const { client, fetchImpl } = makeClient({ status: "ok", engine: "specter", version: "0.2.0", mcp_tools: 15, data_dir: "", reports_dir: "" });
    const health = await client.health();
    expect(health.status).toBe("ok");
    expect(health.mcp_tools).toBe(15);
    expect(fetchImpl).toHaveBeenCalledWith("http://127.0.0.1:8787/health", expect.anything());
  });

  it("createCase envía POST con cuerpo JSON", async () => {
    const { client, fetchImpl } = makeClient({ status: "CASE_CREATED", case_id: "case-1", name: "Test", investigator: "A", genesis_hash: "abc", message: "ok" });
    const created = await client.createCase({ name: "Test", description: "d" });
    expect(created.case_id).toBe("case-1");
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:8787/cases");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ name: "Test", description: "d" });
  });

  it("mapea errores HTTP a SpecterError", async () => {
    const { client } = makeClient({ detail: "Caso no existe" }, 404);
    await expect(client.caseGraph("nope")).rejects.toBeInstanceOf(SpecterError);
  });

  it("caseLedger devuelve bloques tipados", async () => {
    const block = { case_id: "case-1", block_index: 0, timestamp: "t", collector: "system", action: "GENESIS", evidence_id: null, evidence_hash: null, prev_hash: "0", block_hash: "h" };
    const { client } = makeClient({ case_id: "case-1", blocks: [block] });
    const ledger = await client.caseLedger("case-1");
    expect(ledger.blocks[0].block_hash).toBe("h");
  });

  it("listTools y agentPermissionRespond contratos basicos", async () => {
    const { client, fetchImpl } = makeClient({ tools: [] });
    await client.listTools();
    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/tools");

    makeRespond(client, fetchImpl);
    const res = await client.agentPermissionRespond("p1", "allow_session");
    expect(res.decision).toBe("allow_session");
    const [url, init] = fetchImpl.mock.calls[1];
    expect(url).toBe("http://127.0.0.1:8787/agent/permissions/respond");
    expect(JSON.parse(init.body as string)).toEqual({ request_id: "p1", decision: "allow_session" });
  });

  it("caseGraph construye query params segun opciones", async () => {
    const { client, fetchImpl } = makeClient({ nodes: [], edges: [], total_nodes: 0, total_edges: 0 });

    await client.caseGraph("case-1");
    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/cases/case-1/graph");

    await client.caseGraph("case 2", { maxDepth: 3, centerId: "n1" });
    const url = fetchImpl.mock.calls[1][0] as string;
    expect(url).toContain("/cases/case%202/graph");
    expect(url).toContain("max_depth=3");
    expect(url).toContain("center_id=n1");
  });

  it("wrappers restantes: listCases, getCase y agentRun", async () => {
    const { client, fetchImpl } = makeClient([]);
    await client.listCases();
    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/cases");

    fetchImpl.mockImplementation(async () =>
      new Response(JSON.stringify({ case_id: "case-9", name: "n", description: "d", investigator: "i", created_at: "t", status: "active" }), { status: 200 }),
    );
    const c = await client.getCase("case-9");
    expect(c.case_id).toBe("case-9");

    fetchImpl.mockImplementation(async () =>
      new Response(JSON.stringify({ status: "COMPLETED", provider: "anthropic", model: "m", iterations: 1, tools_used: [], final_message: "ok" }), { status: 200 }),
    );
    const run = await client.agentRun({ case_id: "case-9", message: "hola", provider: "anthropic" });
    expect(run.status).toBe("COMPLETED");
    const [url, init] = fetchImpl.mock.calls[fetchImpl.mock.calls.length - 1];
    expect(url).toBe("http://127.0.0.1:8787/agent/run");
    expect(JSON.parse(init.body as string)).toMatchObject({ case_id: "case-9", message: "hola" });
  });

  it("propaga errores HTTP con body de texto plano como SpecterError", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response("Internal Server Error", { status: 500 }),
    );
    const client = new SpecterClient({ baseUrl: "http://127.0.0.1:8787", fetchImpl });
    const err = await client.callTool("investigate_domain", {}).catch((e) => e);
    expect(err).toBeInstanceOf(SpecterError);
    expect(err.status).toBe(500);
    expect(err.message).toContain("Internal Server Error");
  });
});

function makeRespond(client: SpecterClient, fetchImpl: ReturnType<typeof vi.fn>) {
  fetchImpl.mockResolvedValueOnce(
    new Response(JSON.stringify({ status: "ok", decision: "allow_session" }), { status: 200 }),
  );
}
