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

  it("caseLedger devuelve bloques tipados y estado de sellado", async () => {
    const block = { case_id: "case-1", block_index: 0, timestamp: "t", collector: "system", action: "GENESIS", evidence_id: null, evidence_hash: null, prev_hash: "0", block_hash: "h", signature: "sig-a" };
    const { client } = makeClient({ case_id: "case-1", blocks: [block], signature_status: "SEALED", key_id: "0123456789abcdef", valid: true });
    const ledger = await client.caseLedger("case-1");
    expect(ledger.blocks[0].block_hash).toBe("h");
    expect(ledger.blocks[0].signature).toBe("sig-a");
    expect(ledger.signature_status).toBe("SEALED");
    expect(ledger.valid).toBe(true);
  });

  it("caseTimeline pide los agregados del bucket elegido", async () => {
    const report = {
      case_id: "case 1",
      bucket: "hour",
      total_events: 4,
      first_activity: "2026-09-01T10:00:00+00:00",
      last_activity: "2026-09-01T11:00:00+00:00",
      span_hours: 1,
      buckets: [{ bucket: "2026-09-01T10", count: 4, entities: 3, evidences: 0, ledger_blocks: 1, types: { DOMAIN: 3 } }],
      bursts: [{ bucket: "2026-09-01T10", count: 4, ratio_vs_average: 3.2 }],
      collectors: { dns_collector: 1 },
      events: [{ timestamp: "2026-09-01T10:00:00+00:00", kind: "entity" as const, artifact_id: "domain:a.test", type: "DOMAIN" }],
    };
    const { client, fetchImpl } = makeClient(report);

    const timeline = await client.caseTimeline("case 1", "hour");

    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/cases/case%201/timeline?bucket=hour");
    expect(timeline.bursts[0].count).toBe(4);
    expect(timeline.events[0].kind).toBe("entity");
  });

  it("caseCorrelations y crossCaseIntelligence devuelven los informes de correlación", async () => {
    const crossCase = {
      anchor_case: "case-1",
      total_shared_entities: 1,
      cases_involved: ["case-1", "case-2"],
      cases_involved_count: 2,
      by_type: { DOMAIN: 1 },
      matches: [{ entity_id: "domain:shared.test", type: "DOMAIN", value: "shared.test", confidence: 1, case_count: 2, case_ids: ["case-1", "case-2"], first_seen: "t1", last_seen: "t2" }],
    };
    const { client, fetchImpl } = makeClient({
      case_id: "case-1",
      cross_case: crossCase,
      identity_candidates: { case_id: "case-1", analyzed_entities: 2, total_candidates: 1, min_score: 0.7, candidates: [] },
    });

    const correlations = await client.caseCorrelations("case-1");
    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/cases/case-1/correlations");
    expect(correlations.cross_case.matches[0].case_ids).toEqual(["case-1", "case-2"]);

    fetchImpl.mockImplementation(async () => new Response(JSON.stringify(crossCase), { status: 200 }));
    const global = await client.crossCaseIntelligence();
    expect(fetchImpl.mock.calls[1][0]).toBe("http://127.0.0.1:8787/intelligence/cross-case");
    expect(global.total_shared_entities).toBe(1);
  });

  it("caseAttestation propaga el sello y el error de caso sin cadena", async () => {
    const { client, fetchImpl } = makeClient({
      case_id: "case-1",
      sealed: true,
      algorithm: "hmac-sha256-v1",
      key_id: "abc",
      chain_valid: true,
      signature_status: "SEALED",
      total_blocks: 3,
      head: { block_index: 2, block_hash: "h2", signature: "s2", action: "MANUAL_LINK: a", timestamp: "t" },
      attestation: { payload: "{}", signature: "s" },
    });

    const attestation = await client.caseAttestation("case-1");
    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/cases/case-1/attestation");
    expect(attestation.sealed).toBe(true);
    expect(attestation.head?.block_index).toBe(2);
    expect(attestation.attestation?.signature).toBe("s");
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

    await client.caseGraph("case-1", { searchTerm: "alice", entityType: "DOMAIN" });
    const filtered = fetchImpl.mock.calls[2][0] as string;
    expect(filtered).toContain("search_term=alice");
    expect(filtered).toContain("entity_type=DOMAIN");
  });

  it("agentQuestionRespond envía respuestas al endpoint de preguntas", async () => {
    const { client, fetchImpl } = makeClient({ status: "ok", answers: [["DNI"]] });
    const res = await client.agentQuestionRespond("q1", [["DNI"]]);
    expect(res.answers).toEqual([["DNI"]]);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:8787/agent/questions/respond");
    expect(JSON.parse(init.body as string)).toEqual({ request_id: "q1", answers: [["DNI"]] });
  });

  it("agentSessions y agentSession consultan el historial", async () => {
    const { client, fetchImpl } = makeClient({
      sessions: [{ session_id: "sess-1", prompt: "hola", status: "completed" }],
    });
    const listed = await client.agentSessions("case-1", 10);
    expect(fetchImpl.mock.calls[0][0]).toBe(
      "http://127.0.0.1:8787/agent/sessions?limit=10&case_id=case-1",
    );
    expect(listed.sessions[0].session_id).toBe("sess-1");

    fetchImpl.mockImplementation(async () =>
      new Response(
        JSON.stringify({ session: { session_id: "sess-1", status: "completed" }, messages: [] }),
        { status: 200 },
      ),
    );
    const detail = await client.agentSession("sess-1");
    expect(fetchImpl.mock.calls[1][0]).toBe("http://127.0.0.1:8787/agent/sessions/sess-1");
    expect(detail.session.status).toBe("completed");
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
      new Response(JSON.stringify({ status: "COMPLETED", provider: "anthropic", model: "m", iterations: 1, tools_used: [], final_message: "ok", usage: { input_tokens: 12, output_tokens: 5 } }), { status: 200 }),
    );
    const run = await client.agentRun({
      case_id: "case-9",
      message: "hola",
      provider: "anthropic",
      stream: false,
      plan_first: false,
    });
    expect(run.status).toBe("COMPLETED");
    expect(run.usage).toEqual({ input_tokens: 12, output_tokens: 5 });
    const [url, init] = fetchImpl.mock.calls[fetchImpl.mock.calls.length - 1];
    expect(url).toBe("http://127.0.0.1:8787/agent/run");
    expect(JSON.parse(init.body as string)).toMatchObject({
      case_id: "case-9",
      message: "hola",
      stream: false,
      plan_first: false,
    });
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

  it("defaultHeaders mandan Authorization y agentRun acepta AbortSignal", async () => {
    const fetchImpl = vi.fn().mockImplementation(async () =>
      new Response(JSON.stringify({ status: "COMPLETED" }), { status: 200 }),
    );
    const client = new SpecterClient({
      baseUrl: "http://127.0.0.1:8787",
      fetchImpl,
      defaultHeaders: { Authorization: "Bearer tok" },
    });
    const controller = new AbortController();
    await client.agentRun({ message: "hola" }, { signal: controller.signal });
    const [, init] = fetchImpl.mock.calls[0];
    expect(init.headers).toMatchObject({ Authorization: "Bearer tok" });
    expect(init.signal).toBe(controller.signal);
  });

  it("deleteAgentSession y cancelRuns pegan a sus endpoints", async () => {
    const { client, fetchImpl } = makeClient({ status: "ok" });
    await client.deleteAgentSession("sess-9");
    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/agent/sessions/sess-9");
    expect(fetchImpl.mock.calls[0][1].method).toBe("DELETE");

    await client.cancelRuns("case-1");
    const [url, init] = fetchImpl.mock.calls[1];
    expect(url).toBe("http://127.0.0.1:8787/agent/runs/cancel");
    expect(JSON.parse(init.body as string)).toEqual({ session_id: "case-1" });
  });

  it("deleteCase pega al endpoint de borrado en cascada", async () => {
    const { client, fetchImpl } = makeClient({ status: "ok", case_id: "case-9" });
    const res = await client.deleteCase("case-9");
    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/cases/case-9");
    expect(fetchImpl.mock.calls[0][1].method).toBe("DELETE");
    expect(res.case_id).toBe("case-9");
  });

  it("bóveda: lista, guarda y borra keys sin exponer valores", async () => {
    const { client, fetchImpl } = makeClient({
      secrets: [{ name: "virustotal_api_key", env_var: "VIRUSTOTAL_API_KEY", configured: true, masked: "••••••••" }],
      path: "secrets.json",
    });
    const listed = await client.listSecrets();
    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/settings/secrets");
    expect(listed.secrets[0].configured).toBe(true);

    await client.setSecret("virustotal_api_key", "sk-vt");
    const [, putInit] = fetchImpl.mock.calls[1];
    expect(fetchImpl.mock.calls[1][0]).toBe("http://127.0.0.1:8787/settings/secrets/virustotal_api_key");
    expect(JSON.parse(putInit.body as string)).toEqual({ value: "sk-vt" });

    await client.deleteSecret("virustotal_api_key");
    expect(fetchImpl.mock.calls[2][0]).toBe("http://127.0.0.1:8787/settings/secrets/virustotal_api_key");
    expect(fetchImpl.mock.calls[2][1].method).toBe("DELETE");
  });
});

function makeRespond(client: SpecterClient, fetchImpl: ReturnType<typeof vi.fn>) {
  fetchImpl.mockResolvedValueOnce(
    new Response(JSON.stringify({ status: "ok", decision: "allow_session" }), { status: 200 }),
  );
}
