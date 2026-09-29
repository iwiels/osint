import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createCaseLoadGuard } from "./caseLoadGuard.ts";

describe("createCaseLoadGuard", () => {
  it("prevents an older case response from committing after a newer load starts", () => {
    const guard = createCaseLoadGuard();

    const caseARequest = guard.begin("case-a");
    const caseBRequest = guard.begin("case-b");

    assert.equal(guard.isCurrent(caseBRequest, "case-b"), true);
    assert.equal(guard.isCurrent(caseARequest, "case-b"), false);
  });

  it("invalidates an in-flight load when its case view is replaced", () => {
    const guard = createCaseLoadGuard();

    const request = guard.begin("case-a");
    guard.invalidate();

    assert.equal(guard.isCurrent(request, "case-a"), false);
  });

  it("rejects a response as soon as the selected case changes", () => {
    const guard = createCaseLoadGuard();
    const request = guard.begin("case-a");

    assert.equal(guard.isCurrent(request, "case-b"), false);
  });
});
