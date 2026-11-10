// Entry 2 (epic-adapter-seam): the simulated-harness conformance suite as part of the node
// floor. The runner (tools/conformance/run.mjs) drives every adapter through the contract
// case set with the scripted brain — zero classifier calls, zero network. Green here means
// every adapter conforms; the runner itself also proves the context-drop variant fails.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runConformance, formatReport } from "../tools/conformance/run.mjs";

test("conformance: every adapter passes the contract case set", async () => {
  const r = await runConformance();
  // The full report goes to stderr so a failure here is diagnosable from the test output.
  if (r.failed.length) process.stderr.write(formatReport(r) + "\n");
  assert.equal(r.failed.length, 0, `${r.failed.length}/${r.total} conformance cases failed: ` +
    r.failed.map((f) => `${f.adapter}/${f.name} — ${f.note}`).join("; "));
  // The five adapters plus the contract surface itself are all in the run.
  for (const adapter of ["contract", "hook", "opencode", "pi", "acp", "hermes"])
    assert.ok(r.adapters.some((a) => a === adapter || a.startsWith(`${adapter}/`)), `${adapter} is covered`);
  // The context-drop detection proof ran and passed (the stub failed carriage as required).
  const detection = r.results.find((x) => x.name.includes("context-drop detection"));
  assert.ok(detection?.ok, "the context-drop conformance case demonstrably fails the broken stub");
}, { timeout: 120000 });
