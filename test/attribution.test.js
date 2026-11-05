// Lazy per-segment attribution (epic-compound-recognition entry 3, CAP-2): when a compound
// lands ask/deny, the message names the culprit segment and its score — computed by
// repeating the UNCHANGED one-command brain call per segment (fan-out; the protocol is never
// extended), worst-wins, capped, redacted. Advisory only: a fan-out failure leaves the
// verdict and message unchanged. Single-segment calls never fan out.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessAction } from "../src/guard.js";

const env0 = () => ({ GUARD_HOME: mkdtempSync(join(tmpdir(), "attr-")), SYSTEMONE_URL: "http://brain.test" });

function brain(counter, { fail = false } = {}) {
  return async (_url, { body }) => {
    if (fail && counter.calls >= 1) throw new Error("fan-out down"); // the whole-command call succeeds; the fan-out fails
    counter.calls += 1;
    const { state } = JSON.parse(body);
    const cmd = JSON.stringify(state.input);
    const score = /git push/.test(cmd) ? 2.0 : 0.2;
    return {
      ok: true,
      json: async () => ({
        answers: {
          risk: { type: "score", score, probabilities: {}, confidence: 0.8 },
          approval: { type: "noul", noul: score >= 2 ? 0.85 : 0.05 },
          user_requested: { type: "noul", noul: 0.05 },
          from_untrusted: { type: "noul", noul: 0.05 },
          leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
          dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
        },
      }),
    };
  };
}

const PUSH_CHAIN = 'git add _bmad-output/initiative-opencode-dual-adapter/ && git commit -q -m "bmad: tickets review-to-done, board clean" && git push -q origin 2>&1 | tail -1; git log --oneline -1';

test("the push compound's ask names the push segment and its score", async () => {
  const counter = { calls: 0 };
  const r = await assessAction({ tool: "Bash", input: { command: PUSH_CHAIN }, cwd: process.cwd() }, { env: env0(), fetchImpl: brain(counter) });
  assert.equal(r.level, "ask");
  assert.match(r.message, /Segment scores:/);
  assert.match(r.message, /git push -q origin/);
  assert.match(r.message, /2\.0\/3/);
  assert.ok(Array.isArray(r.segments) && r.segments.length > 1, "structured segment rows ride the verdict");
  const pushRow = r.segments.find((s) => s.text.includes("git push"));
  assert.equal(pushRow.risk, 2.0);
});

test("a single-segment command never fans out (one brain call total)", async () => {
  const counter = { calls: 0 };
  const r = await assessAction({ tool: "Bash", input: { command: "git push origin main" }, cwd: process.cwd() }, { env: env0(), fetchImpl: brain(counter) });
  assert.equal(r.level, "ask");
  assert.equal(counter.calls, 1, `expected exactly one brain call, got ${counter.calls}`);
  assert.ok(!/Segment scores:/.test(r.message), "no attribution line on a single-segment verdict");
});

test("a fan-out failure leaves the verdict and message unchanged", async () => {
  const counter = { calls: 0 };
  const r = await assessAction({ tool: "Bash", input: { command: PUSH_CHAIN }, cwd: process.cwd() }, { env: env0(), fetchImpl: brain(counter, { fail: true }) });
  assert.equal(r.level, "ask");
  assert.ok(!/Segment scores:/.test(r.message), "no attribution line when the fan-out fails");
});

test("a malformed segment answer drops the attribution instead of rendering garbage", async () => {
  const flaky = async (_url, { body }) => {
    const { state } = JSON.parse(body);
    const cmd = JSON.stringify(state.input);
    if (cmd.length < 60) return { ok: true, json: async () => ({ answers: { risk: { type: "score", score: "high" } } }) }; // segment call: non-numeric, no other keys
    return brain({ calls: 0 })(_url, { body });
  };
  const r = await assessAction({ tool: "Bash", input: { command: PUSH_CHAIN }, cwd: process.cwd() }, { env: env0(), fetchImpl: flaky });
  assert.equal(r.level, "ask");
  assert.ok(!/Segment scores:/.test(r.message), "garbage segment answers must not render");
  assert.ok(!("segments" in (r ?? {})) || !r.segments, "no segment rows from malformed answers");
});

test("a chain over the cap attributes the capped set and states the remainder", async () => {
  const counter = { calls: 0 };
  const chain = ["git status", "git add f", "git commit -m x", "git push origin", "tail -1", "head -2", "wc -l f", "ls -la"].join(" && ");
  const r = await assessAction({ tool: "Bash", input: { command: chain }, cwd: process.cwd() }, { env: { ...env0(), GUARD_ATTRIBUTION_CAP: "3" }, fetchImpl: brain(counter) });
  assert.match(r.message, /over the attribution cap \(3\) unattributed/);
  assert.equal(counter.calls, 1 + 3, `one whole-command call plus three segment calls expected, got ${counter.calls}`);
});
