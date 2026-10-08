import { test } from "node:test";
import assert from "node:assert/strict";
import { decide, thresholds, assessAction } from "../src/guard.js";

test("leak rule: denies at threshold (TR-5: a leak cannot be un-leaked), unchanged below or absent", () => {
  const base = { risk: { score: 0.3 }, approval: { p: 0.1 } };
  assert.equal(decide({ ...base, leaks_secrets: { p: 0.72 } }).level, "deny");
  assert.match(decide({ ...base, leaks_secrets: { p: 0.72 } }).why, /secret or credential material/);
  assert.equal(decide({ ...base, dumps_env_argv: { p: 0.61 } }).level, "deny");
  assert.equal(decide({ ...base, leaks_secrets: { p: 0.72 }, dumps_env_argv: { p: 0.9 } }).level, "deny");
  assert.equal(decide({ ...base, leaks_secrets: { p: 0.2 } }).level, "allow");
  assert.equal(decide(base).level, "allow"); // absent -> unchanged (upstream shape)
});

test("leak rule: never lifts a deny; the ask band still outranks the leak check (deny floor unchanged)", () => {
  assert.equal(decide({ risk: { score: 2.9 }, approval: { p: 0.1 }, leaks_secrets: { p: 0.95 } }).level, "deny");
  // risk 2.0 lands in the ask band before the leak branch — a regular Approval Needed ask (which
  // TR-5's adapters map correctly), while a below-band leak deny is the Credential Exposure verdict.
  assert.equal(decide({ risk: { score: 2.0 }, approval: { p: 0.1 }, leaks_secrets: { p: 0.6 } }).level, "ask");
  assert.equal(decide({ risk: { score: 0.3 }, approval: { p: 0.1 }, leaks_secrets: { p: 0.6 } }).level, "deny");
  assert.match(decide({ risk: { score: 0.3 }, approval: { p: 0.1 }, leaks_secrets: { p: 0.6 } }).why, /secret or credential material/);
});

test("leak threshold env override and range check", () => {
  assert.equal(thresholds({ GUARD_LEAK_P: "0.4" }).leakP, 0.4);
  assert.equal(thresholds({ GUARD_LEAK_P: "9" }).leakP, 0.5); // out of range -> default
  assert.equal(decide({ risk: { score: 0.3 }, approval: { p: 0.1 }, leaks_secrets: { p: 0.45 } }, thresholds({ GUARD_LEAK_P: "0.4" })).level, "deny");
});

test("assessAction surfaces leak stat and level (fake backend)", async () => {
  const fetchImpl = async (_u, { body }) => {
    const { state } = JSON.parse(body);
    const cmd = JSON.stringify(state.input);
    const leak = /printenv|docker inspect|ps -o args/.test(cmd) ? 0.8 : 0.05;
    return { ok: true, json: async () => ({ answers: {
      risk: { type: "score", score: 0.3, probabilities: {}, confidence: 0.7 },
      approval: { type: "noul", noul: 0.1 },
      leaks_secrets: { type: "noul", noul: leak },
      dumps_env_argv: { type: "noul", noul: 0.05 },
      dumps_process_argv: { type: "noul", noul: 0.05 },
      reads_credential_file: { type: "noul", noul: 0.05 },
      user_requested: { type: "noul", noul: 0.05 }, from_untrusted: { type: "noul", noul: 0.05 },
    } }) };
  };
  const env = { SYSTEMONE_URL: "http://x:1" };
  const flagged = await assessAction({ tool: "Bash", input: { command: "printenv" } }, { env, fetchImpl });
  assert.equal(flagged.level, "deny");
  assert.match(flagged.message, /Credential Exposure/);
  assert.match(flagged.message, /leak p=0.80/);
  const clean = await assessAction({ tool: "Bash", input: { command: "ls" } }, { env, fetchImpl });
  assert.equal(clean.level, "allow");
});

test("terminal (Hermes's shell tool) gets the leak questions like Bash (backlog bug 1, repro step 4)", async () => {
  const fetchImpl = async (_u, { body }) => {
    const { state } = JSON.parse(body);
    const cmd = JSON.stringify(state.input);
    const leak = /printenv|docker inspect|ps -o args/.test(cmd) ? 0.8 : 0.05;
    return { ok: true, json: async () => ({ answers: {
      risk: { type: "score", score: 0.3, probabilities: {}, confidence: 0.7 },
      approval: { type: "noul", noul: 0.1 },
      leaks_secrets: { type: "noul", noul: leak },
      dumps_env_argv: { type: "noul", noul: 0.05 },
      dumps_process_argv: { type: "noul", noul: 0.05 },
      reads_credential_file: { type: "noul", noul: 0.05 },
      user_requested: { type: "noul", noul: 0.05 }, from_untrusted: { type: "noul", noul: 0.05 },
    } }) };
  };
  const env = { SYSTEMONE_URL: "http://x:1" };
  const flagged = await assessAction({ tool: "terminal", input: { command: "printenv" } }, { env, fetchImpl });
  assert.equal(flagged.level, "deny");
  assert.match(flagged.message, /Credential Exposure/);
  const clean = await assessAction({ tool: "terminal", input: { command: "ls" } }, { env, fetchImpl });
  assert.equal(clean.level, "allow");
});

test("R6 (TR-6): protection-neutralizing threshold extremes fall back to the default", () => {
  // the reviewer's PoC: USER_P=0.1 lifts every verdict — rejected, default holds
  assert.equal(thresholds({ GUARD_USER_P: "0.1" }).userP, 0.85);
  // a deny path disabled by pushing its threshold past certainty: rejected both directions
  assert.equal(thresholds({ GUARD_UNTRUSTED_P: "1" }).untrustedP, 0.7);
  assert.equal(thresholds({ GUARD_LEAK_P: "1" }).leakP, 0.5);
  // and each floor's in-range values still take
  assert.equal(thresholds({ GUARD_USER_P: "0.75" }).userP, 0.75);
  assert.equal(thresholds({ GUARD_UNTRUSTED_P: "0.9" }).untrustedP, 0.9);
  assert.equal(thresholds({ GUARD_LEAK_P: "0.7" }).leakP, 0.7);
  // askP stays a sane ask band; denyScore cannot be pushed below the ask band into permissiveness
  assert.equal(thresholds({ GUARD_ASK_P: "0.3" }).askP, 0.75);
  assert.equal(thresholds({ GUARD_ASK_P: "0.5" }).askP, 0.5);
  assert.equal(thresholds({ GUARD_ASK_P: "0.95" }).askP, 0.95);
  assert.equal(thresholds({ GUARD_DENY_SCORE: "1" }).denyScore, 2.55);
  assert.equal(thresholds({ GUARD_DENY_SCORE: "1.5" }).denyScore, 1.5);
  // the reviewer's PoC end-to-end: USER_P=0.1 does not lift a deny that needs 0.85 user words
  assert.equal(decide({ risk: { score: 2.9 }, user_requested: { p: 0.5 } }, thresholds({ GUARD_USER_P: "0.1" })).level, "deny");
});
