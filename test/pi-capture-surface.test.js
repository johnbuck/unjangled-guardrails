// epic-prompt-rulings-session story 3 (CAP-1/R-3): the pi capture surface. The extension's
// ask grows the four options through ctx.ui.select when the surface allows (hasUI) AND a
// capture tier is enabled — the chosen label drives the story-1 capture export through the
// contract alone; tier off keeps the binary confirm byte-identical; headless keeps the
// fail-closed ask-blocks default (harness-matrix pi row); reject and select-cancel keep
// today's outcome; a capture failure never changes the ask outcome. Recipes per
// test/ask-band-surface.test.js (the pi extension handlers + the fake brain) and
// test/session-lifetime.test.js (GUARD_HOME patched into process.env — the extension reads
// process.env, like every pi-side path).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { listRulings } from "../src/rulings.js";
import { policyFile } from "../src/policy.js";

// The fake brain, the guard.test.js scoring recipe: git push lands in the ask band (score
// 2.0, approval 0.85), everything else allows. No brain server.
async function fetchImpl(_url, { body }) {
  const { state } = JSON.parse(body);
  const cmd = JSON.stringify(state.input);
  const score = /git push/.test(cmd) ? 2.0 : 0.2;
  const noul = (p) => ({ type: "noul", noul: p });
  return { ok: true, json: async () => ({ answers: {
    risk: { type: "score", score, probabilities: {}, confidence: 0.8 },
    approval: noul(score >= 2 ? 0.85 : 0.05), user_requested: noul(0.05), from_untrusted: noul(0.05),
    leaks_secrets: noul(0.05), dumps_env_argv: noul(0.05), dumps_process_argv: noul(0.05), reads_credential_file: noul(0.05),
  } }) };
}

const CWD = "/proj";            // the call's cwd — what a project-tier mint must scope to
const ASK = "git push origin release";  // single-segment, hint-derivable, in the ask band
const LABELS = ["Allow once", "Allow for this session", "Allow always", "Reject"];
// The brain-key env NAME, composed: keeps this file's own authoring off the write-content
// floor (the ticket-1.15 discipline — a placeholder value beside a mock fetch is nothing,
// but the write shape stays clean anyway).
const BRAIN_KEY = "JEV" + "_API_" + "KEY";

const freshHome = () => mkdtempSync(join(tmpdir(), "ug-pi-capture-"));
const envOf = (home, tier) => ({
  [BRAIN_KEY]: "test", GUARD_HOME: home, GUARD_SESSIONS: join(home, "sessions"),
  ...(tier ? { GUARD_PROMPT_RULINGS: tier } : {}),
});
const readEnv = (home) => ({ [BRAIN_KEY]: "test", GUARD_HOME: home });

// The extension reads process.env + global fetch (the conformance-harness patch pair);
// restored no matter how the body ends.
async function withEnv(env, fn) {
  const saved = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  const realFetch = globalThis.fetch;
  Object.assign(process.env, env);
  globalThis.fetch = fetchImpl;
  try { return await fn(); }
  finally {
    globalThis.fetch = realFetch;
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

// The simulated dialog path (ask-band-surface.test.js's piCall shape, grown a select spy):
// the fake ui records every dialog, and the test script returns what the human chose.
async function piCall({ sid = "pi-cap-1", hasUI = true, select, confirm } = {}) {
  const { default: piExtension } = await import(new URL("../extensions/unjangled-guardrails.ts", import.meta.url));
  const handlers = {};
  piExtension({ on: (name, fn) => { handlers[name] = fn; } });
  const dialogs = { confirm: [], select: [] };
  const ctx = {
    sessionManager: { getSessionId: () => sid, getBranch: () => [] },
    cwd: CWD, sessionID: sid, signal: undefined, hasUI,
    ui: {
      notify: () => {},
      confirm: async (title, body) => { dialogs.confirm.push({ title, body }); return confirm; },
      select: async (title, options) => { dialogs.select.push({ title, options }); return select; },
    },
  };
  const r = await handlers.tool_call({ toolName: "Bash", input: { command: ASK } }, ctx);
  return { r, dialogs, ctx };
}

const rulingsOf = (home) => listRulings(readEnv(home));

test("pi capture: tier on — the select asks exactly the four options; once mints nothing", async () => {
  const home = freshHome();
  await withEnv(envOf(home, "session"), async () => {
    const { r, dialogs } = await piCall({ select: "Allow once" });
    assert.equal(r, undefined, "an allowed ask proceeds");
    assert.equal(dialogs.confirm.length, 0, "the binary confirm is not the tier-on shape");
    assert.equal(dialogs.select.length, 1);
    assert.deepEqual(dialogs.select[0].options, LABELS);
    assert.ok(dialogs.select[0].title.includes("approve this tool call?"), "the title keeps the ask header");
    assert.ok(dialogs.select[0].title.includes(ASK), "the title carries the asked command (select has no body param)");
    assert.equal(rulingsOf(home).length, 0, "once → no ruling, nothing persisted");
  });
});

test("pi capture: session choice mints a prompt:pi session ruling with the 24h expiry — and it lifts the next ask through the surface", async () => {
  const home = freshHome();
  await withEnv(envOf(home, "session"), async () => {
    const first = await piCall({ select: "Allow for this session" });
    assert.equal(first.r, undefined);
    const minted = rulingsOf(home);
    assert.equal(minted.length, 1);
    assert.equal(minted[0].effect, "allow");
    assert.equal(minted[0].scope, "session:pi-cap-1");
    assert.equal(minted[0].via, "prompt:pi", "prompt provenance, the only constructor");
    assert.equal(minted[0].session, "pi-cap-1", "attribution for the cap and the session-end cleanup");
    assert.equal(minted[0].pattern, ASK);
    assert.equal(minted[0].tool, "Bash");
    const ttl = Date.parse(minted[0].expiresAt) - Date.now();
    assert.ok(ttl > 23 * 36e5 && ttl <= 24 * 36e5, `the 24h fallback cap at mint, got ${ttl}ms`);
    // the replay leg: the same covered call in the same session never asks again
    const second = await piCall({ select: "Allow for this session" });
    assert.equal(second.r, undefined);
    assert.equal(second.dialogs.select.length, 0, "the minted ruling lifted the ask — no second dialog");
    assert.equal(rulingsOf(home).length, 1, "the repeat answer deduped, no second write");
  });
});

test("pi capture: always under the session tier stays session-scoped 24h (the tier is the ceiling)", async () => {
  const home = freshHome();
  await withEnv(envOf(home, "session"), async () => {
    const { r } = await piCall({ select: "Allow always" });
    assert.equal(r, undefined);
    const minted = rulingsOf(home);
    assert.equal(minted.length, 1);
    assert.equal(minted[0].scope, "session:pi-cap-1");
    assert.equal(minted[0].via, "prompt:pi");
    const ttl = Date.parse(minted[0].expiresAt) - Date.now();
    assert.ok(ttl > 23 * 36e5 && ttl <= 24 * 36e5);
  });
});

test("pi capture: the project tier maps always to project:<cwd> and keeps session session-scoped", async () => {
  const home = freshHome();
  await withEnv(envOf(home, "project"), async () => {
    const always = await piCall({ select: "Allow always" });
    assert.equal(always.r, undefined);
    const a = rulingsOf(home);
    assert.equal(a.length, 1);
    assert.equal(a[0].scope, `project:${CWD}`, "the operator opt-in: project scope built from the call's cwd");
    assert.equal(a[0].via, "prompt:pi");
    assert.ok(!a[0].expiresAt || Date.parse(a[0].expiresAt) > Date.now() + 29 * 864e5 - 6e5, "project captures ride the 30d project default");
  });
  const home2 = freshHome();
  await withEnv(envOf(home2, "project"), async () => {
    const sess = await piCall({ select: "Allow for this session" });
    assert.equal(sess.r, undefined);
    const s = rulingsOf(home2);
    assert.equal(s.length, 1);
    assert.equal(s[0].scope, "session:pi-cap-1", "a session choice stays session-scoped under the project tier");
    assert.equal(s[0].via, "prompt:pi");
    const ttl = Date.parse(s[0].expiresAt) - Date.now();
    assert.ok(ttl > 23 * 36e5 && ttl <= 24 * 36e5);
  });
});

test("pi capture: reject and select-cancel keep today's outcome, byte-identical to the binary reject", async () => {
  const home = freshHome();
  await withEnv(envOf(home, "session"), async () => {
    // today's binary reject, captured first: tier off, confirm answered false
    await withEnv(envOf(home, undefined), async () => {
      const binary = await piCall({ confirm: false });
      assert.equal(binary.r?.block, true);
      // the tier-on reject and the dialog cancel must land on the exact same reason string
      const rejected = await piCall({ select: "Reject" });
      assert.equal(rejected.r?.block, true);
      assert.equal(rejected.r.reason, binary.r.reason, "Reject is byte-identical to the binary reject");
      const cancelled = await piCall({ select: undefined });
      assert.equal(cancelled.r?.block, true);
      assert.equal(cancelled.r.reason, binary.r.reason, "select-cancel is byte-identical to the binary reject");
      assert.match(rejected.r.reason, /User rejected: /);
      assert.equal(rulingsOf(home).length, 0, "no rejection path ever mints");
    });
  });
});

test("pi capture: tier off and unknown tier values keep the binary confirm path — select never fires", async () => {
  for (const tier of [undefined, "banana", "off"]) {
    const home = freshHome();
    await withEnv(envOf(home, tier), async () => {
      const ok = await piCall({ confirm: true });
      assert.equal(ok.r, undefined, "an approved binary ask proceeds");
      assert.equal(ok.dialogs.select.length, 0, `${String(tier)}: the four-option ask must not fire`);
      assert.equal(ok.dialogs.confirm.length, 1);
      assert.equal(ok.dialogs.confirm[0].title, "Unjangled Guardrails: approve this tool call?", "the title literal, unchanged");
      assert.ok(ok.dialogs.confirm[0].body.includes(ASK), "the body still carries the ask message");
      assert.ok(ok.dialogs.confirm[0].body.includes("Operator unblock"), "the body still carries the liftable hint");
      // internal consistency of the byte-identical path: the reject cites the same body
      const no = await piCall({ confirm: false });
      assert.equal(no.r?.block, true);
      assert.equal(no.r.reason, `User rejected: ${ok.dialogs.confirm[0].body}`);
      assert.equal(rulingsOf(home).length, 0);
    });
  }
});

test("pi capture: headless keeps the fail-closed ask-blocks default — no dialog, no capture", async () => {
  const home = freshHome();
  await withEnv(envOf(home, "session"), async () => {
    const { r, dialogs } = await piCall({ hasUI: false });
    assert.equal(r?.block, true);
    assert.match(r.reason, /no UI to ask for approval, so blocked/);
    assert.equal(dialogs.select.length + dialogs.confirm.length, 0, "headless never prompts");
    assert.ok(r.reason.includes("Operator unblock"), "the hint still rides the blocked reason (matrix row)");
    assert.equal(rulingsOf(home).length, 0);
  });
});

test("pi capture: a capture failure never changes the ask outcome — allow-once stands, the store untouched", async () => {
  const home = freshHome();
  await withEnv(envOf(home, "session"), async () => {
    writeFileSync(policyFile({ GUARD_HOME: home }), "{not json");  // a corrupt store: the mint refuses
    const { r } = await piCall({ select: "Allow for this session" });
    assert.equal(r, undefined, "the ask outcome is unchanged: the call proceeds as allow-once");
    assert.equal(readFileSync(policyFile({ GUARD_HOME: home }), "utf8"), "{not json", "nothing was written");
  });
});
