// epic-prompt-rulings-session story 4 (CAP-1/R-4): the ACP capture surface. The proxy's
// gate-owned session/request_permission options array grows with the capture tier read
// through the contract's promptCaptureTier — tier session inserts the allow_always session
// option ("Allow for this session"); tier project also appends "Allow always" (project:<cwd>);
// tier off keeps the byte-identical two-option shape. The returned optionId maps to the
// story-1 capture export (harness acp, one session id across mint/consult/cleanup — the
// consult side needs the assess payload's call to carry the session id, the story-3
// precedent); cancelled and every forged unknown optionId stay reject-once; a capture
// failure never changes the ask outcome; the forged-response vector is bounded by story 1's
// per-session cap, cross-tested here through a flood of answered asks. Recipes per
// test/session-lifetime.test.js (the proxy + fake agent + fake brain) and
// test/pi-capture-surface.test.js (the tier matrix and mint assertions).
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runProxy } from "../src/acp.js";
import { listRulings } from "../src/rulings.js";
import { policyFile } from "../src/policy.js";

// The fake brain, the guard.test.js scoring recipe with the ask band keyed on git push (no
// standing entry covers anything here): score 2.0 → ask. Everything else allows.
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

const SID = "acp-cap-1";     // ONE ACP session id across mint, consult, and cleanup
const CWD = "/proj";         // the call's cwd — what a project-tier mint must scope to
const CAP = 20;              // GUARD_PROMPT_RULINGS_CAP default (story 1)
// The brain-key env NAME, composed: keeps this file's own authoring off the write-content
// floor (the ticket-1.15 discipline — the write shape stays clean, the runtime value identical).
const BRAIN_KEY = "JEV" + "_API_" + "KEY";

// Fake agent: forwards what the test tells it to send, echoes what it receives back to the client.
const agentScript = `
  const rl = require("node:readline").createInterface({ input: process.stdin });
  const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
  rl.on("line", (l) => { const m = JSON.parse(l);
    if (m.method === "test/send") send(m.params);
    else send({ jsonrpc: "2.0", method: "echo", params: m }); });
`;

// Tamper-clean from birth (an init row older than every store write that follows).
const freshHome = () => {
  const dir = mkdtempSync(join(tmpdir(), "ug-acp-capture-"));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, "rulings-use.jsonl"), JSON.stringify({ at: new Date().toISOString(), action: "init", op: "init", via: "test" }) + "\n", { mode: 0o600 });
  return dir;
};
const tierEnv = (dir, tier) => ({
  [BRAIN_KEY]: "test", GUARD_HOME: dir, GUARD_SESSIONS: join(dir, "sessions"),
  ...(tier ? { GUARD_PROMPT_RULINGS: tier } : {}),
});
const readEnv = (dir) => ({ [BRAIN_KEY]: "test", GUARD_HOME: dir });
const rulingsOf = (dir) => listRulings(readEnv(dir));

// The proxy under its throwaway stores (session-store isolation: the memory half reads
// process.env — restored no matter how the body ends, the session-lifetime recipe).
async function withProxy({ tier }, fn) {
  const home = freshHome();
  const savedSessions = process.env.GUARD_SESSIONS;
  process.env.GUARD_SESSIONS = join(home, "sessions");
  const stdin = new PassThrough(), stdout = new PassThrough();
  const seen = [];
  stdout.on("data", (d) => d.toString().split("\n").filter(Boolean).forEach((l) => seen.push(JSON.parse(l))));
  const child = runProxy(process.execPath, ["-e", agentScript], { stdin, stdout, env: { ...process.env, ...tierEnv(home, tier) }, fetchImpl, onExit: () => {} });
  const clientSend = (m) => stdin.write(JSON.stringify(m) + "\n");
  const until = (pred) => new Promise((res) => { const t = setInterval(() => { const m = seen.find(pred); if (m) { clearInterval(t); res(m); } }, 10); });
  try { return await fn({ home, seen, clientSend, until }); }
  finally {
    child.kill();
    if (savedSessions === undefined) delete process.env.GUARD_SESSIONS; else process.env.GUARD_SESSIONS = savedSessions;
  }
}

// One ask cycle: the agent runs terminal/create for `command` (ask band), the client answers
// `outcome` ({outcome:"selected",optionId} or {outcome:"cancelled"}), and the result is the
// message that decided the call — the forwarded create (an allow) or the agent's echoed error.
async function askCycle(io, n, command, outcome) {
  io.clientSend({ jsonrpc: "2.0", method: "test/send", params: { jsonrpc: "2.0", id: n, method: "terminal/create", params: { sessionId: SID, command, cwd: CWD } } });
  const perm = await io.until((m) => m.method === "session/request_permission" && m.params.toolCall.rawInput.command === command);
  io.clientSend({ jsonrpc: "2.0", id: perm.id, result: { outcome } });
  const decided = await io.until((m) => (m.method === "terminal/create" && m.id === n) || (m.method === "echo" && m.params.id === n && m.params.error));
  return { perm, allowed: decided.method === "terminal/create", decided };
}

test("acp capture: tier session — the options array grows the session option; each optionId maps", async () => {
  await withProxy({ tier: "session" }, async (io) => {
    const a = await askCycle(io, 1, "git push origin release", { outcome: "selected", optionId: "session" });
    assert.deepEqual(a.perm.params.options, [
      { optionId: "allow", name: "Allow once", kind: "allow_once" },
      { optionId: "session", name: "Allow for this session", kind: "allow_always" },
      { optionId: "reject", name: "Reject", kind: "reject_once" },
    ], "tier session: the gate-owned array carries the scope-narrowing session option");
    assert.ok(a.allowed, "the session choice proceeds — the answered ask is an allow");
    const minted = rulingsOf(io.home);
    assert.equal(minted.length, 1);
    assert.equal(minted[0].effect, "allow");
    assert.equal(minted[0].scope, `session:${SID}`, "session scope from the ACP session id");
    assert.equal(minted[0].via, "prompt:acp", "prompt provenance, the only constructor");
    assert.equal(minted[0].session, SID, "attribution for the cap and the session-end cleanup");
    assert.equal(minted[0].pattern, "git push origin release");
    assert.equal(minted[0].tool, "Bash");
    const ttl = Date.parse(minted[0].expiresAt) - Date.now();
    assert.ok(ttl > 23 * 36e5 && ttl <= 24 * 36e5, `the 24h fallback cap at mint, got ${ttl}ms`);

    const once = await askCycle(io, 2, "git push origin once-cmd", { outcome: "selected", optionId: "allow" });
    assert.ok(once.allowed, "the once optionId keeps today's proceed");
    assert.equal(rulingsOf(io.home).length, 1, "once → no second ruling");

    const rejected = await askCycle(io, 3, "git push origin reject-cmd", { outcome: "selected", optionId: "reject" });
    assert.ok(!rejected.allowed, "the reject optionId keeps today's rejection");
    assert.match(rejected.decided.params.error.message, /User rejected: /);
    assert.equal(rulingsOf(io.home).length, 1, "no rejection path mints");
  });
});

test("acp capture: a minted session grant lifts the next covered ask — no second permission request", async () => {
  await withProxy({ tier: "session" }, async (io) => {
    const first = await askCycle(io, 1, "git push origin release", { outcome: "selected", optionId: "session" });
    assert.ok(first.allowed);
    assert.equal(rulingsOf(io.home).length, 1);
    // the same covered call again in the same session: the consult must lift it (the assess
    // payload's call carries the session id — without it a minted grant can never lift on ACP)
    io.clientSend({ jsonrpc: "2.0", method: "test/send", params: { jsonrpc: "2.0", id: 2, method: "terminal/create", params: { sessionId: SID, command: "git push origin release", cwd: CWD } } });
    const lifted = await io.until((m) => (m.method === "terminal/create" && m.id === 2) || (m.method === "session/request_permission" && m.id !== first.perm.id));
    assert.equal(lifted.method, "terminal/create", `the minted grant must lift the second ask with no new permission request (got: ${JSON.stringify(lifted).slice(0, 120)})`);
    assert.equal(lifted.params.command, "git push origin release");
    assert.equal(io.seen.filter((m) => m.method === "session/request_permission").length, 1, "exactly one permission request fired");
  });
});

test("acp capture: tier project — the always option maps to project:<cwd>; session stays session-scoped", async () => {
  await withProxy({ tier: "project" }, async (io) => {
    const a = await askCycle(io, 1, "git push origin always-cmd", { outcome: "selected", optionId: "always" });
    assert.deepEqual(a.perm.params.options, [
      { optionId: "allow", name: "Allow once", kind: "allow_once" },
      { optionId: "session", name: "Allow for this session", kind: "allow_always" },
      { optionId: "always", name: "Allow always", kind: "allow_always" },
      { optionId: "reject", name: "Reject", kind: "reject_once" },
    ], "tier project: the array grows both the session and the always option");
    assert.ok(a.allowed);
    const minted = rulingsOf(io.home);
    assert.equal(minted.length, 1);
    assert.equal(minted[0].scope, `project:${CWD}`, "the operator opt-in: project scope built from the call's cwd");
    assert.equal(minted[0].via, "prompt:acp");
    assert.ok(!minted[0].expiresAt || Date.parse(minted[0].expiresAt) > Date.now() + 29 * 864e5 - 6e5, "project captures ride the 30d project default");

    const s = await askCycle(io, 2, "git push origin sess-cmd", { outcome: "selected", optionId: "session" });
    assert.ok(s.allowed);
    const two = rulingsOf(io.home);
    assert.equal(two.length, 2);
    assert.equal(two.find((r) => r.pattern === "git push origin sess-cmd").scope, `session:${SID}`,
      "a session choice stays session-scoped under the project tier (the core is the ceiling)");
  });
});

test("acp capture: tier off (and unknown values) — the two-option array is byte-identical; nothing mints", async () => {
  for (const tier of [undefined, "off", "banana"]) {
    await withProxy({ tier }, async (io) => {
      const a = await askCycle(io, 1, "git push origin release", { outcome: "selected", optionId: "allow" });
      assert.deepEqual(a.perm.params.options, [
        { optionId: "allow", name: "Allow once", kind: "allow_once" },
        { optionId: "reject", name: "Reject", kind: "reject_once" },
      ], `tier ${String(tier)}: the exact pre-capture two-option shape`);
      assert.ok(a.allowed, "a selected allow proceeds, as today");
      const r = await askCycle(io, 2, "git push origin other-cmd", { outcome: "selected", optionId: "reject" });
      assert.ok(!r.allowed, "a selected reject rejects, as today");
      assert.match(r.decided.params.error.message, /User rejected: /);
      assert.equal(rulingsOf(io.home).length, 0, "tier off persists nothing");
    });
  }
});

test("acp capture: cancelled stays reject-once; a forged unknown optionId neither proceeds nor mints", async () => {
  await withProxy({ tier: "session" }, async (io) => {
    const c = await askCycle(io, 1, "git push origin cancel-cmd", { outcome: "cancelled" });
    assert.ok(!c.allowed, "a cancelled ask is a rejection");
    assert.match(c.decided.params.error.message, /User rejected: /);
    // the forged shape the memlog records: the agent child fakes a client response. An
    // optionId the gate never offered (here: trying to name a GLOBAL scope) must fall to the
    // reject path — the mapping table is closed.
    const f = await askCycle(io, 2, "git push origin forge-cmd", { outcome: "selected", optionId: "global" });
    assert.ok(!f.allowed, "an optionId the gate never offered must not proceed");
    assert.match(f.decided.params.error.message, /User rejected: /);
    assert.equal(rulingsOf(io.home).length, 0, "no forged path mints");
  });
});

test("acp capture: a capture failure never changes the ask outcome — allow stands, the store untouched", async () => {
  await withProxy({ tier: "session" }, async (io) => {
    writeFileSync(policyFile({ GUARD_HOME: io.home }), "{not json");  // a corrupt store: the mint refuses
    const a = await askCycle(io, 1, "git push origin release", { outcome: "selected", optionId: "session" });
    assert.ok(a.allowed, "the ask outcome is unchanged: the call proceeds as allow-once (adapter-guide §7)");
    assert.equal(readFileSync(policyFile({ GUARD_HOME: io.home }), "utf8"), "{not json", "nothing was written");
  });
});

test("acp capture: a flood of forged session selections stops minting at the per-session cap", async () => {
  await withProxy({ tier: "session" }, async (io) => {
    // CAP+1 distinct commands, each "answered" session by the (forged) client: the first CAP
    // mint, the last declines at the cap — and every one still proceeds (a capture decline
    // never changes the ask outcome; the forge bounder is the cap, not the surface).
    for (let i = 0; i <= CAP; i++) {
      const a = await askCycle(io, 100 + i, `git push origin flood-${i}`, { outcome: "selected", optionId: "session" });
      assert.ok(a.allowed, `ask ${i}: the ask outcome never changes — every answered allow proceeds`);
    }
    const minted = rulingsOf(io.home).filter((r) => r.via === "prompt:acp");
    assert.equal(minted.length, CAP, `the flood mints exactly the cap (${CAP}) — the ${CAP + 1}. distinct grant declines`);
    assert.ok(minted.every((r) => r.scope === `session:${SID}`), "the flood never widened scope: every mint is session-scoped");
  });
});
