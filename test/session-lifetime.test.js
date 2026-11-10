// epic-prompt-rulings-session story 2 (R-2 cleanup half, the adapter legs): the harness
// adapters react to their session-end signals and expire the session's prompt-captured
// grants through the contract alone. pi: the session_shutdown event (reason "reload" is the
// one reason the SAME session continues — grants survive it; quit/new/resume/fork end the
// runtime — grants die). ACP: session/cancel is the v1 path the proxy sees — it resolves the
// proxy's pending permission asks for that session as cancelled (spec: cancelled =
// reject-once) AND expires the session's prompt-captured grants; the cancel itself still
// forwards to the agent untouched. Harness recipes per test/guard.test.js (the proxy + fake
// agent) and test/ask-band-surface.test.js (the pi extension handlers), fake brain included.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runProxy } from "../src/acp.js";
import { capturePromptRuling, listRulings } from "../src/rulings.js";

// The fake brain, the guard.test.js scoring recipe with the ask band keyed on git push (no
// standing entry covers it here): score 2.0 → ask. Everything else allows.
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

const tierEnv = (dir) => ({ JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_PROMPT_RULINGS: "session" });
const readEnv = (dir) => ({ JEV_API_KEY: "test", GUARD_HOME: dir });

test("pi session_shutdown: prompt-captured session grants die on session end; reason 'reload' keeps them", async () => {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-lifetime-pi-"));
  const savedHome = process.env.GUARD_HOME;  // the extension's cleanup reads process.env
  process.env.GUARD_HOME = dir;
  try {
    const { default: piExtension } = await import(new URL("../extensions/unjangled-guardrails.ts", import.meta.url));
    const handlers = {};
    piExtension({ on: (name, fn) => { handlers[name] = fn; } });
    const ctx = (sid) => ({ sessionManager: { getSessionId: () => sid, getBranch: () => [] }, ui: { notify: () => {} } });
    const mint = (cmd) => capturePromptRuling({ choice: "session", harness: "pi", sessionId: "pi-1", tool: "Bash", input: { command: cmd }, cwd: "/w" }, { env: tierEnv(dir) });
    mint("git push origin release");
    assert.equal(listRulings(readEnv(dir)).length, 1);
    // reload: the SAME session continues with fresh extension instances — the grant survives
    await handlers.session_shutdown({ reason: "reload" }, ctx("pi-1"));
    assert.equal(listRulings(readEnv(dir)).length, 1, "a /reload must not kill a live session's grants");
    // every reason that truly ends the session runtime: the grant dies with it
    for (const reason of ["quit", "new", "resume", "fork"]) {
      mint(`git push origin ${reason}`);
      await handlers.session_shutdown({ reason }, ctx("pi-1"));
      assert.equal(listRulings(readEnv(dir)).length, 0, reason);
    }
    const rows = readFileSync(join(dir, "rulings-use.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const cleans = rows.filter((r) => r.op === "expire-prompt-session");
    assert.equal(cleans.length, 4);                     // one row per effective cleanup, none for the reload
    assert.ok(cleans.every((r) => r.via === "session-end:pi"));
    // an ephemeral session (no id): nothing to clean, no crash — the 24h cap holds
    mint("git push origin ephemeral");
    await handlers.session_shutdown({ reason: "quit" }, ctx(undefined));
    assert.equal(listRulings(readEnv(dir)).length, 1);
  } finally {
    if (savedHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedHome;
  }
});

test("acp session/cancel: pending asks resolve cancelled and the session's prompt-captured grants die", async () => {
  // Fake agent: forwards what the test tells it to send, echoes what it receives back to the client.
  const agentScript = `
    const rl = require("node:readline").createInterface({ input: process.stdin });
    const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
    rl.on("line", (l) => { const m = JSON.parse(l);
      if (m.method === "test/send") send(m.params);
      else send({ jsonrpc: "2.0", method: "echo", params: m }); });
  `;
  const dir = mkdtempSync(join(tmpdir(), "unjangled-lifetime-acp-"));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // tamper-clean from birth: an init row older than every store write that follows
  writeFileSync(join(dir, "rulings-use.jsonl"), JSON.stringify({ at: new Date().toISOString(), action: "init", op: "init", via: "test" }) + "\n", { mode: 0o600 });
  // a prompt-captured session grant for the ACP session (the capture ask-options land in story 4)
  capturePromptRuling({ choice: "session", harness: "acp", sessionId: "acp-1", tool: "Bash", input: { command: "git push origin release" }, cwd: "/w" }, { env: tierEnv(dir) });
  assert.equal(listRulings(readEnv(dir)).length, 1);
  // session-store isolation (the memory half reads process.env): throwaway stores only
  const savedSessions = process.env.GUARD_SESSIONS;
  process.env.GUARD_SESSIONS = join(dir, "sessions");
  try {
    const stdin = new PassThrough(), stdout = new PassThrough();
    const seen = [];
    stdout.on("data", (d) => d.toString().split("\n").filter(Boolean).forEach((l) => seen.push(JSON.parse(l))));
    const child = runProxy(process.execPath, ["-e", agentScript], { stdin, stdout, env: { ...process.env, ...tierEnv(dir) }, fetchImpl, onExit: () => {} });
    const clientSend = (m) => stdin.write(JSON.stringify(m) + "\n");
    const until = (pred) => new Promise((res) => { const t = setInterval(() => { const m = seen.find(pred); if (m) { clearInterval(t); res(m); } }, 10); });

    // an ask mid-flight: the agent's terminal/create (a bare push, uncovered by any entry)
    // scores in the ask band; the proxy holds the permission request open
    clientSend({ jsonrpc: "2.0", method: "test/send", params: { jsonrpc: "2.0", id: 1, method: "terminal/create", params: { sessionId: "acp-1", command: "git", args: ["push", "origin", "hotfix"] } } });
    const perm = await until((m) => m.method === "session/request_permission");
    assert.equal(perm.params.sessionId, "acp-1");
    // the client cancels the session instead of answering the ask
    clientSend({ jsonrpc: "2.0", id: 50, method: "session/cancel", params: { sessionId: "acp-1" } });
    // the pending ask resolved cancelled → the terminal/create is rejected to the agent (cancelled = reject-once)
    const rejected = await until((m) => m.method === "echo" && m.params.id === 1);
    assert.match(rejected.params.error.message, /User rejected/);
    // the cancel request itself still forwarded to the agent, untouched — observed as the
    // fake agent's echo of it (a client never receives its own request back)
    await until((m) => m.method === "echo" && m.params?.method === "session/cancel" && m.params?.id === 50);
    // the store side: the session's prompt-captured grant died with the cancel, audit row naming the channel
    assert.equal(listRulings(readEnv(dir)).length, 0);
    const rows = readFileSync(join(dir, "rulings-use.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const cleans = rows.filter((r) => r.op === "expire-prompt-session");
    assert.equal(cleans.length, 1);
    assert.equal(cleans[0].via, "session-end:acp");
    assert.equal(cleans[0].id, "session:acp-1");
    // another session's grant is untouched by a cancel it did not name
    capturePromptRuling({ choice: "session", harness: "acp", sessionId: "acp-2", tool: "Bash", input: { command: "git push origin other" }, cwd: "/w" }, { env: tierEnv(dir) });
    clientSend({ jsonrpc: "2.0", id: 51, method: "session/cancel", params: { sessionId: "acp-1" } });
    await until((m) => m.method === "echo" && m.params?.method === "session/cancel" && m.params?.id === 51);
    await new Promise((r) => setTimeout(r, 50));  // let the cancel's cleanup leg run to completion
    assert.equal(listRulings(readEnv(dir)).length, 1);  // acp-2's grant survived acp-1's cancel
    child.kill();
  } finally {
    if (savedSessions === undefined) delete process.env.GUARD_SESSIONS; else process.env.GUARD_SESSIONS = savedSessions;
  }
});
