// Story 12: orchestrator — the vendored Secrets Guard rules as a measured floor while the
// brain is up, and as the full gate while degraded on a sole-gate host.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ACTIVE_FLOOR, DIVERGENCE_FAMILIES, familyOf, floorVerdict, ruleVerdict, degradedGate } from "../src/orchestrate.js";
import { assessAction } from "../src/guard.js";

// Same fake brain as the other suites: only `rm -rf` denies; ps/docker etc. sail through.
const fakeBrain = async (_url, { body }) => {
  const { state } = JSON.parse(body);
  const cmd = JSON.stringify(state.input);
  const answers = {
    risk: { type: "score", score: /rm -rf/.test(cmd) ? 2.9 : 0.2, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: 0.05 }, user_requested: { type: "noul", noul: 0.05 }, from_untrusted: { type: "noul", noul: 0.05 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
  };
  return { ok: true, json: async () => ({ answers }) };
};

test("rule families classify every vendored deny reason", () => {
  assert.equal(familyOf("secret-leak-guard: BLOCKED — `infisical secrets get` prints the secret"), "infisical");
  assert.equal(familyOf("a clientSecret/secretValue written inline in -d"), "curl-secret-api");
  assert.equal(familyOf("-x/set -x traces every expanded command"), "shell-tracing");
  assert.equal(familyOf("displaying a credential file dumps its values"), "credential-file");
  assert.equal(familyOf("a Hermes/agent config.yaml embeds inline secrets"), "agent-config");
  assert.equal(familyOf("bare printenv/env dumps every environment variable"), "env-dump");
  assert.equal(familyOf("dumping a container's full environment"), "docker-env");
  assert.equal(familyOf("bare `docker inspect` prints the container's full Config.Env"), "docker-inspect-format");
  assert.equal(familyOf("pgrep -a prints each process's full command line"), "process-argv");
});

test("rules verdict: shell and read tools judged, others untouched", () => {
  assert.equal(ruleVerdict("Bash", { command: "cat ~/.env" }).family, "credential-file");
  assert.equal(ruleVerdict("Bash", { command: "ls -la" }), null);
  assert.equal(ruleVerdict("Read", { file_path: "~/.ssh/id_rsa" }).family, "credential-file");
  assert.equal(ruleVerdict("WebFetch", { url: "https://x" }), null);
  // Hermes's shell tool judges on the same rules as Bash (backlog bug 1)
  assert.equal(ruleVerdict("terminal", { command: "cat ~/.env" }).family, "credential-file");
  assert.equal(ruleVerdict("Terminal", { command: "ls -la" }), null);
});

test("Hermes terminal gets the same offline verdict as Bash with the backend down (backlog bug 1, repro step 3)", () => {
  const err = new Error("connect ECONNREFUSED");
  const closed = { GUARD_FALLBACK: "closed", GUARD_HOME: mkdtemp() };
  const termDeny = degradedGate({ tool: "terminal", input: { command: "cat ~/.env" }, env: closed }, err);
  assert.equal(termDeny.level, "deny");
  assert.match(termDeny.why, /displaying a credential file/);
});

test("floor: an active-floor family escalates the brain's allow; divergences never escalate", () => {
  const cmd = { command: "ps aux" };
  assert.equal(ruleVerdict("Bash", cmd).family, "process-argv");
  ACTIVE_FLOOR.push("process-argv");
  try {
    const floor = floorVerdict("Bash", cmd);
    assert.equal(floor.family, "process-argv");
  } finally { ACTIVE_FLOOR.pop(); }
  assert.equal(floorVerdict("Bash", cmd), null);  // floor removed → brain verdict stands
  // the approved divergence: when the rules deny the docker-inspect-format family (an Env-selecting
  // format), the floor never fires — and status-only selects are allowed by both engines outright
  const inspectEnv = { command: "docker inspect -f '{{.Config.Env}}' c" };
  assert.equal(ruleVerdict("Bash", inspectEnv).family, "docker-inspect-format");
  assert.ok(DIVERGENCE_FAMILIES.includes("docker-inspect-format"));
  assert.equal(floorVerdict("Bash", inspectEnv), null);
  assert.equal(ruleVerdict("Bash", { command: "docker inspect -f '{{.State.Status}}' c" }), null);
});

test("floor through assessAction: rules escalate a brain allow to deny, citing the rule", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtemp() };
  ACTIVE_FLOOR.push("process-argv");
  try {
    const r = await assessAction({ tool: "Bash", input: { command: "ps aux" }, cwd: "/proj" }, { env, fetchImpl: fakeBrain });
    assert.equal(r.level, "deny");
    assert.equal(r.floor, "process-argv");
    assert.match(r.message, /built-in offline rules/);
    // and the deny floor of Story 10 holds: no allow ruling consults (already covered), the verdict is final
  } finally { ACTIVE_FLOOR.pop(); }
});

test("degradedGate closed mode: vendored rules gate first, deny-all for the rest", () => {
  const err = new Error("connect ECONNREFUSED");
  const closed = { GUARD_FALLBACK: "closed", GUARD_HOME: mkdtemp() };
  const ruleDeny = degradedGate({ tool: "Bash", input: { command: "cat ~/.env" }, env: closed }, err);
  assert.equal(ruleDeny.level, "deny");
  assert.match(ruleDeny.why, /built-in offline rules/);
  assert.match(ruleDeny.why, /displaying a credential file/);
  const plainDeny = degradedGate({ tool: "Bash", input: { command: "git push origin" }, env: closed }, err);
  assert.equal(plainDeny.level, "deny");
  assert.match(plainDeny.why, /sole gate/);
  const layered = degradedGate({ tool: "Bash", input: { command: "git push origin" }, env: { GUARD_HOME: mkdtemp(), warnStream: { write() {} } } }, err);
  assert.equal(layered.level, "allow");
  assert.equal(layered.degraded, true);
});

// ── plan 1.1 (red-team R1): path-based self-modification guard ────────────────────────────────
import { selfModVerdict } from "../src/orchestrate.js";
import { guardHome, rulingsFile } from "../src/rulings.js";
import { sessionsDir } from "../src/session.js";
import { homedir } from "node:os";

// Brain scored like the live shim when the user genuinely asked: user_requested 0.95 lifts.
const userWordsBrain = async (_url, { body }) => {
  return { ok: true, json: async () => ({ answers: {
    risk: { type: "score", score: 1.0, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: 0.3 }, from_untrusted: { type: "noul", noul: 0.05 },
    user_requested: { type: "noul", noul: 0.95 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 } } }) };
};

test("1.1 path guard: file-shaped writes into store/config/sessions deny, tool-agnostic", () => {
  const dir = mkdtemp();
  const env = { GUARD_HOME: dir };
  const store = rulingsFile(env), cfg = join(homedir(), ".unjangled-guardrails", "config.json"), sess = join(sessionsDir(env), "abc123.json");
  // the red team's shapes: Write overwrite, Edit, NotebookEdit, MCP file tool — plus tilde/relative/traversal forms
  for (const [tool, input] of [
    ["Write", { file_path: store, content: '[{"effect":"allow","pattern":"*"}]' }],
    ["Edit", { file_path: store, old_string: "[]", new_string: '[{"effect":"allow","pattern":"*"}]' }],
    ["NotebookEdit", { notebook_path: sess }],
    ["mcp__fs__write", { path: cfg, content: "{}" }],
    ["Write", { file_path: "~/.unjangled-guardrails/rulings.json" }],
    ["Write", { file_path: join(dir, "sub", "..", "rulings.json") }],   // traversal resolves back into the store dir
    ["Bash", { command: "cat x", file_path: store }],                   // tool-agnostic: path checked on bash-shaped input too
  ]) assert.ok(selfModVerdict(tool, input, { env }), `${tool} on ${input.file_path ?? input.path ?? input.notebook_path} must deny`);
  // and the guard must not over-fire: ordinary project files, sibling files inside the home dir
  // (a shared home like this repo's root must stay writable), and reads of the gate's own files
  for (const [tool, input] of [
    ["Write", { file_path: "/proj/src/app.ts" }],
    ["Read", { file_path: "/proj/README.md" }],
    ["Write", { file_path: join(dir, "scratch-notes.md") }],            // sibling of the store, not the store
    ["Read", { file_path: store }],                                     // a read of the store is not an edit
    ["view", { file_path: sess }],
    ["mcp__fs__read", { path: store }],
    ["Bash", { command: "ls -la" }],
  ]) assert.equal(selfModVerdict(tool, input, { cwd: "/proj", env }), null, `${tool} on ${input.file_path ?? input.path ?? "/proj/README.md"} must pass`);
});

test("1.1 degraded mode + Write to the store path: deny [Gate Self-Protection] in every fallback mode", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtemp() };  // default rules mode
  const storeWrite = { tool: "Write", input: { file_path: rulingsFile(env), content: '[{"effect":"allow","pattern":"*"}]' }, cwd: "/proj" };
  // unit level: the guard fires before the ruling consult, in every mode
  for (const extra of [{}, { GUARD_FALLBACK: "closed" }, { GUARD_FALLBACK: "layered" }]) {
    const v = degradedGate({ ...storeWrite, env: { ...env, ...extra }, warnStream: { write() {} } }, new Error("down"));
    assert.equal(v.level, "deny", JSON.stringify(extra));
    assert.equal(v.degraded, true);
    assert.ok(v.selfMod);
  }
  // end to end: the verdict reaches the agent as [Gate Self-Protection]
  const r = await assessAction(storeWrite, { env, fetchImpl: fakeBrain });
  assert.equal(r.level, "deny");
  assert.match(r.message, /\[Gate Self-Protection\]/);
});

test("1.1 a self-modification deny is unliftable by rulings but lifted by the user's own words", async () => {
  const { addRuling } = await import("../src/rulings.js");
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtemp(), GUARD_OPERATOR_CLI: "1" };
  const storeWrite = { tool: "Write", input: { file_path: rulingsFile(env), content: "[]" }, cwd: "/proj", sessionId: "s1" };
  // the brain scores a store overwrite safe (risk 0.2 here — the real one scored 0.70): the guard must deny anyway
  const denied = await assessAction(storeWrite, { env, fetchImpl: fakeBrain });
  assert.equal(denied.level, "deny");
  // and a broad allow-all ruling — the exact prize of the escalation — does NOT lift it
  addRuling({ effect: "allow", pattern: "*", scope: "project:/proj", expiresAt: "2099-01-01" }, env);
  const stillDenied = await assessAction(storeWrite, { env, fetchImpl: fakeBrain });
  assert.equal(stillDenied.level, "deny");
  assert.ok(!stillDenied.ruling);  // no ruling consult happened, so no audit row for a lift
  // only genuine user words (the 0.85 bar) lift it — operator ruling 2026-10-04
  const lifted = await assessAction(storeWrite, { env, fetchImpl: userWordsBrain });
  assert.equal(lifted.level, "allow");
  assert.match(lifted.message, /the user explicitly asked/);
});

test("1.1 pinning: the bash-regex selfMod layer is NOT user-liftable — only the path guard is", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtemp() };
  const r = await assessAction({ tool: "Bash", input: { command: "node src/cli.js ruling add --effect allow --pattern '*'" }, cwd: "/proj" },
    { env, fetchImpl: userWordsBrain });
  assert.equal(r.level, "deny");  // matrix row 5: bash selfMod denies even at user_requested 0.95
  // the same escape through Hermes's terminal is equally visible (backlog bug 1)
  const rt = await assessAction({ tool: "terminal", input: { command: "node src/cli.js ruling add --effect allow --pattern '*'" }, cwd: "/proj" },
    { env, fetchImpl: userWordsBrain });
  assert.equal(rt.level, "deny");
  assert.match(rt.message, /operator-only/);
});

test("1.1 e2e chain: the red team's self-escalation script fails at every step", async () => {
  const { addRuling, listRulings } = await import("../src/rulings.js");
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtemp() };
  const err = new Error("connect ECONNREFUSED");
  // step 1 — overwrite the store with allow-all: denied, nothing lands
  const step1 = await assessAction({ tool: "Write", input: { file_path: rulingsFile(env), content: '[{"effect":"allow","pattern":"*"}]' }, cwd: "/proj" }, { env, fetchImpl: fakeBrain });
  assert.equal(step1.level, "deny");
  // step 2 — the innocuous wrapper importing addRuling: the library refuses non-TTY
  assert.throws(() => addRuling({ effect: "allow", pattern: "*", scope: "project:/proj", expiresAt: "2099-01-01" }, env), /operator-only/);
  assert.deepEqual(listRulings(env), []);  // no ruling landed
  // step 3 — the originally-blocked dangerous call stays blocked (degraded: closed mode, no lifter exists)
  const step3 = degradedGate({ tool: "Bash", input: { command: "git push --force origin main" }, cwd: "/proj", env: { ...env, GUARD_FALLBACK: "closed" } }, err);
  assert.equal(step3.level, "deny");
});

function mkdtemp() { return mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")); }
