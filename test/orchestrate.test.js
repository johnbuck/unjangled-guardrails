// The Always-Deny layer's unit pins (consolidation 2026-10-20; formerly the orchestrator's
// rule/floor/degraded pins — Story 12). The active-floor escalation and the divergence
// carve-outs died with the skip stack: the vendored rules are layer 1 now, absolute, and the
// closed/layered postures resolve only what Always-Deny did not claim.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { alwaysDeny, familyOf, selfModVerdict } from "../src/always-deny.js";
import { degradedVerdict, fallbackMode, failClosed } from "../src/orchestrate.js";
import { assessAction } from "../src/guard.js";
import { guardHome, rulingsFile } from "../src/rulings.js";
import { sessionsDir } from "../src/session.js";
import { homedir } from "node:os";

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

test("the vendored rules judge shell and read tools at layer 1; others pass through", () => {
  // the operand leg (credential-source) precedes the checkBash cat-family leg — the old
  // assessAction had the same precedence (the floor ran before the brain, the rules after)
  assert.equal(alwaysDeny("Bash", { command: "cat ~/.env" }, {}).floor, "credential-source");
  assert.equal(alwaysDeny("Bash", { command: "printenv" }, {}).floor, "env-dump");
  assert.equal(alwaysDeny("Bash", { command: "ls -la" }, {}), null);
  assert.equal(alwaysDeny("Read", { file_path: "~/.ssh/id_rsa" }, {}).floor, "credential-file");
  assert.equal(alwaysDeny("WebFetch", { url: "https://x" }, {}), null);
  // Hermes's shell tool judges on the same rules as Bash (backlog bug 1)
  assert.equal(alwaysDeny("terminal", { command: "cat ~/.env" }, {}).floor, "credential-source");
  assert.equal(alwaysDeny("Terminal", { command: "ls -la" }, {}), null);
});

test("a credential-shaped command denies with the backend down (no brain round-trip, any posture)", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")) };
  const dead = async () => { throw new Error("connect ECONNREFUSED"); };
  for (const extra of [{}, { GUARD_FALLBACK: "closed" }, { GUARD_FALLBACK: "layered" }]) {
    const r = await assessAction({ tool: "terminal", input: { command: "printenv" }, cwd: "/proj" },
      { env: { ...env, ...extra }, fetchImpl: dead });
    assert.equal(r.level, "deny", JSON.stringify(extra));
    assert.equal(r.floor, "env-dump");
    assert.match(r.message, /leak-guard rule: environment dump/);  // plain rule parens (message registry 2026-10-25)
  }
});

test("layer 1 denies what the active floor used to escalate; the divergence carve-out is gone", async () => {
  const cmd = { command: "ps aux" };
  assert.equal(alwaysDeny("Bash", cmd, {}).floor, "process-argv");
  // the formerly-approved divergence (an Env-selecting docker inspect) is now a plain
  // Always-Deny; the status-only select passes both engines outright
  assert.equal(alwaysDeny("Bash", { command: "docker inspect -f '{{.Config.Env}}' c" }, {}).floor, "docker-inspect-format");
  assert.equal(alwaysDeny("Bash", { command: "docker inspect -f '{{.State.Status}}' c" }, {}), null);
});

test("through assessAction: the vendored rules deny a brain allow, citing the rule", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")) };
  const r = await assessAction({ tool: "Bash", input: { command: "ps aux" }, cwd: "/proj" }, { env, fetchImpl: fakeBrain });
  assert.equal(r.level, "deny");
  assert.equal(r.floor, "process-argv");
  assert.match(r.message, /leak-guard rule: process argv/);
  assert.equal(r.risk, undefined, "no brain verdict rides an Always-Deny deny");
});

test("degraded: closed mode deny-all, layered defers, and the policy option hardens the default", () => {
  const err = new Error("connect ECONNREFUSED");
  const quiet = { write() {} };
  const closed = { GUARD_FALLBACK: "closed", GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")) };
  const plainDeny = degradedVerdict({ tool: "Bash", input: { command: "git push origin" }, env: closed, warnStream: quiet }, err);
  assert.equal(plainDeny.level, "deny");
  assert.match(plainDeny.why, /sole gate/);
  const layered = degradedVerdict({ tool: "Bash", input: { command: "git push origin" }, env: { GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")), warnStream: quiet } }, err);
  assert.equal(layered.level, "allow");
  assert.equal(layered.degraded, true);
  // the policy option (degradation: fail-closed) hardens the default rules posture
  const policyClosed = { GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")), warnStream: quiet };
  mkdirSync(policyClosed.GUARD_HOME, { recursive: true });
  writeFileSync(join(policyClosed.GUARD_HOME, "user-policy.json"), JSON.stringify({ version: 1, entries: [], degradation: "fail-closed" }));
  const hardened = degradedVerdict({ tool: "Bash", input: { command: "git push origin" }, env: policyClosed, warnStream: quiet }, err);
  assert.equal(hardened.level, "deny");
  assert.match(hardened.why, /fail-closed/);
  // and the env surface still wins over the policy option
  const envWins = degradedVerdict({ tool: "Bash", input: { command: "git push origin" }, env: { ...policyClosed, GUARD_FALLBACK: "layered" }, warnStream: quiet }, err);
  assert.equal(envWins.level, "allow");
  assert.equal(fallbackMode({ GUARD_FALLBACK: "closed" }), "closed");
  assert.equal(failClosed({ GUARD_FAIL_CLOSED: "1" }), true);
});

// ── plan 1.1 (red-team R1): path-based self-modification guard (now layer 1, absolute) ─────────
// Stub scored like the live brain when the user genuinely asked: user_requested 0.95 lifts.
const userWordsBrain = async (_url, { body }) => {
  return { ok: true, json: async () => ({ answers: {
    risk: { type: "score", score: 1.0, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: 0.3 }, from_untrusted: { type: "noul", noul: 0.05 },
    user_requested: { type: "noul", noul: 0.95 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 } } }) };
};

test("1.1 path guard: file-shaped writes into store/config/sessions deny, tool-agnostic", () => {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-"));
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
    // the 2026-11-09 read split (GHI-10, CAP-1): the policy store is operator-private — a
    // read-shaped tool over the STORE file denies as private-store access (superseding the
    // 1.1-era "a read of the store is not an edit" carve for the store files only)
    ["Read", { file_path: store }],
    ["mcp__fs__read", { path: store }],
  ]) assert.ok(selfModVerdict(tool, input, { env }), `${tool} on ${input.file_path ?? input.path ?? input.notebook_path} must deny`);
  // and the guard must not over-fire: ordinary project files, sibling files inside the home dir
  // (a shared home like this repo's root must stay writable), and session reads (the user's own
  // words — the read split keeps them free on every plane)
  for (const [tool, input] of [
    ["Write", { file_path: "/proj/src/app.ts" }],
    ["Read", { file_path: "/proj/README.md" }],
    ["Write", { file_path: join(dir, "scratch-notes.md") }],            // sibling of the store, not the store
    ["view", { file_path: sess }],
    ["Bash", { command: "ls -la" }],
  ]) assert.equal(selfModVerdict(tool, input, { cwd: "/proj", env }), null, `${tool} on ${input.file_path ?? input.path ?? "/proj/README.md"} must pass`);
});

test("a Write to the store path denies [Gate Self-Protection] in every posture — now pre-brain", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")) };
  const storeWrite = { tool: "Write", input: { file_path: rulingsFile(env), content: '[{"effect":"allow","pattern":"*"}]' }, cwd: "/proj" };
  for (const extra of [{}, { GUARD_FALLBACK: "closed" }, { GUARD_FALLBACK: "layered" }]) {
    const r = await assessAction(storeWrite, { env: { ...env, ...extra }, fetchImpl: fakeBrain });
    assert.equal(r.level, "deny", JSON.stringify(extra));
    assert.equal(r.category, "Gate Self-Protection");
  }
  // the old degradedGate row's shape: even a dead brain changes nothing (Always-Deny ran first)
  const r = await assessAction(storeWrite, { env, fetchImpl: async () => { throw new Error("down"); } });
  assert.equal(r.level, "deny");
  assert.match(r.message, /\[Gate Self-Protection\]/);
});

test("1.1 consolidation: a self-modification deny is absolute — no ruling, and no longer even user words", async () => {
  const { addRuling } = await import("../src/rulings.js");
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")), GUARD_OPERATOR_CLI: "1" };
  const storeWrite = { tool: "Write", input: { file_path: rulingsFile(env), content: "[]" }, cwd: "/proj", sessionId: "s1" };
  // the brain scores a store overwrite safe (risk 0.2 here — the real one scored 0.70): the guard must deny anyway
  const denied = await assessAction(storeWrite, { env, fetchImpl: fakeBrain });
  assert.equal(denied.level, "deny");
  // a broad allow-all ruling — the exact prize of the escalation — does NOT lift it
  addRuling({ effect: "allow", pattern: "*", scope: "project:/proj", expiresAt: "2099-01-01" }, env);
  const stillDenied = await assessAction(storeWrite, { env, fetchImpl: fakeBrain });
  assert.equal(stillDenied.level, "deny");
  assert.ok(!stillDenied.ruling);  // no ruling consult happened, so no audit row for a lift
  // CONSOLIDATION TIGHTENING (the plan's frozen intent: "No brain, no lane pass, no ruling
  // consult can lift it — self-mod precedent"): the user-words lift on the path branch is
  // gone with the brain-derived verdicts. Genuine user words at the 0.75 bar no longer lift.
  const lifted = await assessAction(storeWrite, { env, fetchImpl: userWordsBrain });
  assert.equal(lifted.level, "deny");
  assert.match(lifted.message, /only the operator changes it/);  // Gate Self-Protection family text (message registry 2026-10-25)
});

test("1.1 pinning: the bash-regex selfMod layer is NOT user-liftable (unchanged by the consolidation)", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")) };
  const r = await assessAction({ tool: "Bash", input: { command: "node src/cli.js ruling add --effect allow --pattern '*'" }, cwd: "/proj" },
    { env, fetchImpl: userWordsBrain });
  assert.equal(r.level, "deny");  // matrix row 5: bash selfMod denies even at user_requested 0.95
  // every mutation alias is covered, degradation posture changes included
  for (const cmd of ["node src/cli.js policy add --tool x", "node src/cli.js lane add --tool x",
    "node src/cli.js policy set --degradation fail-open", "node src/cli.js policy adopt-defaults"]) {
    const m = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: "/proj" }, { env, fetchImpl: userWordsBrain });
    assert.equal(m.level, "deny", cmd);
    assert.equal(m.category, "Gate Self-Protection", cmd);
  }
  // the same escape through Hermes's terminal is equally visible (backlog bug 1)
  const rt = await assessAction({ tool: "terminal", input: { command: "node src/cli.js ruling add --effect allow --pattern '*'" }, cwd: "/proj" },
    { env, fetchImpl: userWordsBrain });
  assert.equal(rt.level, "deny");
  assert.match(rt.message, /only the operator changes it/);
});

test("2026-10-17: bash-content writes into gate source are operator-only — reads and dev tools stay free", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")) };
  const deny = async (command) => assessAction({ tool: "Bash", input: { command }, cwd: "/proj" }, { env, fetchImpl: userWordsBrain });
  // the finding's exact shape: a python one-liner rewriting gate source — denies even with
  // user words in context (chat-blind family, matrix row 5 precedent)
  const finding = await deny(`python3 -c " s = open('src/guard.js').read(); s = s.replace('a','b'); open('src/guard.js','w').write(s)"`);
  assert.equal(finding.level, "deny");  // userWordsBrain answers user_requested 0.95 — the deny holds anyway: chat-blind family
  assert.match(finding.why, /writes the gate's own source/);   // structured why carries the rule's message
  assert.match(finding.message, /only the operator changes it/);  // the surfaced guidance routes to the operator terminal
  // the other write verbs
  assert.equal((await deny(`sed -i 's/a/b/' src/guard.js`)).level, "deny");
  assert.equal((await deny(`echo 'x' > src/orchestrate.js`)).level, "deny");
  assert.equal((await deny(`cp patch.js src/guard.js`)).level, "deny");
  assert.equal((await deny(`node -e "require('fs').writeFileSync('src/jev.js','x')"`)).level, "deny");
  // reads stay free — the corpus's audit shapes must not move
  for (const ok of ["grep -n brain test/ask-band-surface.test.js", "sed -n 1,60p src/guard.js", "cat src/guard.js | wc -l",
    "grep -rn SYSTEMONE_URL src/ | head -3", "node --test test/", "cp src/guard.js /tmp/backup.js", "cat src/guard.js > /tmp/inspect.txt"]) {
    const r = await deny(ok);
    assert.notEqual(r.level, "deny", `read shape must not deny: ${ok}`);
  }
});

test("1.1 e2e chain: the red team's self-escalation script fails at every step", async () => {
  const { addRuling, listRulings } = await import("../src/rulings.js");
  const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")) };
  // step 1 — overwrite the store with allow-all: denied, nothing lands
  const step1 = await assessAction({ tool: "Write", input: { file_path: rulingsFile(env), content: '[{"effect":"allow","pattern":"*"}]' }, cwd: "/proj" }, { env, fetchImpl: fakeBrain });
  assert.equal(step1.level, "deny");
  // step 2 — the innocuous wrapper importing addRuling: the library refuses non-TTY
  assert.throws(() => addRuling({ effect: "allow", pattern: "*", scope: "project:/proj", expiresAt: "2099-01-01" }, env), /operator-only/);
  assert.deepEqual(listRulings(env), []);  // no ruling landed
  // step 3 — the originally-blocked dangerous call stays blocked (degraded: closed mode, no lifter exists)
  const step3 = degradedVerdict({ tool: "Bash", input: { command: "git push --force origin main" }, cwd: "/proj", env: { ...env, GUARD_FALLBACK: "closed" }, warnStream: { write() {} } }, new Error("connect ECONNREFUSED"));
  assert.equal(step3.level, "deny");
});

// ── posture-triage 5.3 M8: the shell-family routing is anchored ────────────────────────────────

test("5.3 M8: real shell-tool names still route to the bash rules; sh-containing names do not", () => {
  // every real shell-shaped tool name keeps routing (the fix preserves these matches)
  for (const tool of ["Bash", "SHELL", "sh", "zsh", "run_shell_command", "terminal", "Terminal"])
    assert.equal(alwaysDeny(tool, { command: "printenv" }, {}).floor, "env-dump", tool);
  // a tool name that merely CONTAINS "sh" no longer routes — "fish" and "marshmallow" both
  // matched the old unanchored /…|sh/ and took the bash rules' denies
  for (const tool of ["fish", "fishd", "marshmallow", "shellfish"])
    assert.equal(alwaysDeny(tool, { command: "cat ~/.env" }, {}), null, tool);
});

// Guard-config read plane (fleet incident 2026-10-16): the gate's own backend config holds the
// brain credential — a Read of it would print the key into context.
test("guard-config read plane: a Read of the gate's own config denies as credential-file; ordinary reads pass", () => {
  const v = alwaysDeny("Read", { file_path: "~/.unjangled-guardrails/config.json" }, {});
  assert.equal(v.family, "secrets");
  assert.equal(v.floor, "credential-file");
  assert.match(v.reason, /credential/);
  assert.equal(alwaysDeny("read_file", { file_path: "/root/.jev-guard/config.json" }, {}).floor, "credential-file");
  assert.equal(alwaysDeny("Read", { file_path: "/proj/src/app.ts" }, {}), null);
  assert.equal(alwaysDeny("Read", { file_path: "/proj/.unjangled-guardrails-notes.md" }, {}), null, "similar names must not over-fire");
});

function mkdtemp() { return mkdtempSync(join(tmpdir(), "unjangled-guardrails-orch-")); }
