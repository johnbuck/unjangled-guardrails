// Workdir-resolved project scope (CAP-6, epic-github-field-reports entry 6 / GitHub issue 6):
// the Hermes plugin stamped every payload with the harness process cwd (~/.hermes), so a
// project-scoped entry never matched a subagent terminal call running in a repo under the
// scope prefix — the gate attributed every call to where Hermes was installed. This file
// pins the fix at both halves: the core's cwd derivation (callWorkdir, applied once inside
// assessAction so the scope consult, the degraded consult, and the ask-band hint all see the
// call's true folder) and the plugin's truthful payload cwd (args/kwargs workdir extraction,
// os.getcwd() only as the fallback). Conventions follow rulings.test.js: temp GUARD_HOME,
// the same fake brain (behind SYSTEMONE_URL — the keyless local backend shape), operator
// escape env for store mutations.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { assessAction } from "../src/guard.js";
import { handleHook } from "../src/hook.js";
import { callWorkdir, addRuling } from "../src/rulings.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));

// Same fake brain as rulings.test.js: rm -rf → deny, git push → ask, everything else → allow.
// Served behind the keyless local-backend env shape (SYSTEMONE_URL selects it; fetchImpl
// intercepts, nothing reaches the network).
async function fetchImpl(_url, { body }) {
  const { state } = JSON.parse(body);
  const cmd = JSON.stringify(state.input);
  const score = /rm -rf|DROP TABLE/.test(cmd) ? 2.9 : /git push|git commit|curl -X POST/.test(cmd) ? 2.0 : 0.2;
  const answers = {
    risk: { type: "score", score, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: score >= 2 ? 0.85 : 0.05 },
    user_requested: { type: "noul", noul: 0.05 },
    from_untrusted: { type: "noul", noul: 0.05 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
  };
  return { ok: true, json: async () => ({ answers }) };
}

const home = () => mkdtempSync(join(tmpdir(), "unjangled-guardrails-workdir-"));
const env = (dir) => ({ SYSTEMONE_URL: "http://127.0.0.1:9", GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" });
const opts = (dir, extra = {}) => ({ env: env(dir), fetchImpl, ...extra });

const HARNESS_HOME = "/Users/reporter/.hermes";           // the issue's payload cwd: where Hermes lives
const SCOPE_ROOT = "/Users/reporter/projects";             // the operator's folder-scoped entry
const REPO_WD = "/Users/reporter/projects/unjangled-guardrails";  // where the call actually runs

// ── callWorkdir units: the derivation, its shape gate, precedence, and fallbacks ──────────────

test("callWorkdir: a bash-shaped input's workdir field is the call's folder", () => {
  for (const field of ["cwd", "workdir", "working_dir", "directory"])
    assert.equal(callWorkdir("Bash", { command: "git commit -m x", [field]: REPO_WD }, HARNESS_HOME), REPO_WD, field);
});

test("callWorkdir: precedence is cwd > workdir > working_dir > directory, first non-empty wins", () => {
  assert.equal(callWorkdir("Bash", { command: "ls", cwd: "/a", workdir: "/b" }, "/f"), "/a");
  assert.equal(callWorkdir("Bash", { command: "ls", workdir: "/b", directory: "/d" }, "/f"), "/b");
  assert.equal(callWorkdir("Bash", { command: "ls", cwd: "  ", workdir: "/b" }, "/f"), "/b", "blank skipped");
});

test("callWorkdir: a terminal tool name derives even without a command field; non-bash never does", () => {
  assert.equal(callWorkdir("Terminal", { workdir: REPO_WD }, HARNESS_HOME), REPO_WD);
  assert.equal(callWorkdir("mcp__fs__list", { directory: REPO_WD }, HARNESS_HOME), HARNESS_HOME,
    "a target dir on a non-shell tool is not an exec folder");
  assert.equal(callWorkdir("Write", { file_path: "/p/x", directory: REPO_WD }, HARNESS_HOME), HARNESS_HOME);
});

test("callWorkdir: relative workdirs resolve against the fallback, never process.cwd(); no fallback passes raw", () => {
  assert.equal(callWorkdir("Bash", { command: "ls", workdir: "sub" }, SCOPE_ROOT), join(SCOPE_ROOT, "sub"));
  assert.equal(callWorkdir("Bash", { command: "ls", workdir: "sub" }), "sub");
});

test("callWorkdir: no workdir field, non-string values, no input — the fallback unchanged", () => {
  assert.equal(callWorkdir("Bash", { command: "ls" }, "/proj"), "/proj");
  assert.equal(callWorkdir("Bash", { command: "ls", workdir: 7, cwd: null }, "/proj"), "/proj");
  assert.equal(callWorkdir("Bash", undefined, "/proj"), "/proj");
});

// ── the repro, through assessAction: the scoped entry matches the call's workdir ──────────────

test("the repro: an entry scoped to the prefix lifts a call whose workdir is inside it — payload cwd is the harness home", async () => {
  const dir = home();
  const r = addRuling({ effect: "allow", pattern: "git commit*", scope: `project:${SCOPE_ROOT}`, reason: "folder-scoped commit allow" }, env(dir));
  const verdict = await assessAction({ tool: "Bash", input: { command: "git commit -m 'ship'", workdir: REPO_WD }, cwd: HARNESS_HOME, sessionId: "s-6" }, opts(dir));
  assert.equal(verdict.level, "allow");
  assert.equal(verdict.ruling, r.id);
  assert.match(verdict.message, new RegExp(`by ruling ${r.id}`));
});

test("the must-not row: workdir outside the prefix does not match — the ask stands, no global widening needed", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git commit*", scope: `project:${SCOPE_ROOT}` }, env(dir));
  const verdict = await assessAction({ tool: "Bash", input: { command: "git commit -m 'ship'", workdir: "/Users/reporter/elsewhere" }, cwd: HARNESS_HOME, sessionId: "s-6" }, opts(dir));
  assert.equal(verdict.level, "ask");
  assert.ok(!verdict.ruling);
});

test("byte-identical fallback: no workdir field keeps today's behavior — the session cwd is the scope", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push*", scope: "project:/proj" }, env(dir));
  assert.equal((await assessAction({ tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj", sessionId: "s-6" }, opts(dir))).level, "allow");
  const other = await assessAction({ tool: "Bash", input: { command: "git push origin release" }, cwd: "/elsewhere", sessionId: "s-6" }, opts(dir));
  assert.equal(other.level, "ask");
});

test("non-bash calls never derive: an MCP directory field does not steer scope", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "*", tool: "mcp__fs__list", scope: `project:${SCOPE_ROOT}` }, env(dir));
  const verdict = await assessAction({ tool: "mcp__fs__list", input: { directory: REPO_WD }, cwd: HARNESS_HOME, sessionId: "s-6" }, opts(dir));
  assert.equal(verdict.level, "allow", "brain allows regardless — the point is no ruling fired");
  assert.ok(!verdict.ruling, "the scoped entry did not match: no derivation outside shell shape");
});

// ── the hook path: the Hermes spawn shape, end to end through the Claude-shaped dialect ───────

test("hook path: a hermes-shaped PreToolUse with the harness-home payload cwd lifts through the scoped entry", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git commit*", scope: `project:${SCOPE_ROOT}` }, env(dir));
  const out = await handleHook(
    { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "git commit -m 'ship'", workdir: REPO_WD }, cwd: HARNESS_HOME, session_id: "s-6" },
    { agent: "hermes", env: env(dir), fetchImpl });
  assert.equal(out, null, "allow prints nothing — the scoped entry matched the workdir");
});

// ── the hint: the block message names the resolved project, never the harness home ────────────

test("the ask-band hint names the resolved project: project:<workdir>, not the harness home", async () => {
  const dir = home();
  const verdict = await assessAction({ tool: "Bash", input: { command: "git push origin release", workdir: REPO_WD }, cwd: HARNESS_HOME, sessionId: "s-6" }, opts(dir));
  assert.equal(verdict.level, "ask");
  assert.ok(verdict.rulingHint.includes(`--scope 'project:${REPO_WD}'`), `hint carries the resolved project: ${verdict.rulingHint}`);
  assert.ok(!verdict.rulingHint.includes(HARNESS_HOME), "the harness home is never the suggested scope");
});

// ── the degraded consult: brain down, the scoped allow still lifts on the workdir ─────────────

test("degraded: with the brain unreachable the scoped entry still lifts through the workdir (no global widening)", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git commit*", scope: `project:${SCOPE_ROOT}` }, env(dir));
  const throwingBrain = async () => { throw new Error("brain unreachable"); };
  const verdict = await assessAction({ tool: "Bash", input: { command: "git commit -m 'ship'", workdir: REPO_WD }, cwd: HARNESS_HOME, sessionId: "s-6" }, { env: env(dir), fetchImpl: throwingBrain });
  assert.equal(verdict.level, "allow");
  assert.equal(verdict.degraded, true);
  assert.match(verdict.why, /by ruling/);
});

// ── the Hermes plugin: the payload itself carries the call's folder ──────────────────────────

// A python driver that stubs the hook spawn and captures the payloads _pre_tool_call builds.
const DRIVER = [
  "import importlib.util, json, os, sys",
  "spec = importlib.util.spec_from_file_location('ug_plugin', sys.argv[1])",
  "mod = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(mod)",
  "captured = []",
  "mod._run_hook = lambda payload: (captured.append(payload), None)[1]",
  "mod._pre_tool_call(tool_name='terminal', args={'command': 'git commit -m x', 'workdir': '/args/wd'}, session_id='s')",
  "mod._pre_tool_call(tool_name='terminal', args={'command': 'ls'}, session_id='s', cwd='/kwargs/cwd')",
  "mod._pre_tool_call(tool_name='terminal', args={'command': 'ls', 'cwd': '/a', 'workdir': '/b'}, session_id='s')",
  "mod.os.getcwd = lambda: '/harness/home'",
  "mod._pre_tool_call(tool_name='terminal', args={'command': 'ls'}, session_id='s')",
  "print(json.dumps([p['cwd'] for p in captured]))",
].join("\n");

test("plugin payload: the call's workdir (args, then kwargs, precedence) is the payload cwd; process cwd is only the fallback", () => {
  const dir = home();
  const driver = join(dir, "driver.py");
  writeFileSync(driver, DRIVER);
  const proc = spawnSync("python3", [driver, join(REPO, "plugins", "unjangled-guardrails", "__init__.py")], { encoding: "utf8" });
  if (proc.error && proc.error.code === "ENOENT") return; // no python3 on this host — the node-side rows already pin the core behavior
  assert.equal(proc.status, 0, proc.stderr);
  assert.deepEqual(JSON.parse(proc.stdout.trim()), ["/args/wd", "/kwargs/cwd", "/a", "/harness/home"]);
});
