// Directory entries — the confined-work surface (2026-10-20, plan-policy-dir-targets): a third
// policy entry kind, `policy add --dir <path> --effect allow|deny|ask` — "calls whose argument
// paths ALL resolve under this directory take this effect". The operator's semantics, verbatim
// force: "ALL THESE CALLS SHOULD STILL GO THROUGH THE BRAIN. THE ONLY THING THIS SHOULD DO IS
// PUSH AN ASK INTO AN ALLOW IF IT IS NOT DANGEROUS." Every row below asserts that shape: the
// brain runs, the push only lifts asks, the brain's deny line and Always-Deny outrank, and the
// effects hold in the degraded posture (deterministic).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirEffect, pathArguments, addDirEntry, removeEntry, adoptDefaults, listEntries } from "../src/policy.js";
import { assessAction } from "../src/guard.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const mkdtemp = () => mkdtempSync(join(tmpdir(), "unjangled-guardrails-dir-"));
const env = (home) => ({ JEV_API_KEY: "test", GUARD_HOME: home });

// Seed the store directly, pairing the audit row FIRST (saveStore's discipline, so the
// consult-time tamper check stays silent on a hand-written fixture).
const seed = (home, entries) => {
  mkdirSync(home, { recursive: true });
  appendFileSync(join(home, "rulings-use.jsonl"), JSON.stringify({ at: new Date().toISOString(), action: "mutation", op: "seed", id: "test" }) + "\n", { mode: 0o600 });
  writeFileSync(join(home, "user-policy.json"), JSON.stringify({ version: 1, entries }, null, 2) + "\n");
};
const dirEntry = (path, effect) => ({ id: "d-test", kind: "dir", path, effect, at: new Date().toISOString() });

// The brain mock (the lane.test.js shape); risk alone drives the verdict —
// 0.2 allow, 2.2 ask (askScore 2.0), 2.7 deny (denyScore 2.55). `calls` counts brain round
// trips, so the rows can prove the brain ran (or, for the Always-Deny row, never ran).
const brainMock = ({ risk = 0.2 } = {}) => {
  const calls = { count: 0 };
  const impl = async () => {
    calls.count++;
    return { ok: true, json: async () => ({ answers: {
      risk: { type: "score", score: risk, probabilities: {}, confidence: 0.8 },
      approval: { type: "noul", noul: 0.1 }, user_requested: { type: "noul", noul: 0.05 },
      from_untrusted: { type: "noul", noul: 0.05 },
      leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
      dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
    } }) };
  };
  impl.calls = calls;
  return impl;
};
const opts = (home, brainOpts) => {
  const fetchImpl = brainMock(brainOpts);
  return { env: env(home), fetchImpl, brainCalls: fetchImpl.calls };
};

// The operator's first consumer, the runtime smoke: every path under /tmp, script exec inside.
const SMOKE = "cd /tmp/claude-mcpe-smoke && npm ci && node build.js > /tmp/smoke.log 2>&1";

// ── the effect matrix (plan-policy-dir-targets) ───────────────────────────────────────────────

test("matrix 1: the brain still runs; its ask on all-under-/tmp work is pushed to allow", async () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow")]);
  const o = opts(home, { risk: 2.2 });  // the ask band
  const r = await assessAction({ tool: "Bash", input: { command: SMOKE }, cwd: "/proj" }, o);
  assert.equal(r.level, "allow", "the hesitation passes for in-dir work");
  assert.match(r.why, /dir policy: pass \(operator-owned directory \/tmp\)/);
  assert.equal(o.brainCalls.count, 1, "the covered call paid the brain round trip");
  assert.match(r.stats, /dir policy/);
});

test("matrix 2: one path outside the directory kills coverage — the compound stays ask", async () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow")]);
  const r = await assessAction({ tool: "Bash", input: { command: "cd /tmp/smoke && cp build.js ~/escape.js" }, cwd: "/proj" },
    opts(home, { risk: 2.2 }));
  assert.equal(r.level, "ask");
  assert.doesNotMatch(r.why ?? "", /dir policy/);
});

test("matrix 3: the brain's deny line outranks the push — dangerous in-dir work stays deny", async () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow")]);
  const r = await assessAction({ tool: "Bash", input: { command: "cd /tmp/smoke && ./build.sh" }, cwd: "/proj" },
    opts(home, { risk: 2.7 }));
  assert.equal(r.level, "deny");
  assert.equal(r.category, "Dangerous Action", "the deny is the brain's, not an operator ban");
});

test("matrix 4+5: file-tool writes — under /tmp pushes the ask, outside takes the plain verdict", async () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow")]);
  const inside = await assessAction({ tool: "Write", input: { file_path: "/tmp/scratch/notes.md", content: "scratch notes" }, cwd: "/proj" },
    opts(home, { risk: 2.2 }));
  assert.equal(inside.level, "allow");
  assert.match(inside.why, /dir policy: pass/);
  const outside = await assessAction({ tool: "Write", input: { file_path: "/home/x/proj/app.js", content: "scratch notes" }, cwd: "/proj" },
    opts(home, { risk: 2.2 }));
  assert.equal(outside.level, "ask");
  assert.doesNotMatch(outside.why ?? "", /dir policy/);
});

test("matrix 6: a deny entry hard-blocks a brain allow, surfacing as the operator's own ban", async () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "deny")]);
  const r = await assessAction({ tool: "Bash", input: { command: "cat /tmp/notes.txt" }, cwd: "/proj" },
    opts(home, { risk: 0.2 }));
  assert.equal(r.level, "deny");
  assert.match(r.why, /dir policy: denied by operator rule \(\/tmp\)/);
  assert.equal(r.category, "dir policy: denied by operator rule (/tmp)");
  assert.match(r.message, /The operator banned this outcome on purpose/);  // operator family text (message registry 2026-10-25)
});

test("matrix 7: most-specific directory wins — the longer path's ask binds even over a brain allow", async () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow"), dirEntry("/tmp/claude-mcpe-smoke", "ask")]);
  const r = await assessAction({ tool: "Bash",
    input: { command: "cd /tmp/claude-mcpe-smoke && node build.js > /tmp/claude-mcpe-smoke/build.log" }, cwd: "/proj" },
    opts(home, { risk: 0.2 }));
  assert.equal(r.level, "ask", "the longest covering path's effect wins");
  assert.match(r.why, /always asks by operator rule \(\/tmp\/claude-mcpe-smoke\)/);
});

test("matrix 8: Always-Deny outranks the dir entry — a credential shape under /tmp denies pre-brain", async () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow")]);
  const o = opts(home, { risk: 0.2 });
  const r = await assessAction({ tool: "Bash", input: { command: "cat /tmp/deploy.env" }, cwd: "/proj" }, o);
  assert.equal(r.level, "deny");
  assert.equal(o.brainCalls.count, 0, "the floor resolved before any brain call");
});

test("matrix 9: brain down — dir effects apply to the degraded verdict (deterministic)", async () => {
  const down = async () => { throw new Error("down"); };
  // (Degraded stats predate dir entries and carry no entry markers — the effect is asserted
  // through the verdicts it visibly flips, not through stats.)
  const passed = mkdtemp();
  seed(passed, [dirEntry("/tmp", "allow")]);
  const allowRow = await assessAction({ tool: "Bash", input: { command: "cd /tmp/smoke && ./build.sh" }, cwd: "/proj" },
    { env: env(passed), fetchImpl: down });
  assert.equal(allowRow.level, "allow", "the fail-open degraded allow takes the dir effect identically");
  assert.equal(allowRow.degraded, true);
  const prompted = mkdtemp();
  seed(prompted, [dirEntry("/tmp", "ask")]);
  const askRow = await assessAction({ tool: "Bash", input: { command: "cd /tmp/smoke && ./build.sh" }, cwd: "/proj" },
    { env: env(prompted), fetchImpl: down });
  assert.equal(askRow.level, "ask", "the ask effect flips the degraded allow — it holds with no brain");
  assert.match(askRow.why, /dir policy: always asks by operator rule \(\/tmp\)/);
  assert.equal(askRow.degraded, true);
  const blocked = mkdtemp();
  seed(blocked, [dirEntry("/tmp", "deny")]);
  const denied = await assessAction({ tool: "Bash", input: { command: "cat /tmp/notes.txt" }, cwd: "/proj" },
    { env: env(blocked), fetchImpl: down });
  assert.equal(denied.level, "deny", "a deny entry holds degraded — hard block, not a posture artifact");
  assert.match(denied.why, /dir policy: denied by operator rule/);
});

test("matrix 10: no path arguments — not covered, the plain brain verdict stands", async () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow")]);
  const r = await assessAction({ tool: "Bash", input: { command: "echo hi" }, cwd: "/proj" }, opts(home, { risk: 2.2 }));
  assert.equal(r.level, "ask");
  assert.doesNotMatch(r.why ?? "", /dir policy/);
});

test("matrix addendum: a glued input-redirect target outside the dir kills coverage", async () => {
  assert.deepEqual(pathArguments("Bash", { command: "cd /tmp/x && ./build.sh </etc/hosts" }),
    ["/tmp/x", "/etc/hosts"], "the < prefix strips and the target resolves");
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow")]);
  const r = await assessAction({ tool: "Bash", input: { command: "cd /tmp/x && ./build.sh </etc/hosts" }, cwd: "/proj" },
    opts(home, { risk: 2.2 }));
  assert.equal(r.level, "ask", "not covered — the ask is not pushed to allow");
  assert.doesNotMatch(r.why ?? "", /dir policy/);
});

test("the camelCase filePath key contributes path arguments — a /tmp deny binds it", () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "deny")]);
  assert.deepEqual(pathArguments("Write", { filePath: "/tmp/x.js" }), ["/tmp/x.js"]);
  assert.equal(dirEffect("Write", { filePath: "/tmp/x.js" }, { env: env(home) }).effect, "deny");
});

test("adopt-defaults refuses a relative dir path with addDirEntry's message", () => {
  const home = mkdtemp();
  const E = { ...env(home), GUARD_OPERATOR_CLI: "1" };
  const file = join(mkdtemp(), "defaults.json");
  writeFileSync(file, JSON.stringify({ version: 1, entries: [{ kind: "dir", path: "relative/dir", effect: "allow" }] }));
  assert.throws(() => adoptDefaults(E, { file }), /absolute path/);
  assert.equal(listEntries(E).filter((e) => e.kind === "dir").length, 0, "nothing adopted");
});

test("remove accepts the raw dir spelling: /tmp/ removes the /tmp entry", () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow")]);
  const E = { ...env(home), GUARD_OPERATOR_CLI: "1" };
  assert.equal(removeEntry("/tmp/", E).removed, true);
  assert.equal(listEntries(E).filter((e) => e.kind === "dir").length, 0);
});

// ── extraction + selection mechanics ──────────────────────────────────────────────────────────

test("pathArguments: bash tokens per segment (redirect targets in, relative names out), file-tool keys", () => {
  assert.deepEqual(pathArguments("Bash", { command: "cd /tmp/a && node build.js > /tmp/b.log 2>&1" }),
    ["/tmp/a", "/tmp/b.log"]);
  assert.deepEqual(pathArguments("Bash", { command: "cat /tmp/a; echo x 2>/tmp/err" }),
    ["/tmp/a", "/tmp/err"], "a glued 2> redirect prefix strips before resolution");
  assert.deepEqual(pathArguments("Bash", { command: "npm ci" }), [], "bare relative names fall through");
  assert.equal(pathArguments("Bash", { command: "cp x ~/keep.txt" }).length, 1, "tilde tokens resolve");
  assert.deepEqual(pathArguments("Write", { file_path: "/tmp/x.js", content: "y" }), ["/tmp/x.js"]);
  assert.deepEqual(pathArguments("NotebookEdit", { notebook_path: "/tmp/n.ipynb" }), ["/tmp/n.ipynb"]);
  assert.deepEqual(pathArguments("WebFetch", { url: "https://example.com/x" }), [], "non-file tools contribute nothing");
  assert.deepEqual(pathArguments("mcp__filesystem__read_file", { path: "/tmp/x" }), ["/tmp/x"],
    "mcp filesystem-style rides the suffix families via the final segment");
});

test("dirEffect: only COVERING entries compete — a longer directory that misses one path loses", () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp", "allow"), dirEntry("/tmp/claude-mcpe-smoke", "ask")]);
  const mixed = dirEffect("Bash", { command: "cd /tmp/claude-mcpe-smoke && cp build.js /tmp/out.log" }, { env: env(home) });
  assert.equal(mixed.effect, "allow", "/tmp/claude-mcpe-smoke does not cover /tmp/out.log — /tmp binds");
  const tight = dirEffect("Bash", { command: "cd /tmp/claude-mcpe-smoke && cp build.js /tmp/claude-mcpe-smoke/out.log" }, { env: env(home) });
  assert.equal(tight.effect, "ask", "both paths inside — the longest directory binds");
  assert.equal(dirEffect("Bash", { command: "echo hi" }, { env: env(home) }), null, "no path arguments, no hit");
});

test("same-path ties resolve deny > ask > allow; removeEntry accepts the dir path", () => {
  const home = mkdtemp();
  seed(home, [dirEntry("/tmp/shared", "ask"), dirEntry("/tmp/shared", "deny")]);
  assert.equal(dirEffect("Write", { file_path: "/tmp/shared/x.js" }, { env: env(home) }).effect, "deny");
  const E = { ...env(home), GUARD_OPERATOR_CLI: "1" };
  assert.equal(removeEntry("/tmp/shared", E).removed, true, "the dir path removes the entry");
  assert.equal(listEntries(E).filter((e) => e.kind === "dir").length, 0);
});

// ── mutations + the CLI surface ───────────────────────────────────────────────────────────────

test("addDirEntry: operator-only, absolute-path + effect validation, idempotent per directory", () => {
  const home = mkdtemp();
  const E = { ...env(home), GUARD_OPERATOR_CLI: "1" };
  assert.throws(() => addDirEntry({ path: "/tmp", effect: "allow" }, env(home)), /operator-only/);
  assert.throws(() => addDirEntry({ path: "relative/dir", effect: "allow" }, E), /absolute path/);
  assert.throws(() => addDirEntry({ path: "/tmp", effect: "maybe" }, E), /effect must be one of/);
  const first = addDirEntry({ path: "/tmp/", effect: "allow", reason: "scratch" }, E);  // trailing slash normalizes
  assert.equal(first.kind, "dir");
  assert.equal(first.path, "/tmp");
  assert.match(first.id, /^d-[0-9a-f]{4}$/);
  assert.equal(addDirEntry({ path: "/tmp", effect: "allow" }, E).existed, true, "one entry per directory");
  assert.equal(listEntries(E).filter((e) => e.kind === "dir").length, 1);
});

test("adopt-defaults merges the /tmp dir entry and skips it on re-adopt", () => {
  const home = mkdtemp();
  const E = { ...env(home), GUARD_OPERATOR_CLI: "1" };
  const first = adoptDefaults(E);
  assert.ok(first.added >= 1);
  assert.equal(listEntries(E).filter((e) => e.kind === "dir" && e.path === "/tmp").length, 1);
  const second = adoptDefaults(E);
  assert.ok(second.skipped >= 1);
  assert.equal(listEntries(E).filter((e) => e.kind === "dir").length, 1, "no duplicate on re-adopt");
});

test("CLI: policy add --dir saves, policy list renders the dir entry, remove by id; mixing kinds dies", () => {
  const home = mkdtemp();
  const childEnv = { ...process.env, GUARD_HOME: home, GUARD_OPERATOR_CLI: "1" };
  const run = (args) => execFileSync(process.execPath, ["src/cli.js", "policy", ...args], { cwd: REPO, env: childEnv, encoding: "utf8" });
  run(["add", "--dir", "/tmp", "--effect", "allow", "--reason", "transient scratch work"]);
  const list = run(["list"]);
  assert.match(list, /^d-[0-9a-f]{4}  dir   allow  \/tmp$/m);
  assert.match(list, /reason: transient scratch work/);
  const id = list.match(/^(d-[0-9a-f]{4})/m)[1];
  assert.match(run(["remove", id]), /policy entry removed/);
  const mixed = (() => { try { run(["add", "--dir", "/tmp", "--tool", "x"]); return ""; } catch (e) { return `${e.status} ${e.stderr}`; } })();
  assert.match(mixed, /^1 .*not a mix/, "--dir is its own entry kind");
});
