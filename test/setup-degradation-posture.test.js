// Issue 16 / CAP-13 (epic-github-field-reports ticket 1.16): the readiness report must SAY the
// active brain-down posture — rules | layered | closed — how it was set (the env spelling or
// the policy option), and the one-line command that changes it. Spawn-based per
// test/setup.test.js / test/install-empty-policy-warning.test.js recipes: temp HOME + temp
// GUARD_HOME for the spawned CLI, the conformance brain's simulated loopback behind
// SYSTEMONE_URL, seeded posture stores with their audit row, subtract-only evidence guard.
// The paste leg follows the 1.4 discipline: the printed change command runs VERBATIM through
// /bin/sh (GUARD_OPERATOR_CLI stands in for the operator terminal the paste lands in — the
// 1.19 adoption-leg precedent).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { brainAnswer, classifyRequest } from "../tools/conformance/brain.mjs";
// The shared collision-proof evidence guard (ticket 1.20's sweep) — this file's third-writer
// role is what the 1.16 change log recorded as widening the race window; the shared guard's
// lock now serializes every such writer against its siblings.
import { evidenceGuard } from "./evidence-guard.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const date = () => new Date().toISOString().slice(0, 10);

// The simulated brain (setup.test.js's shape): safe passes, destructive is stopped — chosen
// per request from the command it sees. The posture section reads no brain state, so every
// row is deterministic against it; it only keeps verification GREEN so the posture line is the
// only thing under test.
async function startScenarioBrain(choose) {
  const { createServer } = await import("node:http");
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      const body = JSON.parse(raw);
      res.writeHead(200, { "content-type": "application/json", connection: "close" });
      res.end(JSON.stringify(brainAnswer(body, choose(body))));
    });
  });
  await new Promise((res, rej) => { server.once("error", rej); server.listen(0, "127.0.0.1", res); });
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}
const chooser = (body) => (/rm -rf/.test(body?.state?.input?.command ?? "") ? "deny" : "allow");

// A whitelisted child env plus the posture spellings under test (nothing from the operator's
// shell can leak into a setup run — setup.test.js's own rule).
function childEnv({ home, guardHome, brainUrl, ...posture } = {}) {
  return {
    PATH: process.env.PATH,
    ...(home ? { HOME: home } : {}),
    ...(guardHome ? { GUARD_HOME: guardHome } : {}),
    ...(brainUrl ? { SYSTEMONE_URL: brainUrl } : {}),
    ...posture,
  };
}

const run = (env, ...args) => new Promise((resolve) => {
  const child = spawn(process.execPath, ["src/cli.js", ...args], { cwd: REPO, env });
  let stdout = "", stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  child.on("error", (e) => resolve({ status: -1, stdout, stderr: stderr + String(e) }));
  child.on("close", (status) => resolve({ status, stdout, stderr }));
});

const tempHome = (kind) => mkdtempSync(join(tmpdir(), `ug-i16-${kind}-`));

// Seed a posture option into the store the way `policy set --degradation` writes it (0600
// store, paired audit row so the tamper check stays quiet — install-empty-policy-warning's
// seeding recipe).
function seedDegradation(guardHome, degradation) {
  writeFileSync(join(guardHome, "user-policy.json"), JSON.stringify({ version: 1, entries: [], degradation }, null, 2) + "\n", { mode: 0o600 });
  appendFileSync(join(guardHome, "rulings-use.jsonl"), JSON.stringify({ at: new Date().toISOString(), action: "policy-set", op: "set-degradation", id: degradation, via: "seed" }) + "\n", { mode: 0o600 });
}

const lastRow = () =>
  JSON.parse(readFileSync(join(REPO, "evidence", `setup-${date()}.jsonl`), "utf8").trim().split("\n").filter(Boolean).pop());

test("fresh install, nothing set: posture rules names the built-in default, the behavior, and the paste-runnable change command — and never gates", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const r = await run(childEnv({ home, guardHome, brainUrl: brain.url }), "setup", "claude");
    assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
    const out = r.stdout;
    assert.match(out, /posture: rules \(the built-in default — brain-down: unmatched calls pass; change: GUARD_HOME='[^']+' node '[^']+' policy set --degradation fail-closed # policy store: [^)]+\)/);
    // section order: the config chain reads store-integrity, store-content, posture — before the live checks
    const at = ["rulings", "policy", "posture", "verification"].map((s) => out.indexOf(`\n${s}: `));
    assert.ok(at.every((i) => i >= 0), out);
    assert.deepEqual(at, [...at].sort((a, b) => a - b), out);
    // the command names the store the report read (this run's temp GUARD_HOME) and the repo's own entry
    assert.ok(out.includes(`GUARD_HOME='${guardHome}'`), out);
    assert.ok(out.includes(`node '${join(REPO, "src", "cli.js")}'`), out);
    assert.ok(out.includes(`# policy store: ${join(guardHome, "user-policy.json")}`), out);
    // the evidence row carries the posture word, topology-free
    const row = lastRow();
    assert.equal(row.sections.posture, "rules");
    assert.ok(!/127\.0\.0\.1|http|\/tmp|ug-i16/.test(JSON.stringify(row)), JSON.stringify(row));
  } finally { restore(); await brain.close(); }
});

test("the printed change command runs as printed and flips the next report — closed by policy", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const first = await run(childEnv({ home, guardHome, brainUrl: brain.url }), "setup", "claude");
    assert.equal(first.status, 0, first.stderr);
    // the paste: the printed line, VERBATIM, through /bin/sh in the operator's terminal shape
    // (GUARD_OPERATOR_CLI=1 — the 1.19 adoption-leg stand-in; a real operator terminal has
    // operator context natively)
    const line = first.stdout.match(/change: (GUARD_HOME='[^']+' node '[^']+' policy set --degradation fail-closed [^)]+)\)/)?.[1];
    assert.ok(line, first.stdout);
    const pasted = execFileSync("/bin/sh", ["-c", line], {
      cwd: REPO, encoding: "utf8",
      env: { PATH: process.env.PATH, HOME: home, GUARD_HOME: guardHome, GUARD_OPERATOR_CLI: "1" },
    });
    assert.match(pasted, /degradation posture set to fail-closed/);
    const second = await run(childEnv({ home, guardHome, brainUrl: brain.url }), "setup", "claude");
    assert.equal(second.status, 0, `exit ${second.status}, stderr: ${second.stderr}`);
    assert.match(second.stdout, /posture: closed \(set by policy: degradation=fail-closed — brain-down: unmatched calls deny; change: GUARD_HOME='[^']+' node '[^']+' policy set --degradation fail-open [^)]+\)/);
    assert.equal(lastRow().sections.posture, "closed");
  } finally { restore(); await brain.close(); }
});

test("explicit policy fail-open reads rules with the policy source — the default, set deliberately", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    seedDegradation(guardHome, "fail-open");
    const r = await run(childEnv({ home, guardHome, brainUrl: brain.url }), "setup", "claude");
    assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
    assert.match(r.stdout, /posture: rules \(set by policy: degradation=fail-open — brain-down: unmatched calls pass; change: [^)]*fail-closed[^)]*\)/);
    assert.equal(lastRow().sections.posture, "rules");
  } finally { restore(); await brain.close(); }
});

test("env GUARD_FALLBACK=closed: posture closed names the env spelling and the env-wins change line, never gates", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const r = await run(childEnv({ home, guardHome, brainUrl: brain.url, GUARD_FALLBACK: "closed" }), "setup", "claude");
    assert.equal(r.status, 0, `the posture section must not gate — exit ${r.status}, stderr: ${r.stderr}`);
    assert.match(r.stdout, /posture: closed \(set by env GUARD_FALLBACK=closed — brain-down: unmatched calls deny; change: unset GUARD_FALLBACK in the env that runs the gate — the env posture wins over policy set --degradation while set\)/);
    assert.equal(lastRow().sections.posture, "closed");
  } finally { restore(); await brain.close(); }
});

test("the legacy GUARD_FAIL_CLOSED flag: closed names the legacy spelling and its own unset line", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const r = await run(childEnv({ home, guardHome, brainUrl: brain.url, GUARD_FAIL_CLOSED: "1" }), "setup", "claude");
    assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
    assert.match(r.stdout, /posture: closed \(set by legacy env GUARD_FAIL_CLOSED=1 — all spellings map to closed; brain-down: unmatched calls deny; change: unset GUARD_FAIL_CLOSED in the env that runs the gate — the env posture wins over policy set --degradation while set\)/);
    assert.equal(lastRow().sections.posture, "closed");
  } finally { restore(); await brain.close(); }
});

test("env GUARD_FALLBACK=layered: posture layered, deferring to the host heuristic stack", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const r = await run(childEnv({ home, guardHome, brainUrl: brain.url, GUARD_FALLBACK: "layered" }), "setup", "claude");
    assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
    assert.match(r.stdout, /posture: layered \(set by env GUARD_FALLBACK=layered — brain-down: unmatched calls defer to the host heuristic stack; change: unset GUARD_FALLBACK in the env that runs the gate — the env posture wins over policy set --degradation while set\)/);
    assert.equal(lastRow().sections.posture, "layered");
  } finally { restore(); await brain.close(); }
});

test("env wins over policy: the legacy flag beats a seeded fail-open option — the source names the winner", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    seedDegradation(guardHome, "fail-open");
    const r = await run(childEnv({ home, guardHome, brainUrl: brain.url, GUARD_FAIL_CLOSED: "1" }), "setup", "claude");
    assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
    const line = r.stdout.split("\n").find((l) => l.startsWith("posture:"));
    assert.match(line, /^posture: closed \(set by legacy env GUARD_FAIL_CLOSED=1/);
    assert.ok(!/set by policy/.test(line), line);  // the policy option is inert under the env posture
  } finally { restore(); await brain.close(); }
});

test("JEV_ back-compat spellings render themselves: JEV_GUARD_FALLBACK and JEV_GUARD_FAIL_CLOSED", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const a = await run(childEnv({ home, guardHome, brainUrl: brain.url, JEV_GUARD_FALLBACK: "closed" }), "setup", "claude");
    assert.match(a.stdout, /posture: closed \(set by env JEV_GUARD_FALLBACK=closed [^)]*\)/);
    const b = await run(childEnv({ home, guardHome, brainUrl: brain.url, JEV_GUARD_FAIL_CLOSED: "true" }), "setup", "claude");
    assert.match(b.stdout, /posture: closed \(set by legacy env JEV_GUARD_FAIL_CLOSED=true [^)]*\)/);
  } finally { restore(); await brain.close(); }
});

test("corrupt store: the policy section owns the RED; posture still renders, honest about the unreadable option, never RED", async () => {
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    writeFileSync(join(guardHome, "user-policy.json"), "{ not json", { mode: 0o600 });
    const r = await run(childEnv({ home, guardHome }), "setup", "claude");
    assert.equal(r.status, 1, "exit 1 comes from the policy RED, not the posture word");
    assert.match(r.stdout, /policy: RED \(store unreadable or corrupt — fix or remove it, then re-run setup\)/);
    assert.match(r.stdout, /posture: rules \(env unset and the policy option unreadable — the corrupt store is the policy section's RED; brain-down: unmatched calls pass; change: [^)]*fail-closed[^)]*\)/);
    assert.notEqual(lastRow().sections.posture, "RED");
  } finally { restore(); }
});

test("a single-quote path degrades the command spelling instead of breaking it", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home");
  const guardHome = mkdtempSync(join(tmpdir(), "ug-i16-q'ote-"));
  const restore = evidenceGuard();
  try {
    const r = await run(childEnv({ home, guardHome, brainUrl: brain.url }), "setup", "claude");
    assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
    // the GUARD_HOME prefix is dropped (its path cannot be single-quoted); the entry + subcommand survive
    assert.ok(!r.stdout.includes("GUARD_HOME='"), r.stdout);
    assert.match(r.stdout, /change: node '[^']+' policy set --degradation fail-closed # policy store: [^)]+\)/);
  } finally { restore(); await brain.close(); }
});
