// Issue 19 / CAP-13 (epic-github-field-reports ticket 1.19): a fresh install must SAY its
// policy is empty — setup's readiness report gains the policy section (WARN on zero entries,
// naming the defaults file and the adopt command; never gating the exit code), the install
// command ends with the recommended-next-steps block, the plugin README ends its Install
// section with the same checklist, and adoption stays explicit everywhere (no surface writes
// a store entry). Spawn-based per test/setup.test.js's recipes: temp HOME + temp GUARD_HOME,
// the conformance brain's simulated loopback behind SYSTEMONE_URL, evidence-guard restore.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { brainAnswer, classifyRequest } from "../tools/conformance/brain.mjs";
// The shared collision-proof evidence guard (ticket 1.20's sweep) — the same subtract-only
// restore this file used to carry as a local copy of setup.test.js's recipe, now serialized
// across suites by its cross-process lock.
import { evidenceGuard } from "./evidence-guard.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const date = () => new Date().toISOString().slice(0, 10);

// The simulated brain (setup.test.js's shape): safe passes, destructive is stopped — chosen
// per request from the command it sees.
async function startScenarioBrain(choose) {
  const { createServer } = await import("node:http");
  const requests = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      const body = JSON.parse(raw);
      requests.push(classifyRequest(body));
      res.writeHead(200, { "content-type": "application/json", connection: "close" });
      res.end(JSON.stringify(brainAnswer(body, choose(body))));
    });
  });
  await new Promise((res, rej) => { server.once("error", rej); server.listen(0, "127.0.0.1", res); });
  return { url: `http://127.0.0.1:${server.address().port}`, requests, close: () => new Promise((r) => server.close(r)) };
}
const chooser = (body) => (/rm -rf/.test(body?.state?.input?.command ?? "") ? "deny" : "allow");

function childEnv({ home, guardHome, brainUrl, operator } = {}) {
  return {
    PATH: process.env.PATH,
    ...(home ? { HOME: home } : {}),
    ...(guardHome ? { GUARD_HOME: guardHome } : {}),
    ...(brainUrl ? { SYSTEMONE_URL: brainUrl } : {}),
    ...(operator ? { GUARD_OPERATOR_CLI: "1" } : {}),
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

const tempHome = (kind) => mkdtempSync(join(tmpdir(), `ug-i19-${kind}-`));

test("fresh setup warns loudly: policy WARN names the defaults file and the adopt command, sits between rulings and verification, never gates exit — and adopts nothing", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const r = await run(childEnv({ home, guardHome, brainUrl: brain.url }), "setup", "claude");
    assert.equal(r.status, 0, `WARN must not gate the exit code — exit ${r.status}, stderr: ${r.stderr}`);
    const out = r.stdout;
    // the loud warning, naming both the file and the command (the issue's expected text)
    assert.match(out, /policy: WARN \(empty — recommended defaults not adopted: review examples\/user-policy\.default\.json, then run policy adopt-defaults \(adoption is explicit, never automatic\)\)/);
    // section order: the report reads store-integrity then store-content, before the live checks
    const at = ["rulings", "policy", "verification"].map((s) => out.indexOf(`\n${s}: `));
    assert.ok(at.every((i) => i >= 0), out);
    assert.deepEqual(at, [...at].sort((a, b) => a - b), out);
    // NEVER auto-applied: the store this run created is still empty, the audit carries only
    // the init row — no adoption row anywhere in the install path
    const store = JSON.parse(readFileSync(join(guardHome, "user-policy.json"), "utf8"));
    assert.deepEqual(store, { version: 1, entries: [] });
    const rows = readFileSync(join(guardHome, "rulings-use.jsonl"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].action, "init");
    // the evidence row carries the new section's status word, topology-free
    const row = JSON.parse(readFileSync(join(REPO, "evidence", `setup-${date()}.jsonl`), "utf8").trim().split("\n").filter(Boolean).pop());
    assert.equal(row.sections.policy, "WARN");
    assert.ok(!/examples\/|user-policy|http/.test(JSON.stringify(row.sections)), JSON.stringify(row.sections));
  } finally { restore(); await brain.close(); }
});

test("setup after adoption: policy GREEN with the count, no empty warning — the count itself stays unpinned (the defaults file churns under entry 13)", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const env = childEnv({ home, guardHome, brainUrl: brain.url, operator: true });
    // operator adoption through the real surface (the env-escape authority, audited)
    const adopt = await run(env, "policy", "adopt-defaults");
    assert.equal(adopt.status, 0, `adopt failed: ${adopt.stderr}`);
    const r = await run(env, "setup", "claude");
    assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
    assert.match(r.stdout, /policy: GREEN \(\d+ entries\)/);
    assert.ok(!/recommended defaults not adopted/.test(r.stdout), r.stdout);
    const row = JSON.parse(readFileSync(join(REPO, "evidence", `setup-${date()}.jsonl`), "utf8").trim().split("\n").filter(Boolean).pop());
    assert.equal(row.sections.policy, "GREEN");
  } finally { restore(); await brain.close(); }
});

test("degradation set but no entries: the warning stands — posture is not entries, the ask-flood gap is", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    // seed a posture-only store (0600, with its audit row so the tamper check stays quiet)
    writeFileSync(join(guardHome, "user-policy.json"), JSON.stringify({ version: 1, entries: [], degradation: "fail-closed" }, null, 2) + "\n", { mode: 0o600 });
    appendFileSync(join(guardHome, "rulings-use.jsonl"), JSON.stringify({ at: new Date().toISOString(), action: "policy-set", op: "set-degradation", id: "fail-closed", via: "seed" }) + "\n", { mode: 0o600 });
    const r = await run(childEnv({ home, guardHome, brainUrl: brain.url }), "setup", "claude");
    assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
    assert.match(r.stdout, /policy: WARN \(empty — recommended defaults not adopted/);
  } finally { restore(); await brain.close(); }
});

test("corrupt store: policy RED, never the empty warning — unknown state is not 'defaults not adopted'", async () => {
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    writeFileSync(join(guardHome, "user-policy.json"), "{ not json", { mode: 0o600 });
    const r = await run(childEnv({ home, guardHome }), "setup", "claude");
    assert.equal(r.status, 1);
    assert.match(r.stdout, /policy: RED \(store unreadable or corrupt — fix or remove it, then re-run setup\)/);
    assert.ok(!/recommended defaults not adopted/.test(r.stdout), r.stdout);
    const row = JSON.parse(readFileSync(join(REPO, "evidence", `setup-${date()}.jsonl`), "utf8").trim().split("\n").filter(Boolean).pop());
    assert.equal(row.sections.policy, "RED");
  } finally { restore(); }
});

test("install ends with the recommended-next-steps block — and installs no policy: the store is never created by the install path", async () => {
  const home = tempHome("home");
  const r = await run(childEnv({ home }), "install", "pi");
  assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
  const out = r.stdout;
  // the block is the tail of the install output: all four items, the target's verify named
  assert.match(out, /Recommended next steps \(the policy is empty until you adopt one — adoption is explicit, never automatic\):/);
  assert.match(out, /1\. review the suggested defaults in your checkout \(examples\/user-policy\.default\.json\), then run: unjangled-guardrails policy adopt-defaults/);
  assert.match(out, /2\. choose the brain-down posture: unjangled-guardrails policy set --degradation fail-open \| fail-closed \(fail-open is the default\)/);
  assert.match(out, /3\. unjangled-guardrails calibrate — self-certify the configured brain/);
  assert.match(out, /4\. unjangled-guardrails verify pi — live-verify pi's real surface/);
  // the block ends the output (only trailing whitespace may follow)
  const tail = out.slice(out.indexOf("Recommended next steps")).trimEnd();
  assert.ok(tail.endsWith("real surface with the safe and destructive probes"), out.slice(-400));
  // never auto-applied on this surface either: no store, no audit, anywhere under the temp HOME
  assert.ok(!existsSync(join(home, ".unjangled-guardrails", "user-policy.json")), "install must not create a policy store");
});

test("the plugin install docs end their Install section with the recommended-next-steps checklist (Hermes-true forms)", async () => {
  const md = readFileSync(join(REPO, "plugins", "unjangled-guardrails", "README.md"), "utf8");
  const at = ["## Install (operator-gated)", "### Recommended next steps", "## Behavior"].map((s) => md.indexOf(s));
  assert.ok(at.every((i) => i >= 0), md.slice(0, 400));
  assert.deepEqual(at, [...at].sort((a, b) => a - b), "the block must end the Install section");
  const block = md.slice(at[1], at[2]);
  // the four items, in the forms a Hermes operator can run: adopt (review first, explicit),
  // posture (env still wins), calibrate, and the adapter-true verify (no `verify hermes` target)
  assert.match(block, /examples\/user-policy\.default\.json/);
  assert.match(block, /policy adopt-defaults/);
  assert.match(block, /nothing is adopted\nautomatically, ever/);
  assert.match(block, /policy set --degradation fail-open \| fail-closed/);
  assert.match(block, /GUARD_FAIL_CLOSED.*env still wins/s);
  assert.match(block, /calibrate/);
  assert.match(block, /test_adapter\.py/);
  assert.match(block, /tools\/hermes-liveverify\.sh/);
});

test("the setup warning names the file adopt-defaults actually reads — one source of truth, pinned against drift", async () => {
  const { suggestedDefaultsFile } = await import("../src/policy.js");
  const { relative, resolve } = await import("node:path");
  // the export is the same constant adoptDefaults reads; the warning renders it repo-relative
  assert.ok(suggestedDefaultsFile().endsWith(join("examples", "user-policy.default.json")), suggestedDefaultsFile());
  assert.equal(relative(REPO, suggestedDefaultsFile()), join("examples", "user-policy.default.json"));
  assert.equal(resolve(REPO, "examples", "user-policy.default.json"), suggestedDefaultsFile());
});
