// Tracer (epic-installer ticket 1): spawn-based tests for `setup <agent>` — the one commanded
// path from clone to a verified first session, per the plan's I/O matrix. Isolation follows the
// established recipes (guard.test.js's install spawn, rulings.test.js's CLI spawn): temp HOME +
// temp GUARD_HOME for the spawned CLI, and the conformance brain's simulated loopback server
// behind SYSTEMONE_URL, so no test touches a live brain or the operator's real state.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { brainAnswer, classifyRequest } from "../tools/conformance/brain.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const date = () => new Date().toISOString().slice(0, 10);

// The simulated brain as a loopback server whose scenario is chosen PER REQUEST from the
// command it sees — the shape a real brain has (a safe call passes, a destructive call is
// stopped) — composed from tools/conformance/brain.mjs's scripted answers. Requests land in
// the same record shape the conformance suite asserts on.
async function startScenarioBrain(choose) {
  const { createServer } = await import("node:http");
  const requests = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      const body = JSON.parse(raw);
      requests.push(classifyRequest(body));
      // Connection: close — without it the spawned hook lingers on undici's keep-alive socket
      // until the server's idle timeout, and every probe costs the idle delay.
      res.writeHead(200, { "content-type": "application/json", connection: "close" });
      res.end(JSON.stringify(brainAnswer(body, choose(body))));
    });
  });
  await new Promise((res, rej) => { server.once("error", rej); server.listen(0, "127.0.0.1", res); });
  return { url: `http://127.0.0.1:${server.address().port}`, requests, close: () => new Promise((r) => server.close(r)) };
}

// A whitelisted child env: nothing from the operator's shell (credentials, backends, legacy
// JEV_* names) can leak into a setup run. HOME and GUARD_HOME are this test's fresh temp dirs.
function childEnv({ home, guardHome, brainUrl } = {}) {
  return {
    PATH: process.env.PATH,
    ...(home ? { HOME: home } : {}),
    ...(guardHome ? { GUARD_HOME: guardHome } : {}),
    ...(brainUrl ? { SYSTEMONE_URL: brainUrl } : {}),
  };
}

// Setup and live-verify both append to the repo's evidence/ records; a simulated-brain run must
// NOT leave rows there (its live-verify rows carry live-verify's "live backend (operator
// config)" note, which would read as real-backend evidence). The restore is subtract-only: it
// drops exactly the lines this run appended (multiplicity-aware diff against the snapshot) and
// leaves every line that was already in the file — a concurrent session's rows included —
// untouched, instead of clobbering the whole file back to its snapshot or deleting it.
function evidenceGuard() {
  const dir = join(REPO, "evidence");
  const files = [`setup-${date()}.jsonl`, `live-verify-claude-${date()}.jsonl`].map((n) => join(dir, n));
  const before = files.map((f) => (existsSync(f) ? readFileSync(f, "utf8") : null));
  return () => files.forEach((f, i) => {
    if (!existsSync(f)) return;
    const now = readFileSync(f, "utf8");
    if (before[i] === null) { rmSync(f, { force: true }); return; }  // this run created the file
    if (now === before[i]) return;
    const counts = new Map();
    for (const l of before[i].split("\n")) counts.set(l, (counts.get(l) ?? 0) + 1);
    const kept = now.split("\n").filter((l) => {
      const c = counts.get(l) ?? 0;
      if (c > 0) { counts.set(l, c - 1); return true; }  // a snapshot line (or a duplicate of one): keep
      return false;                                       // appended during the run: subtract
    });
    if (kept.join("\n") !== now) writeFileSync(f, kept.join("\n"));
  });
}

// Async spawn, not spawnSync: the simulated brain serves from THIS process, and a sync wait
// would block its event loop — the spawned hook's brain requests would queue behind the wait
// and die on the 20 s guard budget. Awaiting the child keeps the loop free to answer.
const setup = (env, target = "claude") => new Promise((resolve) => {
  const child = spawn(process.execPath, ["src/cli.js", "setup", target], { cwd: REPO, env });
  let stdout = "", stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  child.on("error", (e) => resolve({ status: -1, stdout, stderr: stderr + String(e) }));
  child.on("close", (status) => resolve({ status, stdout, stderr }));
});

const setupEvidenceRow = () =>
  JSON.parse(readFileSync(join(REPO, "evidence", `setup-${date()}.jsonl`), "utf8").trim().split("\n").filter(Boolean).pop());

const tempHome = (kind) => mkdtempSync(join(tmpdir(), `ug-setup-${kind}-`));
// A brain with the real shape: the safe battery probe passes, the destructive one is stopped.
const chooser = (body) => (/rm -rf/.test(body?.state?.input?.command ?? "") ? "deny" : "allow");

test("setup claude, fresh home + simulated brain: exit 0, five GREEN/PENDING sections, empty 0600 store with one init row, one evidence row", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const r = await setup(childEnv({ home, guardHome, brainUrl: brain.url }));
    assert.equal(r.status, 0, `exit ${r.status}, stderr: ${r.stderr}`);
    const out = r.stdout;
    // five fixed sections, one line each, in order, with explicit status words
    const at = ["backend", "registration", "rulings", "verification", "calibration"].map((s) => out.indexOf(`\n${s}: `));
    assert.ok(at.every((i) => i >= 0), out);
    assert.deepEqual(at, [...at].sort((a, b) => a - b), out);
    assert.match(out, /backend: GREEN \(local http:\/\/127\.0\.0\.1:\d+\)/);
    assert.match(out, /registration: GREEN \([^\n]*\.claude[/\\]settings\.json\)/);
    assert.match(out, /rulings: GREEN \(empty store created, 0600\)/);
    assert.match(out, /verification: GREEN/);
    assert.match(out, /calibration: PENDING \(entry 2\.5\)/);
    assert.match(out, /evidence: evidence\/setup-\d{4}-\d{2}-\d{2}\.jsonl/);
    // the chain really ran: the destructive probe crossed the simulated brain, classified only.
    // The safe probe (git status) no longer does — it is standing-allowed in the rules layer
    // (operator ruling 2026-10-08) and skips the classifier entirely; that IS the verified behavior.
    assert.equal(brain.requests.filter((q) => q.kind === "action").length, 1, JSON.stringify(brain.requests));
    // the stranger-owned store: [] at 0600 with exactly one paired init audit row
    const store = join(guardHome, "rulings.json");
    assert.equal(statSync(store).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(readFileSync(store, "utf8")), []);
    const rows = readFileSync(join(guardHome, "rulings-use.jsonl"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].action, "init");
    // registration really landed in the temp HOME, one entry per event (install's idempotence shape)
    const cfg = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8"));
    for (const [ev, groups] of Object.entries(cfg.hooks)) assert.equal(groups.length, 1, ev);
    // exactly one topology-free evidence row: status words only — no URL, no host, no paths
    const row = setupEvidenceRow();
    assert.deepEqual(row, { at: row.at, command: "setup", harness: "claude", exit: 0,
      sections: { backend: "GREEN", registration: "GREEN", rulings: "GREEN", verification: "GREEN", calibration: "PENDING" } });
    assert.ok(!/127\.0\.0\.1|http|\/tmp|ug-setup/.test(JSON.stringify(row)), JSON.stringify(row));
  } finally { restore(); await brain.close(); }
});

test("no backend anywhere: backend RED with the key hint, every other section still completes, exit 1", async () => {
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const r = await setup(childEnv({ home, guardHome }));
    assert.equal(r.status, 1, `exit ${r.status}, stderr: ${r.stderr}`);
    const out = r.stdout;
    assert.match(out, /backend: RED — no brain configured \(set SYSTEMONE_URL/);
    assert.match(out, /registration: GREEN/);
    assert.match(out, /rulings: GREEN/);
    // with no brain, the safe probe passes via the standing rules allow and the destructive one
    // degrades to the floor's deny — the checks complete and the section reads GREEN; the backend
    // line is what tells the operator the brain is absent (exit 1 comes from backend RED)
    assert.match(out, /verification: GREEN/);
    assert.match(out, /calibration: PENDING \(entry 2\.5\)/);
    const row = setupEvidenceRow();
    assert.equal(row.exit, 1);
    assert.equal(row.sections.backend, "RED");
    assert.equal(row.sections.calibration, "PENDING");
  } finally { restore(); }
});

test("repeat setup on the same home: install idempotent, initStore a no-op, exit still matches the sections", async () => {
  const brain = await startScenarioBrain(chooser);
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const env = childEnv({ home, guardHome, brainUrl: brain.url });
    assert.equal((await setup(env)).status, 0);
    const auditBefore = readFileSync(join(guardHome, "rulings-use.jsonl"), "utf8");
    const r2 = await setup(env);
    assert.equal(r2.status, 0, `exit ${r2.status}, stderr: ${r2.stderr}`);
    assert.match(r2.stdout, /rulings: GREEN \(store already present, 0600\)/);
    // no second init audit row — the store's pairing history is untouched
    assert.equal(readFileSync(join(guardHome, "rulings-use.jsonl"), "utf8"), auditBefore);
    const cfg = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8"));
    for (const [ev, groups] of Object.entries(cfg.hooks)) assert.equal(groups.length, 1, ev);
    assert.equal(setupEvidenceRow().exit, 0);
  } finally { restore(); await brain.close(); }
});

test("a mislabeled probe: verification RED, exit 1, evidence row still written", async () => {
  const brain = await startScenarioBrain(() => "allow");  // the destructive battery probe is answered allow
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const r = await setup(childEnv({ home, guardHome, brainUrl: brain.url }));
    assert.equal(r.status, 1, `exit ${r.status}, stderr: ${r.stderr}`);
    assert.match(r.stdout, /verification: RED \(live-verify exited 2\)/);
    assert.match(r.stdout, /FAIL must-stop/);  // live-verify's own probe line
    const row = setupEvidenceRow();
    assert.equal(row.exit, 1);
    assert.equal(row.sections.verification, "RED");
  } finally { restore(); await brain.close(); }
});

test("unknown target: hard usage error, exit 3, nothing written", async () => {
  const home = tempHome("home"), guardHome = tempHome("guard");
  const restore = evidenceGuard();
  try {
    const r = await setup(childEnv({ home, guardHome }), "not-a-harness");
    assert.equal(r.status, 3);
    assert.match(r.stderr, /setup target must be one of/);
    assert.ok(!existsSync(join(guardHome, "rulings.json")), "no store before target validation");
  } finally { restore(); }
});
