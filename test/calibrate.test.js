// Calibration probe (epic-installer ticket 5): spawn-based tests for `calibrate` over the
// plan's I/O matrix — the certifying brain, the mislabeled brain, a dead port, the bare env
// and the config-only backend. Isolation follows setup.test.js's recipes: whitelisted child
// env (fresh temp HOME, nothing from the operator's shell), the conformance brain's
// simulated loopback server behind SYSTEMONE_URL with a per-request scenario chooser,
// Connection: close, async spawn — no test touches a live brain or the operator's real
// state. A simulated-brain run must not leave evidence rows in the repo, so every append to
// evidence/calibrate-<date>.jsonl is subtract-only restored (multiplicity-aware).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { brainAnswer, classifyRequest } from "../tools/conformance/brain.mjs";
import { BATTERY } from "../tools/battery.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const date = () => new Date().toISOString().slice(0, 10);
const evidenceFile = () => join(REPO, "evidence", `calibrate-${date()}.jsonl`);
const cmdExpect = new Map(BATTERY.map((c) => [c.cmd, c.expect]));
// Class counts, computed from the live corpus — their 7.2 grew the battery (+18 rows) and it
// will grow again; hardcoded fractions here broke exactly that way once already.
const classCounts = (() => { const c = { safe: 0, destructive: 0, tricky: 0 }; for (const x of BATTERY) c[x.expect]++; return c; })();
const frac = (pass, n) => `${pass}/${n}`;
const ASK_NOTE = "\\(environment-sensitive — never gates\\)";
// The certifying brain's summary line, computed from the live corpus: every class full.
const fullLine = new RegExp(`safe ${frac(classCounts.safe, classCounts.safe)} · destructive ${frac(classCounts.destructive, classCounts.destructive)} · tricky ${frac(classCounts.tricky, classCounts.tricky)} · ask-band 0 ${ASK_NOTE}`);
const FULL_ROW = { safe: frac(classCounts.safe, classCounts.safe), destructive: frac(classCounts.destructive, classCounts.destructive), tricky: frac(classCounts.tricky, classCounts.tricky) };

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
      // Connection: close — without it the spawned CLI lingers on undici's keep-alive socket
      // until the server's idle timeout, and every probe costs the idle delay.
      res.writeHead(200, { "content-type": "application/json", connection: "close" });
      res.end(JSON.stringify(brainAnswer(body, choose(body))));
    });
  });
  await new Promise((res, rej) => { server.once("error", rej); server.listen(0, "127.0.0.1", res); });
  return { url: `http://127.0.0.1:${server.address().port}`, requests, close: () => new Promise((r) => server.close(r)) };
}

// The certifying brain: safe battery commands resolve allow, everything else is contained.
const certifying = (body) => (cmdExpect.get(body?.state?.input?.command ?? "") === "safe" ? "allow" : "deny");

// A whitelisted child env: no operator credentials, no legacy JEV_* names, no GUARD_* tuning.
// HOME is this test's fresh temp dir, so no operator config file is read unless the test
// writes one there.
function childEnv({ home, brainUrl, timeoutMs } = {}) {
  return {
    PATH: process.env.PATH,
    ...(home ? { HOME: home } : {}),
    ...(brainUrl ? { SYSTEMONE_URL: brainUrl, SYSTEMONE_KEY: "test-key" } : {}),
    ...(timeoutMs ? { GUARD_TIMEOUT_MS: String(timeoutMs) } : {}),
  };
}

// Async spawn, not spawnSync: the simulated brain serves from THIS process, and a sync wait
// would block its event loop — the spawned CLI's brain requests would queue behind the wait
// and die on the guard budget. Awaiting the child keeps the loop free to answer.
const calibrate = (args, env) => new Promise((resolve) => {
  const child = spawn(process.execPath, ["src/cli.js", "calibrate", ...args], { cwd: REPO, env });
  let stdout = "", stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  child.on("error", (e) => resolve({ status: -1, stdout, stderr: stderr + String(e) }));
  child.on("close", (status) => resolve({ status, stdout, stderr }));
});

// Subtract-only restore of the calibrate evidence file (setup.test.js's evidenceGuard
// pattern, narrowed to the one file this suite can touch): drops exactly the lines this run
// appended (multiplicity-aware diff against the snapshot) and leaves every line that was
// already in the file — a concurrent session's rows included — untouched.
function evidenceGuard() {
  const f = evidenceFile();
  const before = existsSync(f) ? readFileSync(f, "utf8") : null;
  return () => {
    if (!existsSync(f)) return;
    if (before === null) { rmSync(f, { force: true }); return; }  // this run created the file
    const now = readFileSync(f, "utf8");
    if (now === before) return;
    const counts = new Map();
    for (const l of before.split("\n")) counts.set(l, (counts.get(l) ?? 0) + 1);
    const kept = now.split("\n").filter((l) => {
      const c = counts.get(l) ?? 0;
      if (c > 0) { counts.set(l, c - 1); return true; }  // a snapshot line (or a duplicate of one): keep
      return false;                                       // appended during the run: subtract
    });
    if (kept.join("\n") !== now) writeFileSync(f, kept.join("\n"));
  };
}

const lastRow = () => JSON.parse(readFileSync(evidenceFile(), "utf8").trim().split("\n").filter(Boolean).pop());
const tempHome = () => mkdtempSync(join(tmpdir(), "ug-calibrate-"));

// Grab a port from the kernel and give it straight back: the caller wants a port nothing
// listens on (the dead-port test).
async function freePort() {
  const { createServer } = await import("node:http");
  const s = createServer();
  await new Promise((res) => s.listen(0, "127.0.0.1", res));
  const { port } = s.address();
  await new Promise((res) => s.close(res));
  return port;
}

test("certifying brain (--url --key): exit 0, every class full, ask-band note, one topology-free evidence row", async () => {
  const brain = await startScenarioBrain(certifying);
  const home = tempHome();
  const restore = evidenceGuard();
  try {
    const r = await calibrate(["--url", brain.url, "--key", "test-key"], childEnv({ home }));
    assert.equal(r.status, 0, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stdout, fullLine);
    assert.match(r.stdout, /OK: certified — every class full/);
    assert.match(r.stdout, /evidence: evidence\/calibrate-\d{4}-\d{2}-\d{2}\.jsonl/);
    // the probe really asked the wire: one request per case, each carrying an action question set
    assert.equal(brain.requests.length, BATTERY.length, JSON.stringify(brain.requests));
    assert.ok(brain.requests.every((q) => q.kind === "action"), JSON.stringify(brain.requests[0]));
    // exactly one topology-free evidence row: status words and counts only — no URL, no host, no key
    const row = lastRow();
    assert.deepEqual(row, { at: row.at, command: "calibrate", endpoint: "configured",
      classes: FULL_ROW, askBand: 0, exit: 0 });
    assert.ok(!/127\.0\.0\.1|http|test-key|\/tmp/.test(JSON.stringify(row)), JSON.stringify(row));
  } finally { restore(); await brain.close(); rmSync(home, { recursive: true, force: true }); }
});

test("mislabeled brain (allows everything): exit 1 naming the case ids, evidence row still written", async () => {
  const brain = await startScenarioBrain(() => "allow");
  const home = tempHome();
  const restore = evidenceGuard();
  try {
    const r = await calibrate(["--url", brain.url], childEnv({ home }));
    assert.equal(r.status, 1, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stdout, new RegExp(`safe ${frac(classCounts.safe, classCounts.safe)} · destructive ${frac(0, classCounts.destructive)} · tricky ${frac(0, classCounts.tricky)} · ask-band 0`));
    assert.match(r.stdout, /MISS: must deny/);
    assert.match(r.stdout, /FAIL: .*d1 \(destructive\)/);
    const row = lastRow();  // the row lands even on a failed certification
    assert.equal(row.exit, 1);
    assert.equal(row.classes.destructive, "0/9");
  } finally { restore(); await brain.close(); rmSync(home, { recursive: true, force: true }); }
});

test("all-ask brain: ask-band rows never hard-fail (exit 0, sensitivity note, misses named)", async () => {
  const brain = await startScenarioBrain(() => "ask");
  const home = tempHome();
  const restore = evidenceGuard();
  try {
    const r = await calibrate(["--url", brain.url, "--quick"], childEnv({ home }));
    assert.equal(r.status, 0, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stdout, /safe 0\/1 · destructive 0\/1 · tricky 1\/1 · ask-band 3 \(environment-sensitive — never gates\)/);
    assert.match(r.stdout, /OK: no fatal miss/);
    assert.equal(lastRow().askBand, 3);
  } finally { restore(); await brain.close(); rmSync(home, { recursive: true, force: true }); }
});

test("dead port: one clean line naming the failure, exit 1, no stack, no evidence row", async () => {
  const home = tempHome();
  const restore = evidenceGuard();
  const f = evidenceFile();
  const before = existsSync(f) ? readFileSync(f, "utf8") : null;
  const isDead = (x) => x.status === 1
    && x.stderr.trim().split("\n").length === 1
    && /^Unjangled Guardrails: calibrate: brain unreachable — /.test(x.stderr.trim());
  try {
    // a port nothing listens on: grab one from the kernel, then give it back. A released
    // port can be claimed by another process inside the race window, so any outcome
    // inconsistent with "dead" retries the whole probe once against a freshly grabbed
    // port — the assertion only fails if two consecutive grabs both lose the race.
    const probe = async () => calibrate(["--url", `http://127.0.0.1:${await freePort()}`, "--quick"], childEnv({ home, timeoutMs: 1500 }));
    let r = await probe();
    if (!isDead(r)) r = await probe();
    assert.ok(isDead(r), `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.ok(!/\n\s+at /.test(r.stderr), r.stderr);  // no stack
    // a transport failure certifies nothing, so it leaves no artifact
    const after = existsSync(f) ? readFileSync(f, "utf8") : null;
    assert.equal(after, before, "no evidence row for a run that never ran");
  } finally { restore(); rmSync(home, { recursive: true, force: true }); }
});

test("bare env: only SYSTEMONE_URL/SYSTEMONE_KEY set, no flags — calibrates that endpoint", async () => {
  const brain = await startScenarioBrain(certifying);
  const home = tempHome();
  const restore = evidenceGuard();
  try {
    const r = await calibrate([], childEnv({ home, brainUrl: brain.url }));
    assert.equal(r.status, 0, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stdout, fullLine);
    assert.equal(brain.requests.length, BATTERY.length);
    assert.equal(lastRow().exit, 0);
  } finally { restore(); await brain.close(); rmSync(home, { recursive: true, force: true }); }
});

test("config-only backend: no env creds, localBaseUrl in the temp HOME's config file — same as bare env", async () => {
  const brain = await startScenarioBrain(certifying);
  const home = tempHome();
  mkdirSync(join(home, ".unjangled-guardrails"), { recursive: true });
  writeFileSync(join(home, ".unjangled-guardrails", "config.json"), JSON.stringify({ localBaseUrl: brain.url, localApiKey: "cfg-key" }));
  const restore = evidenceGuard();
  try {
    const r = await calibrate([], childEnv({ home }));  // no SYSTEMONE_URL anywhere in the child env
    assert.equal(r.status, 0, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stdout, fullLine);
    assert.equal(brain.requests.length, BATTERY.length, "the config-file backend served every case");
    assert.equal(lastRow().exit, 0);
  } finally { restore(); await brain.close(); rmSync(home, { recursive: true, force: true }); }
});

test("partial brain (risk only on d1/t4): the gate's own malformed-answer bar — destructive fatal, tricky a named miss, exit 1", async () => {
  const home = tempHome();
  const restore = evidenceGuard();
  const { createServer } = await import("node:http");
  // full, well-formed answers for the safe probe; risk-only for everything else — the shape
  // decide()'s ??-defaults would silently score but the real gate throws on (TR-2)
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      const body = JSON.parse(raw);
      res.writeHead(200, { "content-type": "application/json", connection: "close" });
      res.end(JSON.stringify(body?.state?.input?.command === "git status"
        ? brainAnswer(body, "allow")
        : { answers: { risk: { type: "score", score: 3.0, probabilities: {}, confidence: 0.8 } } }));
    });
  });
  await new Promise((res, rej) => { server.once("error", rej); server.listen(0, "127.0.0.1", res); });
  try {
    const r = await calibrate(["--url", `http://127.0.0.1:${server.address().port}`, "--quick"], childEnv({ home }));
    assert.equal(r.status, 1, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stdout, /malformed answer: missing approval, user_requested, from_untrusted, leaks_secrets/);
    assert.match(r.stdout, /safe 1\/1 · destructive 0\/1 · tricky 0\/1/);
    assert.match(r.stdout, /FAIL: .*d1 \(destructive\)/);  // unanswered destructive is fatal, like an allow
    const row = lastRow();
    assert.equal(row.exit, 1);
  } finally {
    restore();
    await new Promise((res) => server.close(res));
    rmSync(home, { recursive: true, force: true });
  }
});

test("no backend anywhere: 'no backend configured' reads differently from a transport failure, exit 1, no evidence row", async () => {
  const home = tempHome();
  const restore = evidenceGuard();
  const f = evidenceFile();
  const before = existsSync(f) ? readFileSync(f, "utf8") : null;
  try {
    const r = await calibrate(["--quick"], childEnv({ home }));  // no SYSTEMONE_* and a fresh HOME: nothing configured anywhere
    assert.equal(r.status, 1, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stderr, /Unjangled Guardrails: calibrate: no backend configured — set SYSTEMONE_URL/);
    const after = existsSync(f) ? readFileSync(f, "utf8") : null;
    assert.equal(after, before, "no evidence row");
  } finally { restore(); rmSync(home, { recursive: true, force: true }); }
});

test("--key without --url: hard usage error, nothing calibrated", async () => {
  const home = tempHome();
  try {
    const r = await calibrate(["--key", "some-key"], childEnv({ home }));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /--key requires --url/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("bad usage: a flag without a value is a hard usage error, nothing calibrated", async () => {
  const home = tempHome();
  try {
    const r = await calibrate(["--url"], childEnv({ home }));
    assert.equal(r.status, 1);
    assert.match(r.stderr, /calibrate --url needs a value/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
