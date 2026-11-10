// Ticket 3 (epic-installer): harness detection for targetless install/setup — the plan's I/O
// matrix as ran-and-passed tests. Two layers: detectHarness() directly over temp HOMEs and env
// objects, and spawn tests through src/cli.js so the CLI's resolution, announcement and loud
// failure paths are pinned end to end. Isolation follows the established recipes: setup.test.js's
// whitelisted child env and install.test.js's home fixtures. The whitelist matters doubly here —
// the operator's shell that runs this suite IS a Claude session, so an unfiltered process.env
// spread would leak its CLAUDECODE marker into every detection test and force the answer
// "claude". Registrations are created with installFor itself, so the detection table can only
// drift if writer and table drift apart — and that drift fails the all-targets pin below.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { candidateTable, detectHarness, registrations } from "../src/detect.js";
import { INSTALL_TARGETS, installFor } from "../src/install.js";
// The shared collision-proof evidence guard (ticket 1.20's sweep) — the local copy this file
// carried (an already-diverged comment on setup.test.js's recipe) folded into the one helper.
import { evidenceGuard } from "./evidence-guard.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const date = () => new Date().toISOString().slice(0, 10);

let scratch;
before(() => { scratch = mkdtempSync(join(tmpdir(), "ug-detect-")); });
after(() => rmSync(scratch, { recursive: true, force: true }));

const freshHome = () => mkdtempSync(join(scratch, "home-"));
// Create the registrations installFor itself writes — never hand-built lookalikes.
const seed = (home, targets) => {
  const files = {};
  for (const t of targets) files[t] = installFor(t, { log: () => {}, home }).file;
  return files;
};

// ── detectHarness: the env matrix + registration matrix ─────────────────────────────────────

test("matrix — CLAUDECODE wins: claude detected even with other registrations present", () => {
  const home = freshHome();
  seed(home, ["claude", "opencode"]);
  assert.deepEqual(detectHarness({ env: { CLAUDECODE: "1" }, home }), { target: "claude", signal: "env CLAUDECODE" });
});

test("matrix — one registration: that target, and the signal names the registration path", () => {
  const home = freshHome();
  const files = seed(home, ["opencode"]);
  assert.deepEqual(detectHarness({ env: {}, home }), { target: "opencode", signal: `registration ${files.opencode}` });
});

test("matrix — two registrations, no marker: ambiguous, both candidates carrying their paths", () => {
  const home = freshHome();
  const files = seed(home, ["claude", "opencode"]);
  const d = detectHarness({ env: {}, home });
  assert.ok(Array.isArray(d.ambiguous), JSON.stringify(d));
  assert.deepEqual(d.ambiguous.map((e) => e.target).sort(), ["claude", "opencode"]);
  for (const e of d.ambiguous) assert.equal(e.path, files[e.target]);
});

test("matrix — empty HOME (nothing registered, no marker): unknown", () => {
  assert.deepEqual(detectHarness({ env: {}, home: freshHome() }), { unknown: true });
});

test("an empty CLAUDECODE value is not the marker (truthiness, not presence)", () => {
  const home = freshHome();
  seed(home, ["opencode"]);
  assert.equal(detectHarness({ env: { CLAUDECODE: "" }, home }).target, "opencode");
});

test("the detection table is installFor's own paths — all seven targets, writer and table pinned together", () => {
  const home = freshHome();
  const files = seed(home, [...INSTALL_TARGETS]);
  const hits = registrations(home).filter((e) => existsSync(e.path));
  assert.deepEqual(hits.map((e) => e.target), [...INSTALL_TARGETS]);
  for (const e of hits) assert.equal(e.path, files[e.target]);
});

test("candidateTable: one line per candidate, target and path in aligned columns", () => {
  const t = candidateTable([{ target: "opencode", path: "/a" }, { target: "pi", path: "/b" }]);
  assert.deepEqual(t.split("\n"), ["  opencode  /a", "  pi        /b"]);  // both paths share column 12
});

// ── spawn tests through src/cli.js: install ──────────────────────────────────────────────────

// Whitelisted child env: PATH plus only what a test names. Nothing from the operator's shell
// (credentials, CLAUDECODE, legacy JEV_* names) can leak into a detection run.
const childEnv = ({ home, ...extra } = {}) => ({ PATH: process.env.PATH, ...(home ? { HOME: home } : {}), ...extra });

const runCli = (args, env) => new Promise((resolve) => {
  const child = spawn(process.execPath, ["src/cli.js", ...args], { cwd: REPO, env });
  let stdout = "", stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  child.on("error", (e) => resolve({ status: -1, stdout, stderr: stderr + String(e) }));
  child.on("close", (status) => resolve({ status, stdout, stderr }));
});

test("targetless install in a Claude session: claude announced with its signal despite other registrations", async () => {
  const home = freshHome();
  const files = seed(home, ["claude", "opencode"]);
  const adapterBefore = readFileSync(files.opencode);
  const r = await runCli(["install"], childEnv({ home, CLAUDECODE: "1" }));
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.includes("no target given — detected claude (env CLAUDECODE)"), r.stdout);
  // the claude registration really (re)written in the temp HOME, install's idempotence shape;
  // the sibling registration untouched — the env marker decides, nothing else is written
  const cfg = JSON.parse(readFileSync(files.claude, "utf8"));
  for (const [ev, groups] of Object.entries(cfg.hooks)) assert.equal(groups.length, 1, ev);
  assert.deepEqual(readFileSync(files.opencode), adapterBefore);
});

test("targetless install with exactly one registration: that target, signal names the path", async () => {
  const home = freshHome();
  const files = seed(home, ["opencode"]);
  const adapterBefore = readFileSync(files.opencode);
  const r = await runCli(["install"], childEnv({ home }));
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.includes(`no target given — detected opencode (registration ${files.opencode})`), r.stdout);
  assert.deepEqual(readFileSync(files.opencode), adapterBefore, "a re-detected install must stay idempotent");
});

test("ambiguous registrations, no marker: both candidates + paths on stderr, exit 1, nothing installed", async () => {
  const home = freshHome();
  const files = seed(home, ["claude", "opencode"]);
  const before = { claude: readFileSync(files.claude), opencode: readFileSync(files.opencode) };
  const r = await runCli(["install"], childEnv({ home }));
  assert.equal(r.status, 1);
  assert.ok(r.stderr.includes("refusing to guess"), r.stderr);
  assert.ok(r.stderr.includes(files.claude) && r.stderr.includes(files.opencode), r.stderr);
  assert.match(r.stderr, /ACP is configured in the editor/);
  assert.deepEqual(readFileSync(files.claude), before.claude, "ambiguous detection must not install anything");
  assert.deepEqual(readFileSync(files.opencode), before.opencode);
  assert.equal(existsSync(join(home, ".codex", "hooks.json")), false, "no other target gets written either");
});

test("empty HOME: the seven targets with their paths + the ACP note, exit 1, nothing written", async () => {
  const home = freshHome();
  const r = await runCli(["install"], childEnv({ home }));
  assert.equal(r.status, 1);
  for (const e of registrations(home)) assert.ok(r.stderr.includes(e.target) && r.stderr.includes(e.path), r.stderr);
  assert.match(r.stderr, /ACP is configured in the editor/);
  assert.deepEqual(readdirSync(home), [], "an unknown environment must not write anything under HOME");
});

test("install --home <relative-dir> in an unknown environment: header and every table row show the same resolved absolute tree", async () => {
  const relative = join("nonexistent", "detect-home");  // relative on purpose; nothing exists there, so detection says unknown
  const expected = resolve(REPO, relative);             // the spawned CLI's cwd is REPO, so this is the path that must print
  const r = await runCli(["install", "--home", relative], childEnv({ home: freshHome() }));
  assert.equal(r.status, 1);
  const lines = r.stderr.split("\n").filter((l) => l.includes(relative));
  assert.ok(lines.length >= 8, r.stderr);  // the header plus all seven candidate rows carry the tree
  for (const l of lines) assert.ok(l.includes(expected), `unresolved relative path printed: ${l}`);
});

test("explicit target never consults detection: install claude succeeds in an empty home with no marker", async () => {
  const home = freshHome();
  const r = await runCli(["install", "claude"], childEnv({ home }));
  assert.equal(r.status, 0, r.stderr);
  assert.ok(!r.stdout.includes("detected"), "detection must not be announced for an explicit target");
  assert.ok(existsSync(join(home, ".claude", "settings.json")));
});

test("explicit garbage target keeps today's hard error (explicit behavior unchanged)", async () => {
  const r = await runCli(["install", "bogus"], childEnv({ home: freshHome() }));
  assert.equal(r.status, 1);
  assert.match(r.stderr, /install target must be one of/);
});

test("--home retargets detection too: the single registration inside the given tree decides", async () => {
  const home = freshHome();
  const files = seed(home, ["opencode"]);
  const r = await runCli(["install", "--home", home], childEnv({ home: freshHome() }));  // decoy HOME: detection must use --home
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.includes(`detected opencode (registration ${files.opencode})`), r.stdout);
});

// ── spawn tests through src/cli.js: setup ────────────────────────────────────────────────────

const evidenceRow = () => {
  const f = join(REPO, "evidence", `setup-${date()}.jsonl`);
  const text = existsSync(f) ? readFileSync(f, "utf8") : "";
  return text.trim() ? JSON.parse(text.trim().split("\n").filter(Boolean).pop()) : null;  // a 0-byte file reads like an absent one
};

test("targetless setup: detection resolves the target before the chain runs (claude via its registration)", async () => {
  const home = freshHome();
  const files = seed(home, ["claude"]);
  const guardHome = freshHome();
  const restore = evidenceGuard();
  try {
    const r = await runCli(["setup"], childEnv({ home, GUARD_HOME: guardHome }));
    // no brain configured → backend RED gates the exit; every other section still completes
    assert.equal(r.status, 1, `stdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.ok(r.stdout.includes(`no target given — detected claude (registration ${files.claude})`), r.stdout);
    assert.match(r.stdout, /registration: GREEN \([^\n]*\.claude[/\\]settings\.json\)/);
    assert.equal(evidenceRow()?.harness, "claude");
  } finally { restore(); }
});

test("targetless setup with ambiguous registrations: candidates listed, exit 1, the chain never starts", async () => {
  const home = freshHome();
  const files = seed(home, ["claude", "opencode"]);
  const guardHome = freshHome();
  const restore = evidenceGuard();
  try {
    const rowBefore = evidenceRow();
    const r = await runCli(["setup"], childEnv({ home, GUARD_HOME: guardHome }));
    assert.equal(r.status, 1);
    assert.ok(r.stderr.includes("refusing to guess") && r.stderr.includes(files.claude) && r.stderr.includes(files.opencode), r.stderr);
    assert.equal(existsSync(join(guardHome, "rulings.json")), false, "no rulings store before a decided detection");
    assert.deepEqual(evidenceRow(), rowBefore, "no evidence row for a refused run");
  } finally { restore(); }
});
