// Ticket 4 (epic-adapter-dual-entry): per-host adapter content at install time.
// `install opencode` (default) keeps writing the v1 adapter byte-identical to the pre-ticket bytes;
// `--v2` writes the v2 adapter (default-exports UnjangledGuardrailsV2 — the {id, setup} form the
// v2.0.24 loader accepts). The --home override targets a COPY of the committed fixture
// (test/fixtures/opencode-v2-home); the real HOME is snapshotted and asserted untouched.
// Story 1 (epic-host-isolation): install-time state-ownership detection — before writing, the
// existing adapter in EITHER scanned plugin dir fingerprints its generation; a mismatched or
// ambiguous takeover is refused until --force, which writes anyway with the warning printed.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { installFor } from "../src/install.js";
import { UnjangledGuardrailsV2 } from "../src/opencode.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(REPO, "test", "fixtures", "opencode-v2-home");
const ADAPTER = "unjangled-guardrails.js";

// Whole-fixture integrity: every relative path + a content hash, flattened to one string.
// Snapshotted at module load (before any test can write) and asserted unchanged once, after
// the whole run — all subdirectories and file contents, not just one subdir's names.
const fixtureSnap = () => {
  const out = [];
  const walk = (dir, rel) => {
    for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (e.isDirectory()) walk(join(dir, e.name), join(rel, e.name));
      else out.push(`${join(rel, e.name)}:${createHash("sha256").update(readFileSync(join(dir, e.name))).digest("hex").slice(0, 16)}`);
    }
  };
  walk(FIXTURE, "");
  return out.join("\n");
};
const FIXTURE_SNAPSHOT = fixtureSnap();

// The pinned byte contracts. These are duplicated here ON PURPOSE: src/install.js holds the
// live templates, this file holds the contract — an accidental edit to either side fails here.
// v1: named re-export only (1.x's loader treats every export as a plugin function — no default).
// v2: default-exported {id, setup} definition (v2.0.24 rejects a named re-export with
// SchemaError(Missing key at ["default"]) — evidence/opencode-v2-plugin-loading-probe-2026-10-07.md).
const V1_ADAPTER = (root) => `export { UnjangledGuardrails } from ${JSON.stringify(join(root, "src", "opencode.js"))};\n`;
const V2_ADAPTER = (root) => `import { UnjangledGuardrailsV2 } from ${JSON.stringify(join(root, "src", "opencode.js"))};\nexport default UnjangledGuardrailsV2;\n`;

let scratch;
const freshHome = () => {
  const copy = join(scratch, `home-${Math.random().toString(36).slice(2)}`);
  cpSync(FIXTURE, copy, { recursive: true });
  return copy;
};

// Ownership-detection fixtures (story 1). Planted adapters reuse install's own templates — the
// fingerprint must classify the real shapes, not lookalikes. CFG_DIR is the dir install writes;
// ALT_DIR (~/.opencode/plugins) is the second scanned root, where a v1-owned marker can
// equally sit (plugin-loading probe Q1/run 4: both dirs scanned, dedupe by plugin id).
const CFG_DIR = join(".config", "opencode", "plugins");
const ALT_DIR = join(".opencode", "plugins");
const V1_TEXT = V1_ADAPTER(REPO);
const V2_TEXT = V2_ADAPTER(REPO);
const FOREIGN_ADAPTER = "module.exports = { notAGuard: true };\n";
const plant = (home, dir, text) => {
  mkdirSync(join(home, dir), { recursive: true });
  writeFileSync(join(home, dir, ADAPTER), text);
};

// Real-HOME guard: snapshot BOTH scanned plugin dirs (entry names + mtimes per dir) — detection
// now reads ~/.opencode/plugins as well as ~/.config/opencode/plugins, so a leak into the
// alternate dir must be caught too. A missing dir is recorded as an absent marker, so a newly
// created dir fails the snapshot equally. Installs here always go through --home, so any delta
// means the override leaked to the real profile.
const REAL_PLUGIN_DIRS = [join(homedir(), ".config", "opencode", "plugins"), join(homedir(), ".opencode", "plugins")];
let realHomeSnap;
let realCfgAbsent;
const snapHome = () => REAL_PLUGIN_DIRS
  .map((dir) => (existsSync(dir)
    ? `${dir}:${readdirSync(dir).map((f) => `${f}:${statSync(join(dir, f)).mtimeMs}`).sort().join(",")}`
    : `${dir}:absent`))
  .join("\n");

before(() => {
  scratch = mkdtempSync(join(tmpdir(), "unjangled-guardrails-install-"));
  realHomeSnap = snapHome();
  realCfgAbsent = !existsSync(REAL_PLUGIN_DIRS[0]);
});
after(() => {
  rmSync(scratch, { recursive: true, force: true });
  assert.deepEqual(snapHome(), realHomeSnap, "real HOME changed during install tests");
  assert.equal(fixtureSnap(), FIXTURE_SNAPSHOT, "the committed fixture tree changed during the test run (paths or contents)");
});

test("install opencode (default) writes the v1 adapter byte-identical to the pinned contract, inside the --home copy", () => {
  const home = freshHome();
  const { file, note } = installFor("opencode", { log: () => {}, home });
  assert.equal(file, join(home, ".config", "opencode", "plugins", ADAPTER));
  // epic-installer ticket 7: the default output is silent on the permission topic — the
  // recommendation moved behind --ask-permissions (opt-in, with its tradeoff printed there).
  assert.ok(!note.includes("permission") && !note.includes('"bash"') && !note.includes("approval prompts"),
    `the default install output must carry no permission-ask recommendation (got: ${note})`);
  const bytes = readFileSync(file);
  assert.deepEqual(bytes, Buffer.from(V1_ADAPTER(REPO)), "v1 adapter bytes drifted from the pinned contract");
  assert.ok(!bytes.includes("export default"), "v1 adapter must not carry a default export (1.x loader throws on object exports)");
  // fixture integrity is not re-checked per test: installs here target copies only, and the
  // whole-tree snapshot is asserted once after the run (see after())
});

test("install opencode --v2 writes the v2 adapter, which dynamic-imports and default-exports UnjangledGuardrailsV2", async () => {
  const home = freshHome();
  const { file } = installFor("opencode", { log: () => {}, v2: true, home });
  assert.equal(file, join(home, ".config", "opencode", "plugins", ADAPTER), "same filename as v1: one host = one adapter");
  const bytes = readFileSync(file);
  assert.deepEqual(bytes, Buffer.from(V2_ADAPTER(REPO)), "v2 adapter bytes drifted from the pinned contract");
  // the written adapter resolves and default-exports exactly the module's V2 definition
  const adapter = await import(pathToFileURL(file).href);
  assert.equal(adapter.default, UnjangledGuardrailsV2, "the adapter's default export must be the module's UnjangledGuardrailsV2 object");
  assert.equal(adapter.default.id, "unjangled-guardrails");
  assert.equal(typeof adapter.default.setup, "function");
});

test("install is idempotent: rewriting either variant reproduces identical bytes, and --v2 replaces the v1 adapter in place (--force: it is a detected mismatch)", () => {
  const home = freshHome();
  const file = join(home, ".config", "opencode", "plugins", ADAPTER);
  installFor("opencode", { log: () => {}, home });
  const v1Once = readFileSync(file);
  installFor("opencode", { log: () => {}, home });
  assert.deepEqual(readFileSync(file), v1Once, "v1 rewrite produced different bytes (the v1-empty-diff criterion)");
  // switching generation inside one HOME is exactly the mismatch the ownership gate exists for:
  // refused without --force, and the refusal leaves the v1 adapter byte-identical
  assert.throws(() => installFor("opencode", { log: () => {}, v2: true, home }), /--force/);
  assert.deepEqual(readFileSync(file), v1Once, "the refused switch must not have touched the v1 adapter");
  installFor("opencode", { log: () => {}, v2: true, home, force: true });
  assert.deepEqual(readFileSync(file), Buffer.from(V2_ADAPTER(REPO)), "--v2 must replace the v1 adapter at the same path");
  installFor("opencode", { log: () => {}, v2: true, home, force: true });
  assert.deepEqual(readFileSync(file), Buffer.from(V2_ADAPTER(REPO)), "v2 rewrite produced different bytes");
});

test("--home creates a missing tree from scratch (fixture layout without the fixture) and never touches the real HOME", () => {
  const home = join(scratch, "home-from-nothing");
  const { file } = installFor("opencode", { log: () => {}, v2: true, home });
  assert.equal(readFileSync(file, "utf8"), V2_ADAPTER(REPO));
  if (realCfgAbsent) {
    // operator has no opencode plugins dir: the strongest form of the guard — install must not have created one
    assert.equal(existsSync(join(homedir(), ".config", "opencode", "plugins", ADAPTER)), false);
  }
});

test("installFor stays a plain import: setup options are additive (existing {log} callers unaffected)", () => {
  const home = freshHome();
  const lines = [];
  const { file } = installFor("opencode", { home, log: (m) => lines.push(m) });
  assert.equal(readFileSync(file, "utf8"), V1_ADAPTER(REPO));
  assert.ok(lines.some((l) => l.includes(file)), "install logs the written path");
});

// ── story 1 (epic-host-isolation): install-time state-ownership detection ────────────────────

test("matching generation writes as today: a v1 adapter already in place rewrites silently (no ownership warning)", () => {
  const home = freshHome();
  const file = join(home, CFG_DIR, ADAPTER);
  plant(home, CFG_DIR, V1_TEXT);
  const lines = [];
  installFor("opencode", { home, log: (m) => lines.push(m) });
  assert.deepEqual(readFileSync(file), Buffer.from(V1_TEXT), "a matching-generation rewrite must not change the adapter bytes");
  assert.ok(!lines.some((l) => l.includes("WARNING")), "no ownership warning for a matching-generation install");
});

test("matching generation (v2 over v2) writes as today", () => {
  const home = freshHome();
  const file = join(home, CFG_DIR, ADAPTER);
  plant(home, CFG_DIR, V2_TEXT);
  const lines = [];
  installFor("opencode", { home, v2: true, log: (m) => lines.push(m) });
  assert.deepEqual(readFileSync(file), Buffer.from(V2_TEXT));
  assert.ok(!lines.some((l) => l.includes("WARNING")));
});

test("mismatch refused: a v1 adapter in the ALTERNATE plugin dir blocks a --v2 write, and nothing is written", () => {
  const home = freshHome();
  plant(home, ALT_DIR, V1_TEXT);  // the other scanned root: a v1-owned marker can sit there
  const cfgAdapter = join(home, CFG_DIR, ADAPTER);
  assert.throws(() => installFor("opencode", { home, v2: true, log: () => {} }), (e) => {
    assert.match(e.message, /--force/, "the refusal names the override flag");
    assert.match(e.message, /v1 adapter/, "the refusal names the generation it found");
    assert.ok(e.message.includes(join(home, ALT_DIR, ADAPTER)), "the refusal names the file it found");
    return true;
  });
  assert.equal(existsSync(cfgAdapter), false, "a refused install must not write the other generation's adapter");
});

test("mismatch refused: a v2 adapter under the primary dir blocks a default (v1) write, v2 bytes untouched", () => {
  const home = freshHome();
  const file = join(home, CFG_DIR, ADAPTER);
  plant(home, CFG_DIR, V2_TEXT);
  assert.throws(() => installFor("opencode", { home, log: () => {} }), /--force/);
  assert.deepEqual(readFileSync(file), Buffer.from(V2_TEXT), "the refused v1 takeover must not touch the v2 adapter");
});

test("--force writes the mismatched adapter anyway, with exactly one warning printed", () => {
  const home = freshHome();
  const file = join(home, CFG_DIR, ADAPTER);
  plant(home, CFG_DIR, V1_TEXT);
  const lines = [];
  installFor("opencode", { home, v2: true, force: true, log: (m) => lines.push(m) });
  assert.deepEqual(readFileSync(file), Buffer.from(V2_TEXT), "--force must write the requested generation");
  const warn = lines.filter((l) => l.includes("WARNING"));
  assert.equal(warn.length, 1, `exactly one ownership warning expected (got ${warn.length})`);
  assert.ok(warn[0].includes("v1"), "the warning names the generation it is overwriting");
  assert.ok(lines.some((l) => l.includes(file)), "the forced run still reports the written path");
});

test("ambiguous ownership refused: both generations present, and an unrecognized foreign adapter (detection never touches it)", () => {
  const home = freshHome();
  plant(home, CFG_DIR, V2_TEXT);
  plant(home, ALT_DIR, V1_TEXT);
  assert.throws(() => installFor("opencode", { home, v2: true, log: () => {} }), /ambiguous/, "mixed-generation signals must refuse");
  const foreign = freshHome();
  const foreignFile = join(foreign, CFG_DIR, ADAPTER);
  plant(foreign, CFG_DIR, FOREIGN_ADAPTER);
  assert.throws(() => installFor("opencode", { home: foreign, log: () => {} }), (e) => {
    assert.match(e.message, /--force/);
    assert.match(e.message, /unrecognized shape/);
    return true;
  });
  assert.deepEqual(readFileSync(foreignFile), Buffer.from(FOREIGN_ADAPTER), "detection only: the foreign adapter is never rewritten");
});

// CLI plumbing (spawn through src/cli.js, detect.test.js's child-env recipe): --force parsed in
// the install case, the refusal surfaced as exit 1, the forced run green with its warning.
const childEnv = (home) => ({ PATH: process.env.PATH, HOME: home });
const runCli = (args, env) => new Promise((res) => {
  const child = spawn(process.execPath, ["src/cli.js", ...args], { cwd: REPO, env });
  let stdout = "", stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  child.on("error", (e) => res({ status: -1, stdout, stderr: stderr + String(e) }));
  child.on("close", (status) => res({ status, stdout, stderr }));
});

test("cli: install opencode --v2 over a v1 HOME exits 1 naming --force, then --force writes with the warning", async () => {
  const home = freshHome();
  plant(home, CFG_DIR, V1_TEXT);
  const refused = await runCli(["install", "opencode", "--v2", "--home", home], childEnv(home));
  assert.equal(refused.status, 1, refused.stderr);
  assert.match(refused.stderr, /--force/);
  assert.deepEqual(readFileSync(join(home, CFG_DIR, ADAPTER)), Buffer.from(V1_TEXT), "the refused CLI run wrote nothing");
  const forced = await runCli(["install", "opencode", "--v2", "--force", "--home", home], childEnv(home));
  assert.equal(forced.status, 0, forced.stderr);
  assert.match(forced.stdout, /WARNING/);
  assert.deepEqual(readFileSync(join(home, CFG_DIR, ADAPTER)), Buffer.from(V2_TEXT), "--force wrote the v2 adapter");
});

// Not an install concern, but load-bearing for the v2 adapter's validity: the module keeps its
// no-default-export ponytail (hook.test.js asserts it too) — repeated here so a future default
// export cannot silently ride along under the v2 adapter without a test failing.
test("src/opencode.js has no module-level default export (the v2 adapter must own the default)", async () => {
  assert.equal((await import("../src/opencode.js")).default, undefined);
});
