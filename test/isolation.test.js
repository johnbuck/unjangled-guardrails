// Ticket 3 (epic-host-isolation): the committed isolation harness. The recorded
// bwrap+`--standalone` procedure (evidence/opencode-v2-plugin-loading-probe-2026-10-07.md,
// "Isolated-HOME procedure"; evidence/opencode-v2-install-probe-2026-10-08.md for the
// installed-adapter + marker-plugin shape; the launch.sh shape in the scans/gating probe
// artifact dirs) as an on-demand test: two legs inside a bind-mounted shadow HOME —
//
//   containment — a real v2 boot (binary COPY, ro-bound checkout, shadow HOME over the
//     real profile, --standalone MANDATORY, env -i scrub, 60s leash with one 90s retry on
//     spawn hang) must touch only its fixture copy: the real HOME's directory mtimes hold,
//     zero files newer than the watermark under the real plugin trees, the real state
//     tree's churn is attributed by a read-only live-DB zero-session query when a live DB
//     exists (mtime/shadow assertions carry the leg when it does not), and a marker plugin
//     (own plugin id, `zz-` sort-last pattern) records that the real adapter entered setup.
//   guard — entry 1's install-time ownership detection, exercised end-to-end through the
//     real CLI inside the same shadow shape: a v1-owned HOME copy refuses an unforced
//     `--v2` install with nothing written; `--force` writes the v2 adapter with exactly the
//     warning.
//
// Prerequisites are explicit and every absence records a clean SKIP, not a failure:
// bwrap(1) on PATH, timeout(1) on PATH, and the v2 binary at the path named by the
// GUARD_TEST_OPENCODE_V2 environment variable (never a hardcoded path — operators park
// binaries where they like, and no checkout may carry a machine-specific literal).
// The committed fixture is COPY-ONLY: every leg works on a temp copy (see
// test/fixtures/opencode-v2-home/README.md); the whole-tree snapshot is asserted
// unchanged after the run, and the real HOME's own snapshot likewise.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, lstatSync } from "node:fs";
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(REPO, "test", "fixtures", "opencode-v2-home");
const ADAPTER = "unjangled-guardrails.js";
const ADAPTER_DIR = join(".config", "opencode", "plugins");
const MARKER_PLUGIN = "zz-isolation-marker.js";
const MARKER_ID = "zz-isolation-marker";
const MARKER_PREFIX = "MARKER v2-setup-entered";
// The recorded working free model (launch.sh, scans/gating probe artifacts). The model
// call itself is POST-boot and its outcome is irrelevant: plugin evaluation and setup
// happen before it, and the marker + shadow log are complete by then (recorded rc=1
// "Model ... is not supported" runs are evidence-complete — expected, never a failure).
const MODEL = "opencode/ling-3.1-flash-free";
const PROMPT = "Reply with the single word ok and nothing else.";
const BIN_ENV_VAR = "GUARD_TEST_OPENCODE_V2";

// Prerequisites, resolved once. Each test records the same reason when one is missing.
const findInPath = (name) => {
  for (const dir of (process.env.PATH ?? "").split(":").filter(Boolean)) {
    const p = join(dir, name);
    if (existsSync(p)) return p;
  }
  return null;
};
const BWRAP = findInPath("bwrap");
const TIMEOUT = findInPath("timeout");
const V2_BIN = process.env[BIN_ENV_VAR];
const MISSING = !BWRAP ? "bwrap(1) not found on PATH — the isolated-HOME procedure cannot run"
  : !TIMEOUT ? "timeout(1) not found on PATH — the boot leash cannot be set"
  : !V2_BIN ? `${BIN_ENV_VAR} is not set (point it at an opencode v2 binary)`
  : !existsSync(V2_BIN) ? `${BIN_ENV_VAR} names a path that does not exist`
  : null;

// Whole-fixture integrity (COPY-ONLY rule): every relative path + content hash, flattened.
// Snapshotted at module load, asserted unchanged once after the whole run.
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

let scratch;          // the whole run's tree: bin/, repo bind target, per-leg homes, markers
let binCopy;          // fresh binary COPY per tree — the env-var binary may live under the home tree
const NS_REPO = () => join(scratch, "repo");   // where the checkout is ro-bound inside the namespace
const HOME = homedir();                        // shadowed over in every namespace; never a literal in this file

// The pinned adapter byte contracts, parameterized by the in-namespace checkout root. These
// are duplicated here ON PURPOSE (same rationale as install.test.js): src/install.js holds
// the live templates, this file holds the contract — an accidental edit to either side
// fails here. Inside the namespace the checkout is bound at scratch/repo, so the adapters
// install writes there embed that path.
const adapterText = (root, v2) => v2
  ? `import { UnjangledGuardrailsV2 } from ${JSON.stringify(join(root, "src", "opencode.js"))};\nexport default UnjangledGuardrailsV2;\n`
  : `export { UnjangledGuardrails } from ${JSON.stringify(join(root, "src", "opencode.js"))};\n`;

// The marker plugin: own plugin id (the v2 loader dedupes setup by id, so a colliding id
// would suppress one of the two setups), `zz-` sort-last name. Its setup imports the REAL
// module, calls its setup, and records what that proves — module import in-shadow, the
// exported shape, and that the loader dispatched THIS setup. It cannot prove the installed
// adapter's setup was dispatched: `context-stored=true` is circular on its own (the marker's
// manual setup call fills the store exactly as the adapter's dispatch would). The
// loader-level load proof is the containment leg's shadow-log assertions (loading-plugin
// line for the adapter, zero failed-to-load / SchemaError lines). Harness shape, not
// production shape: the manual setup call double-registers execute.before in the
// observation boot — a real HOME carries one adapter and no marker plugin.
const markerPluginSource = (nsRepo, markFile) => `import { UnjangledGuardrailsV2, getV2Context } from ${JSON.stringify(join(nsRepo, "src", "opencode.js"))};
import { appendFileSync } from "node:fs";
export default {
  id: ${JSON.stringify(MARKER_ID)},
  setup: (ctx) => {
    UnjangledGuardrailsV2.setup(ctx);
    appendFileSync(${JSON.stringify(markFile)}, ${JSON.stringify(`${MARKER_PREFIX} id=${MARKER_ID} `)} + "context-stored=" + (getV2Context() === ctx) + " keys=" + Object.keys(UnjangledGuardrailsV2).join("+") + "\\n");
  },
};
`;

// Child output may name the home path — nothing machine-specific may land in an assertion
// message, so every echoed fragment goes through the scrub.
const scrub = (text) => String(text ?? "").split(HOME).join("<home>");
const tail = (text, n = 240) => { const s = String(text ?? "").trimEnd(); return s.length <= n ? s : "…" + s.slice(-n); };
const firstLine = (text) => String(text ?? "").split("\n").find((l) => l.trim()) ?? "";

// Recursive newer-than-watermark file count (find <dir> -type f -newer <watermark>,
// lstat semantics like find's default: no symlink follow).
const countNewer = (dir, ms) => {
  let n = 0;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return 0; }  // absent dir counts zero
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) n += countNewer(p, ms);
    else {
      try { if (lstatSync(p).mtimeMs > ms) n += 1; } catch { /* raced away mid-walk: not newer */ }
    }
  }
  return n;
};

// Real-HOME state, snapshotted in before() and asserted after both legs (test 3).
const REAL_DIRS = {
  "config tree": join(HOME, ".config", "opencode"),
  "alternate plugin dir": join(HOME, ".opencode", "plugins"),
  "state tree": join(HOME, ".local", "share", "opencode"),
};
const snapDirMtimes = () => Object.entries(REAL_DIRS)
  .map(([k, d]) => `${k}=${existsSync(d) ? statSync(d).mtimeMs : "absent"}`).join("\n");
const LIVE_DB = join(REAL_DIRS["state tree"], "opencode.db");

let REAL_DIR_MTIMES = null;
let WATERMARK_MS = 0;
let LIVE_DB_AT_START = false;
let BOOT_CWD = null;  // the containment boot's cwd inside the throwaway tree (leg 3's attribution key)

before(() => {
  scratch = mkdtempSync(join(tmpdir(), "unjangled-guardrails-isolation-"));
  // the watermark goes down BEFORE anything else — every later mtime is judged against it
  const watermark = join(scratch, "watermark");
  writeFileSync(watermark, "");
  WATERMARK_MS = statSync(watermark).mtimeMs;
  REAL_DIR_MTIMES = snapDirMtimes();
  LIVE_DB_AT_START = existsSync(LIVE_DB);
  if (MISSING) return;  // a prerequisite is absent: the tests record the skip; nothing to prepare
  // fresh binary COPY per tree (recorded procedure step 1): the parked binary usually sits
  // under the home tree, where the shadow would hide it, and nothing may write near it.
  mkdirSync(join(scratch, "bin"), { recursive: true });
  binCopy = join(scratch, "bin", "opencode-v2");
  cpSync(V2_BIN, binCopy);
  mkdirSync(NS_REPO(), { recursive: true });  // bwrap needs its bind target to exist
});

after(() => {
  rmSync(scratch, { recursive: true, force: true });
  assert.equal(fixtureSnap(), FIXTURE_SNAPSHOT, "the committed fixture tree changed during the isolation run (COPY-ONLY rule)");
});

// ── namespace plumbing ──────────────────────────────────────────────────────────────────────

// env -i equivalent (spawn env REPLACES the whole environment — the recorded scrub, with
// HOME pinned to the shadowed path so os.homedir() inside resolves under the shadow).
const scrubbedEnv = () => ({ HOME, PATH: "/usr/bin:/bin:/usr/local/bin", TERM: "dumb" });

// One namespace: / kept, checkout ro-bound at the in-namespace path, shadow HOME over the
// real profile, chdir (default: the shadow HOME — the recorded shape). Recorded bwrap
// shape, verbatim, placeholder-free.
const inShadow = ({ homeSource, timeoutSeconds, chdir = HOME, argv }) => spawnSync(TIMEOUT, [String(timeoutSeconds), BWRAP,
  "--dev-bind", "/", "/",
  "--ro-bind", REPO, NS_REPO(),
  "--bind", homeSource, HOME,
  "--chdir", chdir,
  ...argv], { env: scrubbedEnv(), encoding: "utf8", maxBuffer: 1 << 26 });

// The real CLI inside the namespace, targeting the shadow HOME. Install runs in-namespace
// on purpose: the adapter bakes its import path at write time, and only the in-namespace
// checkout root resolves inside the shadow (install-probe procedure step 3).
const nsInstall = (homeSource, args) => inShadow({
  homeSource,
  timeoutSeconds: 60,
  argv: [process.execPath, join(NS_REPO(), "src", "cli.js"), "install", ...args],
});

// A shadow HOME: temp copy of the committed fixture (never install into the committed
// tree), plus the run-root dirs the recorded launcher shapes create.
const makeShadowHome = (tag) => {
  const runroot = join(scratch, tag);
  const fakehome = join(runroot, "home");
  cpSync(FIXTURE, fakehome, { recursive: true });
  for (const d of [join(fakehome, ".opencode", "plugins"), join(fakehome, ".local", "share", "opencode"), join(fakehome, ".cache"), join(runroot, "proj")]) {
    mkdirSync(d, { recursive: true });
  }
  return { runroot, fakehome };
};

// The boot: v2 `run --standalone` under the 60s leash, with ONE 90s retry — and the retry
// only fires on the recorded spawn-hang signature (leash expiry, no setup marker). A boot
// that expired WITH a marker already finished its plugin observation (recorded: setup and
// evaluation precede any model call), so no retry is spent on it. Each attempt's captured
// output lands in its own file (run-boot.out / run-boot-retry.out) — the hung attempt's
// evidence survives the retry, per the recorded procedure's per-run preservation.
// `cwd` chdirs the run into the throwaway proj dir (launch.sh's run-root proj), NOT the
// shadow HOME: the session row's `directory` then names the temp tree, so leg 3's
// by-directory attribution can never match an operator session launched from $HOME.
const childOut = (r) => (r.stdout ?? "") + (r.stderr ?? "");
const boot = ({ fakehome, markFile, cwd }) => {
  const once = (seconds) => inShadow({
    homeSource: fakehome,
    timeoutSeconds: seconds,
    chdir: cwd,
    argv: [binCopy, "run", "--standalone", "--model", MODEL, PROMPT],
  });
  let r = once(60);
  writeFileSync(join(scratch, "run-boot.out"), childOut(r));
  let retried = false;
  if (r.status === 124 && !(existsSync(markFile) && readFileSync(markFile, "utf8").includes(MARKER_PREFIX))) {
    retried = true;
    writeFileSync(join(scratch, "marker-retry.log"), "RETRY90 leash-at-spawn no-setup-marker\n");
    r = once(90);
    writeFileSync(join(scratch, "run-boot-retry.out"), childOut(r));
  }
  return { rc: r.status, out: childOut(r), retried };
};

// Live-DB attribution: zero in-window sessions with the shadow run's cwd as their
// `directory` — by directory, not window alone, because the on-demand harness has no
// idle-window guarantee (an operator session created mid-window must not false-fail;
// their sessions carry their own cwds). Read-only throughout: the sqlite3 CLI with a
// file:...?mode=ro URI first (the recorded artifact's shape), node:sqlite's readOnly
// open as the fallback for hosts without the CLI. Any failure degrades the leg to the
// mtime/shadow assertions (recorded degradation). The node:sqlite path is SELECT-only,
// opened readOnly, and bails if the open reports itself non-read-only.
const liveDbSessionsSince = async (sinceMs, directory) => {
  const until = Date.now() + 60_000;  // span the assert moment, like the artifact's window end
  const dirLit = `'${String(directory).replaceAll("'", "''")}'`;
  const q = `SELECT COUNT(*) FROM session WHERE time_created >= ${Math.floor(sinceMs)} AND time_created < ${until} AND directory = ${dirLit};`;
  const cli = spawnSync("sqlite3", [`file:${LIVE_DB}?mode=ro`, q], { encoding: "utf8" });
  if (cli.status === 0 && cli.stdout !== null) {
    const n = Number.parseInt(cli.stdout.trim(), 10);
    if (Number.isFinite(n)) return { mode: "sqlite3-cli", count: n };
  }
  try {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(LIVE_DB, { readOnly: true });
    try {
      if (db.isReadOnly === false) return { mode: "unavailable", reason: "node:sqlite refused a read-only open" };
      const n = Number(db.prepare("SELECT COUNT(*) AS n FROM session WHERE time_created >= ? AND time_created < ? AND directory = ?").get(Math.floor(sinceMs), until, directory).n);
      return { mode: "node-sqlite", count: n };
    } finally { db.close(); }
  } catch (e) {
    return { mode: "unavailable", reason: scrub(e?.message ?? String(e)).slice(0, 120) };
  }
};

// ── leg 1: containment ──────────────────────────────────────────────────────────────────────

test("containment: a v2 boot inside the shadow HOME writes only into the shadow and proves the real adapter entered setup", (t) => {
  if (MISSING) return t.skip(MISSING);
  const { runroot, fakehome } = makeShadowHome("containment");
  const bootCwd = join(runroot, "proj");
  BOOT_CWD = bootCwd;  // leg 3 attributes live-DB sessions by this directory (temp tree — never an operator cwd)
  const markFile = join(scratch, "marker-containment.log");
  writeFileSync(join(fakehome, ADAPTER_DIR, MARKER_PLUGIN), markerPluginSource(NS_REPO(), markFile));

  // install the v2 adapter into the shadow copy, inside the namespace
  const inst = nsInstall(fakehome, ["opencode", "--v2", "--home", HOME]);
  assert.equal(inst.status, 0, `in-shadow v2 install failed rc=${inst.status}: ${scrub(firstLine(inst.stderr))}`);
  const adapterFile = join(fakehome, ADAPTER_DIR, ADAPTER);
  assert.deepEqual(readFileSync(adapterFile), Buffer.from(adapterText(NS_REPO(), true)),
    "the installed adapter must be the v2 contract pinned to the in-namespace checkout root");

  const b = boot({ fakehome, markFile, cwd: bootCwd });

  // marker evidence: the repo module imported in-shadow, kept its exact {id, setup}
  // export shape, and the loader dispatched a setup (the marker's). The installed adapter's
  // own dispatch is proven loader-side by the shadow-log assertions below.
  const marker = existsSync(markFile) ? readFileSync(markFile, "utf8") : "";
  const markerLine = marker.split("\n").find((l) => l.startsWith(MARKER_PREFIX));
  assert.ok(markerLine,
    `no setup marker — the marker plugin's setup never ran (rc=${b.rc}${b.retried ? ", retried at 90s" : ""}; run tail: ${scrub(tail(b.out))})`);
  assert.ok(markerLine.includes("context-stored=true"), `marker setup ran without context evidence (marker: ${scrub(markerLine)})`);
  // exact, not substring: "keys=id+setup+extra" must fail here
  assert.ok(/keys=id\+setup$/.test(markerLine), `the adapter's exported shape drifted from exactly {id, setup} (marker: ${scrub(markerLine)})`);

  // shadow-write confinement, positive side: the run's state landed in the shadow
  const shadowLog = join(fakehome, ".local", "share", "opencode", "log", "opencode.log");
  assert.ok(existsSync(shadowLog), "no v2 log under the shadow HOME — the boot never wrote state into the copy");
  const log = readFileSync(shadowLog, "utf8");
  const loadingLines = log.split("\n").filter((l) => l.includes("loading plugin"));
  assert.ok(loadingLines.some((l) => l.includes(ADAPTER)), "the shadow log shows no loading-plugin line for the installed adapter");
  assert.ok(!log.includes("failed to load plugin"), "the shadow log records a failed plugin load");
  assert.ok(!log.includes("SchemaError"), "the shadow log records a schema rejection — the adapter did not pass the v2 load schema");
  // t.log keeps the counts in the recorded output without echoing shadow paths
  t.log(`shadow log: ${loadingLines.length} loading-plugin line(s), installed adapter present, no load failures`);
});

// ── leg 2: the guard (entry 1's detection, end-to-end) ──────────────────────────────────────

test("guard: install opencode --v2 against a v1-owned shadow HOME refuses with nothing written; --force writes with the warning", (t) => {
  if (MISSING) return t.skip(MISSING);
  const { fakehome } = makeShadowHome("guard");
  const adapterFile = join(fakehome, ADAPTER_DIR, ADAPTER);

  // the natural owner: a default (v1) install into the shadow copy, inside the namespace
  const v1 = nsInstall(fakehome, ["opencode", "--home", HOME]);
  assert.equal(v1.status, 0, `in-shadow v1 install failed rc=${v1.status}: ${scrub(firstLine(v1.stderr))}`);
  assert.deepEqual(readFileSync(adapterFile), Buffer.from(adapterText(NS_REPO(), false)), "the planted owner must be the v1 contract");

  // refuse: the unforced cross-generation install exits 1 naming the override and the
  // generation it found, and writes NOTHING
  const refused = nsInstall(fakehome, ["opencode", "--v2", "--home", HOME]);
  assert.equal(refused.status, 1, `an unforced cross-generation install must exit 1 (got ${refused.status})`);
  const refusal = scrub(refused.stderr);
  assert.match(refusal, /--force/, "the refusal must name the override flag");
  assert.match(refusal, /v1 adapter/, "the refusal must name the generation it found");
  assert.deepEqual(readFileSync(adapterFile), Buffer.from(adapterText(NS_REPO(), false)),
    "the refused install must not have touched the v1 adapter (no-write)");

  // warn: --force writes the requested generation anyway, with the warning printed
  const forced = nsInstall(fakehome, ["opencode", "--v2", "--force", "--home", HOME]);
  assert.equal(forced.status, 0, `the forced install must succeed (got ${forced.status}: ${scrub(firstLine(forced.stderr))})`);
  assert.match(scrub(forced.stdout), /WARNING/, "the forced install must print the ownership warning");
  assert.deepEqual(readFileSync(adapterFile), Buffer.from(adapterText(NS_REPO(), true)), "--force must write the v2 adapter");
});

// ── leg 3: the real-HOME closure across both legs ───────────────────────────────────────────
// Watermark touched before any leg; asserted after them. Runs in declaration order after
// legs 1 and 2.

test("real HOME untouched: directory mtimes hold, plugin trees gain nothing newer than the watermark, state-tree churn attributed", async (t) => {
  if (MISSING) return t.skip(MISSING);
  assert.deepEqual(snapDirMtimes(), REAL_DIR_MTIMES, "a real HOME directory changed mtime during the isolation legs");

  for (const key of ["config tree", "alternate plugin dir"]) {
    const n = countNewer(REAL_DIRS[key], WATERMARK_MS);
    assert.equal(n, 0, `${n} file(s) newer than the watermark appeared under the real ${key} during the legs`);
  }

  if (!LIVE_DB_AT_START) {
    assert.equal(existsSync(LIVE_DB), false, "a live opencode DB materialized in the real state tree during the legs");
    t.log("no live DB at start and none appeared — state-tree leg rests on the mtime/shadow assertions (recorded degradation)");
    return;
  }
  const stateNewer = countNewer(REAL_DIRS["state tree"], WATERMARK_MS);
  if (stateNewer === 0) {
    t.log("zero files newer than the watermark under the real state tree");
    return;
  }
  if (!existsSync(LIVE_DB)) {
    t.log(`the live DB vanished mid-run; ${stateNewer} newer state-tree file(s) stand unattributed`);
    return;
  }
  const q = await liveDbSessionsSince(WATERMARK_MS, BOOT_CWD);
  if (q.mode === "unavailable") {
    // recorded degradation: no read-only driver — the mtime/shadow assertions carry the leg
    t.log(`live-DB attribution unavailable (${q.reason}); ${stateNewer} newer state-tree file(s) stand unattributed`);
    return;
  }
  assert.equal(q.count, 0,
    `${q.count} in-window session(s) carry the shadow run's cwd as their directory — a leg wrote a real session (${q.mode} query)`);
  t.log(`${stateNewer} newer state-tree file(s) attributed to live-service churn: zero in-window sessions with the shadow cwd (${q.mode})`);
});
