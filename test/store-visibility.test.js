// Store visibility (CAP-5, epic-github-field-reports entry 5 / GitHub issue 5): the
// two-terminal split — a harness that sets GUARD_HOME (the Hermes adapter must: it is the
// fork root the plugin spawns the hook from) reads a different user-policy.json than an
// operator terminal without it — made visible three ways: every policy-family command
// prints the store file it touched, a harness-store registry (anchored at the DEFAULT home,
// the one anchor every terminal can find) records where each harness's policy actually
// lives, and `policy where` prints the whole map with divergences marked. This file pins
// the registry machinery, the CLI surfaces through spawned children (hermetic HOME + no
// real registry), and the recording at each harness-serving entry (hook main, ACP proxy,
// opencode plugin) — plus the guards that keep every scratch fixture under the OS tmpdir
// from ever polluting the operator's real registry.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { PassThrough, Readable, Writable } from "node:stream";
import {
  policyFile, harnessStoreRegistryFile, readHarnessStores, recordHarnessStore,
  divergentHarnessStores, storeSpell,
} from "../src/policy.js";
import { recordHarnessStore as recordViaContract, CONTRACT_VERSION } from "../src/contract.js";
import { main } from "../src/hook.js";
import { runProxy } from "../src/acp.js";
import { UnjangledGuardrails } from "../src/opencode.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const CLI = join(REPO, "src", "cli.js");
const REAL_HOME = homedir();            // captured before any HOME override in this process
const storeName = () => basename(policyFile({}));

// The registry anchor honors $HOME at call time (guardHome({}) → homedir()), so every test
// pins it to a throwaway tree; store homes recorded in tests must look DURABLE (not under
// the OS tmpdir — the scratch guard), so they live in self-cleaning hidden dirs under the
// real home, created before any override.
const registryAnchor = () => mkdtempSync(join(tmpdir(), "ug-vis-anchor-"));
const durableRoot = () => mkdtempSync(join(REAL_HOME, ".ug-vis-fixture-"));
const DURABLES = [];
const durable = () => { const d = durableRoot(); DURABLES.push(d); return d; };

const withHome = (home, fn) => {
  const saved = process.env.HOME;
  process.env.HOME = home;
  try { return fn(); } finally { process.env.HOME = saved; }
};
const seedRegistry = (anchor, harnesses) => {
  // explicit anchor path — NEVER harnessStoreRegistryFile() (that reads the process env,
  // i.e. the operator's real default home at seeding time)
  mkdirSync(join(anchor, ".unjangled-guardrails"), { recursive: true });
  writeFileSync(join(anchor, ".unjangled-guardrails", "harness-stores.json"), JSON.stringify({ version: 1, harnesses }, null, 2) + "\n");
};
const registryOf = (anchor) => {
  const raw = readFileSync(join(anchor, ".unjangled-guardrails", "harness-stores.json"), "utf8");
  return JSON.parse(raw).harnesses;
};

// ── registry machinery units ─────────────────────────────────────────────────────────────────

test("recordHarnessStore writes the registry at the DEFAULT home, keyed by harness, naming the deciding spell", () => {
  const anchor = registryAnchor();
  const root = durable();
  withHome(anchor, () => {
    const wrote = recordHarnessStore("hermes", { PATH: "/usr/bin", HOME: anchor, GUARD_HOME: root },
      { now: () => "2026-11-10T01:00:00.000Z" });
    assert.equal(wrote, true);
    assert.deepEqual(registryOf(anchor), { hermes: { home: root, spell: "GUARD_HOME", at: "2026-11-10T01:00:00.000Z" } });
  });
});

test("recordHarnessStore is idempotent while fresh, refreshes when stale, and never throws", () => {
  const anchor = registryAnchor();
  const root = durable();
  const env = { PATH: "/usr/bin", HOME: anchor, JEV_GUARD_HOME: root };
  withHome(anchor, () => {
    assert.equal(recordHarnessStore("claude", env, { now: () => "2026-11-10T01:00:00.000Z" }), true);
    const before = readFileSync(harnessStoreRegistryFile(), "utf8");
    assert.equal(recordHarnessStore("claude", env, { now: () => "2026-11-10T02:00:00.000Z" }), false, "unchanged and fresh — no write");
    assert.equal(readFileSync(harnessStoreRegistryFile(), "utf8"), before, "byte-identical");
    assert.equal(recordHarnessStore("claude", env, { now: () => "2026-11-10T23:00:00.000Z" }), true, "stale record refreshes");
    assert.equal(registryOf(anchor).claude.at, "2026-11-10T23:00:00.000Z");
  });
});

test("the guards: synthetic envs, scratch roots and bad names record nothing", () => {
  const anchor = registryAnchor();
  withHome(anchor, () => {
    const root = durable();
    for (const [label, env] of [
      ["no PATH", { HOME: anchor, GUARD_HOME: root }],
      ["no HOME", { PATH: "/usr/bin", GUARD_HOME: root }],
      ["tmp-rooted GUARD_HOME", { PATH: "/usr/bin", HOME: anchor, GUARD_HOME: join(tmpdir(), "scratch-fork") }],
    ]) assert.equal(recordHarnessStore("hermes", env), false, label);
    assert.equal(recordHarnessStore("bad harness!", { PATH: "/usr/bin", HOME: anchor, GUARD_HOME: root }), false);
    assert.equal(existsSync(harnessStoreRegistryFile()), false, "no guard case wrote a registry");
  });
});

test("readHarnessStores: missing reads empty, corrupt warns and reads empty, and the next recording regenerates", () => {
  const anchor = registryAnchor();
  withHome(anchor, () => {
    assert.deepEqual(readHarnessStores(), { version: 1, harnesses: {} }, "no registry yet");
    mkdirSync(join(anchor, ".unjangled-guardrails"), { recursive: true });
    writeFileSync(harnessStoreRegistryFile(), "{not json");
    const warnings = [];
    const w = new Writable({ write: (c, _e, cb) => { warnings.push(String(c)); cb(); } });
    assert.deepEqual(readHarnessStores(undefined, { warnStream: w }).harnesses, {}, "corrupt reads as empty");
    assert.match(warnings.join(""), /registry unreadable/);
    const root = durable();
    assert.equal(recordHarnessStore("hermes", { PATH: "/usr/bin", HOME: anchor, GUARD_HOME: root }), true, "corrupt regenerates");
    assert.deepEqual(Object.keys(registryOf(anchor)), ["hermes"]);
  });
});

test("divergentHarnessStores: only recorded harnesses whose root differs from the command's resolution", () => {
  const anchor = registryAnchor();
  const hermesRoot = durable();
  const claudeRoot = durable();
  withHome(anchor, () => {
    seedRegistry(anchor, {
      hermes: { home: hermesRoot, spell: "GUARD_HOME", at: "2026-11-10T01:00:00.000Z" },
      claude: { home: claudeRoot, spell: "default", at: "2026-11-10T01:00:00.000Z" },
    });
    const fromClaude = divergentHarnessStores({ GUARD_HOME: claudeRoot });
    assert.deepEqual(fromClaude.map((d) => d.harness), ["hermes"]);
    assert.deepEqual(fromClaude[0], { harness: "hermes", home: hermesRoot, spell: "GUARD_HOME", at: "2026-11-10T01:00:00.000Z" });
    assert.deepEqual(divergentHarnessStores({ GUARD_HOME: hermesRoot }).map((d) => d.harness), ["claude"]);
    assert.deepEqual(divergentHarnessStores({ GUARD_HOME: hermesRoot, JEV_GUARD_HOME: claudeRoot }).map((d) => d.harness), ["claude"], "the modern spelling outranks the legacy one in resolution");
  });
  const empty = registryAnchor();
  withHome(empty, () => assert.deepEqual(divergentHarnessStores({}), [], "no registry → no divergence"));
});

test("storeSpell names the deciding spelling; default means GUARD_HOME unset", () => {
  assert.equal(storeSpell({ GUARD_HOME: "/a" }), "GUARD_HOME");
  assert.equal(storeSpell({ JEV_GUARD_HOME: "/a" }), "JEV_GUARD_HOME");
  assert.equal(storeSpell({ GUARD_HOME: "/a", JEV_GUARD_HOME: "/b" }), "GUARD_HOME");
  assert.equal(storeSpell({}), "default");
  assert.equal(storeSpell({ GUARD_HOME: "" }), "default", "an empty value is an unset one");
});

// ── the CLI surfaces (spawned children, hermetic HOME and registry) ──────────────────────────

const child = (args, { anchor, guardHome, operator = true } = {}) => {
  const env = { PATH: process.env.PATH, HOME: anchor };
  if (guardHome !== undefined) env.GUARD_HOME = guardHome;
  if (operator) env.GUARD_OPERATOR_CLI = "1";
  return spawnSync(process.execPath, [CLI, ...args], { cwd: REPO, env, encoding: "utf8" });
};

test("every policy-family command prints the store file it touched", () => {
  const anchor = registryAnchor();
  const root = durable();
  const footer = `unjangled-guardrails: policy store: ${join(root, storeName())}`;
  const expectFooter = (r, note) => {
    assert.equal(r.status, 0, `${note}: ${r.stderr}`);
    assert.ok(r.stdout.includes(footer), `${note}: the store echo is present`);
  };
  expectFooter(child(["policy", "add", "--tool", "mcp__x"], { anchor, guardHome: root }), "policy add --tool");
  expectFooter(child(["policy", "list"], { anchor, guardHome: root }), "policy list");
  expectFooter(child(["policy", "set", "--degradation", "fail-closed"], { anchor, guardHome: root }), "policy set");
  expectFooter(child(["policy", "adopt-defaults"], { anchor, guardHome: root }), "policy adopt-defaults");
  expectFooter(child(["policy", "remove", "mcp__x"], { anchor, guardHome: root }), "policy remove");
  expectFooter(child(["ruling", "init"], { anchor, guardHome: root }), "ruling init");
  const add = child(["ruling", "add", "--effect", "allow", "--pattern", "make deploy", "--scope", "project:/p"], { anchor, guardHome: root });
  expectFooter(add, "ruling add");
  expectFooter(child(["ruling", "list"], { anchor, guardHome: root }), "ruling list");
  const id = add.stdout.match(/policy entry (p-[0-9a-f]+) saved/)?.[1];
  assert.ok(id, "the ruling add reported its id");
  expectFooter(child(["ruling", "revoke", id], { anchor, guardHome: root }), "ruling revoke");
  expectFooter(child(["lane", "add", "--tool", "mcp__x"], { anchor, guardHome: root }), "lane add");
  expectFooter(child(["lane", "list"], { anchor, guardHome: root }), "lane list");
  expectFooter(child(["lane", "remove", "mcp__x"], { anchor, guardHome: root }), "lane remove");
});

test("a recorded harness reading a different store warns on every policy command; a matching record stays silent", () => {
  const anchor = registryAnchor();
  const terminalRoot = durable();   // where THIS command resolves its store
  const hermesRoot = durable();     // the harness's split store
  seedRegistry(anchor, {
    hermes: { home: hermesRoot, spell: "GUARD_HOME", at: "2026-11-10T01:00:00.000Z" },
    claude: { home: terminalRoot, spell: "default", at: "2026-11-10T01:00:00.000Z" },
  });
  const r = child(["policy", "list"], { anchor, guardHome: terminalRoot });
  assert.equal(r.status, 0);
  assert.ok(r.stdout.includes(`unjangled-guardrails: policy store: ${join(terminalRoot, storeName())}`), "the echo names this command's store");
  assert.match(r.stderr, new RegExp(`harness 'hermes' reads a different policy store: ${join(hermesRoot, storeName())}`));
  assert.match(r.stderr, /recorded 2026-11-10T01:00:00\.000Z/);
  assert.match(r.stderr, /policy where/);
  assert.ok(!r.stderr.includes("claude"), "a harness recorded at this command's own root never warns");
});

test("policy where prints the store per surface: this terminal, the default store, recorded harnesses with divergences marked", () => {
  const anchor = registryAnchor();
  const terminalRoot = durable();
  const hermesRoot = durable();
  seedRegistry(anchor, {
    hermes: { home: hermesRoot, spell: "GUARD_HOME", at: "2026-11-10T01:00:00.000Z" },
    claude: { home: terminalRoot, spell: "default", at: "2026-11-10T01:00:00.000Z" },
  });
  const r = child(["policy", "where"], { anchor, guardHome: terminalRoot, operator: false });
  assert.equal(r.status, 0, r.stderr);
  const out = r.stdout;
  assert.match(out, new RegExp(`this terminal\\s+${join(terminalRoot, storeName())}  \\(GUARD_HOME\\)`));
  assert.match(out, new RegExp(`default store\\s+${join(anchor, ".unjangled-guardrails", storeName())}  \\(what terminals and harnesses without GUARD_HOME read\\)`));
  assert.match(out, new RegExp(`hermes\\s+${join(hermesRoot, storeName())}  \\(GUARD_HOME, recorded 2026-11-10T01:00:00\\.000Z\\)  \\[diverges\\]`));
  assert.match(out, new RegExp(`claude\\s+${join(terminalRoot, storeName())}  \\(default, recorded`));
  assert.ok(!out.includes("[diverges]") || out.match(/\[diverges\]/g).length === 1, "only the hermes row diverges");
});

test("policy where: a fresh machine names the default store and says nothing else is known", () => {
  const anchor = registryAnchor();
  const r = child(["policy", "where"], { anchor, guardHome: undefined, operator: false });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, new RegExp(`this terminal\\s+${join(anchor, ".unjangled-guardrails", storeName())}  \\(GUARD_HOME unset — the default store\\)`));
  assert.doesNotMatch(r.stdout, /^default store/m, "no separate default row when this terminal IS the default");
  assert.match(r.stdout, /no other harness store recorded and no other install registered/);
});

test("policy where lists a registered install with no runtime record yet", () => {
  const anchor = registryAnchor();
  const terminalRoot = durable();
  const install = child(["install", "pi", "--home", anchor], { anchor, guardHome: terminalRoot, operator: false });
  assert.equal(install.status, 0, install.stderr);
  const r = child(["policy", "where"], { anchor, guardHome: terminalRoot, operator: false });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, new RegExp(`pi\\s+no runtime record yet — install registered at .*\\.pi.*settings\\.json; its store is its harness env's GUARD_HOME, else the default store`));
});

// ── the recording at each harness-serving entry ──────────────────────────────────────────────

test("the hook's main records the serving harness's store root (the Hermes shape); handleHook alone records nothing", async () => {
  const anchor = registryAnchor();
  const hookRoot = durable();
  const project = mkdtempSync(join(tmpdir(), "ug-vis-proj-"));
  const env = { PATH: process.env.PATH, HOME: anchor, GUARD_HOME: hookRoot, JEV_API_KEY: "test" };
  const out = new PassThrough();
  const savedSessions = process.env.GUARD_SESSIONS;
  process.env.GUARD_SESSIONS = join(project, "sessions");  // the session half of the hook writes via process env
  try {
    await withHomeAsync(anchor, async () => {
      await main(["--agent", "hermes"], Readable.from([JSON.stringify({ hook_event_name: "SessionStart", session_id: "vis-1", cwd: project })]), out, env);
    });
    assert.deepEqual(registryOf(anchor), { hermes: { home: hookRoot, spell: "GUARD_HOME", at: registryOf(anchor).hermes.at } }, "main recorded hermes at its GUARD_HOME");
    assert.ok(!Number.isNaN(Date.parse(registryOf(anchor).hermes.at)), "the record carries a parsable timestamp");
    // the library surface records nothing: only real process entries do (fixtures stay hermetic)
    rmSync(join(anchor, ".unjangled-guardrails"), { recursive: true, force: true });
    await withHomeAsync(anchor, async () => {
      const { handleHook } = await import("../src/hook.js");
      await handleHook({ hook_event_name: "SessionStart", session_id: "vis-2", cwd: project }, { agent: "claude", env });
    });
    assert.equal(existsSync(join(anchor, ".unjangled-guardrails", "harness-stores.json")), false, "handleHook wrote no registry (the anchor's, never the process-level real home)");
  } finally { process.env.GUARD_SESSIONS = savedSessions; }
});

const withHomeAsync = async (home, fn) => {
  const saved = process.env.HOME;
  process.env.HOME = home;
  try { return await fn(); } finally { process.env.HOME = saved; }
};

test("the ACP proxy records 'acp' at its entry", async () => {
  const anchor = registryAnchor();
  const acpRoot = durable();
  const stdin = new PassThrough(), stdout = new PassThrough();
  const env = { ...process.env, HOME: anchor, GUARD_HOME: acpRoot };
  const proc = runProxy(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdin, stdout, env, onExit: () => {} });
  try {
    await new Promise((res) => setTimeout(res, 150));
    assert.deepEqual(registryOf(anchor).acp, { home: acpRoot, spell: "GUARD_HOME", at: registryOf(anchor).acp.at }, "runProxy recorded the acp store root");
  } finally { proc.kill(); }  // a live child keeps the file process's loop — kill on every path
});

test("the opencode plugin entries record 'opencode'", async () => {
  const anchor = registryAnchor();
  const ocRoot = durable();
  const saved = { HOME: process.env.HOME, GUARD_HOME: process.env.GUARD_HOME };
  process.env.HOME = anchor;
  process.env.GUARD_HOME = ocRoot;
  try {
    await UnjangledGuardrails({ client: null, directory: "/w" });  // the v1 entry records before returning its hooks
    assert.equal(registryOf(anchor).opencode.home, ocRoot);
  } finally {
    process.env.HOME = saved.HOME;
    process.env.GUARD_HOME = saved.GUARD_HOME;
  }
});

test("the contract re-exports the recording export (pinned at the current contract version; 1.7.0 is entry 3's sub-agent relay on top of 1.6's ask-user lane and 1.5's recordHarnessStore)", async () => {
  assert.equal(typeof recordViaContract, "function");
  assert.equal(CONTRACT_VERSION, "1.7.0");
  const anchor = registryAnchor();
  const root = durable();
  withHome(anchor, () => {
    assert.equal(recordViaContract("contract-check", { PATH: "/usr/bin", HOME: anchor, GUARD_HOME: root }), true);
    assert.equal(registryOf(anchor)["contract-check"].home, root);
  });
});

// Self-cleaning: the durable fixtures live under the real home as hidden dirs — remove them
// so the visibility tests leave nothing behind.
test("cleanup: durable fixtures removed", () => {
  for (const d of DURABLES) rmSync(d, { recursive: true, force: true });
});
