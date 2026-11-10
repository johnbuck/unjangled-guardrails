// Target-keyed self-protection, the reads half (ticket 10 / GHI-10, CAP-1 — operator ruling
// 2026-11-09): the self-protection rule keys on what the call actually TOUCHES, never on
// gate-related words in the command text. Documentation is readable forever; only real writes
// into the gate's own paths and real private-store access deny; every deny names exactly what
// it matched. The rows here are the doctrine's both-directions battery: the reporter repro and
// this session's own live misfires pass, the real store/CLI/source shapes deny, and each deny
// carries its matched clause.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { selfModVerdict, pathSelfModVerdict, alwaysDeny } from "../src/always-deny.js";
import { assessAction } from "../src/guard.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const scratchHome = () => mkdtempSync(join(tmpdir(), "unjangled-guardrails-selfprot-"));

// The suites' shared fake-brain shape: everything scores 0.2, so a non-floor call allows.
const calmBrain = async () => ({
  ok: true,
  json: async () => ({ answers: {
    risk: { type: "score", score: 0.2, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: 0.05 }, user_requested: { type: "noul", noul: 0.05 }, from_untrusted: { type: "noul", noul: 0.05 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
  } }),
});

const leg = (command, { cwd = "/proj", home = scratchHome() } = {}) =>
  selfModVerdict("Bash", { command }, { cwd, env: { GUARD_HOME: home } });

// ── the repro family: text mentions never fire ────────────────────────────────────────────────

test("GHI-10 repro: a read-only grep of the gate's own docs whose PATTERN spells subcommand shapes passes", () => {
  const home = scratchHome();
  // the reporter's exact command, run inside the gate clone (cwd under the gate tree)
  assert.equal(leg(`grep -n -E 'policy add|--dir|--effect|--expires|--scope' docs/policy.md`, { cwd: REPO, home }), null);
});

test("the session's own live misfire shapes pass (a confirmed misfire becomes a test row, never a waiver)", () => {
  // both were denied live on 2026-11-10 by the old word rule — recorded in the evidence file
  assert.equal(leg(`grep -rn "policy add\\|selfMod\\|Self-Protection\\|self-protection" test/`), null);
  assert.equal(leg(`grep -rn "rulings.json\\|user-policy.json\\|user-lane" test/guard.test.js`), null);
  // unquoted mentions are equally free: position, not quoting, is what retired the class
  assert.equal(leg("echo policy add docs"), null);
  assert.equal(leg(`git commit -m 'fixes the rulings.json migration'`), null);
  assert.equal(leg(`gh issue create -R me/unjangled-guardrails --title 'policy add misfires on doc reads' --body-file notes.md`), null);
  assert.equal(leg(`echo 'GUARD_OPERATOR_CLI=1 documentation note'`), null);
});

test("reads of docs, README, and gate source under the gate tree pass on every plane", () => {
  const home = scratchHome();
  for (const command of ["cat README.md", "head docs/policy.md", "sed -n 1,60p src/guard.js", "grep -n brain src/guard.js | wc -l", "ls src"])
    assert.equal(leg(command, { cwd: REPO, home }), null, command);
  // the read-tool plane: gate-tree files are not guarded paths at all
  assert.equal(pathSelfModVerdict("Read", { file_path: join(REPO, "docs", "policy.md") }, { cwd: REPO, env: { GUARD_HOME: home } }), null);
  assert.equal(pathSelfModVerdict("read_file", { path: join(REPO, "src", "guard.js") }, { cwd: REPO, env: { GUARD_HOME: home } }), null);
});

// ── the exec half: the policy CLI in command position ────────────────────────────────────────

test("the gate's policy CLI at command position with a mutating subcommand denies, naming the invocation", () => {
  const home = scratchHome();
  for (const [command, invocation] of [
    ["node src/cli.js policy add --effect allow --pattern '*'", "src/cli.js policy add"],
    ["node 'src/cli.js' ruling revoke r-deadbeef", "src/cli.js ruling revoke"],
    ["unjangled-guardrails policy set --degradation fail-open", "unjangled-guardrails policy set"],
    ["node src/cli.js lane add --tool x", "src/cli.js lane add"],
    ["node src/cli.js policy adopt-defaults", "src/cli.js policy adopt-defaults"],
    ["node ./src/cli.js policy remove p-1", "./src/cli.js policy remove"],
    ["npx unjangled-guardrails policy add --pattern 'git push *'", "unjangled-guardrails policy add"],
    ["sh -c 'unjangled-guardrails policy add --tool x'", "unjangled-guardrails policy add"],
    ["/opt/tool/src/cli.js policy add --pattern '*'", "cli.js policy add"],   // any cli.js entry spelling
  ]) {
    const v = leg(command, { home });
    assert.ok(v, command);
    assert.equal(v.leg, "store", command);
    assert.match(v.matched, new RegExp(`the gate policy-CLI invocation '.*${invocation.slice(invocation.lastIndexOf("/") + 1)}.*'`), command);
  }
  // leading env assignments do not move the command position
  const prefixed = leg("GUARD_HOME=/tmp/x node src/cli.js policy add --pattern '*'", { home });
  assert.ok(prefixed && prefixed.leg === "store");
});

test("non-mutating CLI subcommands pass: list/where are reads, ruling init is deliberately ungated", () => {
  const home = scratchHome();
  for (const command of ["node src/cli.js policy list", "node src/cli.js policy where", "node src/cli.js ruling init",
    "node src/cli.js calibrate", "node src/cli.js rules-check", "node server.js policy add"])  // last: not the gate entry
    assert.equal(leg(command, { home }), null, command);
});

// ── the write/read split over the real store files ────────────────────────────────────────────

test("real writes into the store deny as policy store write, naming the resolved target", () => {
  const home = scratchHome();
  const store = join(home, "user-policy.json");
  // [command, cwd, matched clause] — the relative spelling resolves against the call cwd
  for (const [command, cwd, clause] of [
    [`echo '[]' > ${store}`, "/proj", `the redirect target ${store}`],
    [`cp x.json ${store}`, "/proj", `the write target ${store}`],
    [`cat a | tee ${store}`, "/proj", `the write target ${store}`],
    [`sed -i s/a/b/ ${store}`, "/proj", `the write target ${store}`],
    [`rm ${store}`, "/proj", `the write target ${store}`],
    [`mv ${store} /tmp/`, "/proj", `the write target ${store}`],
    [`echo '[]' > user-policy.json`, home, `the redirect target ${store}`],
  ]) {
    const v = selfModVerdict("Bash", { command }, { cwd, env: { GUARD_HOME: home } });
    assert.ok(v, command);
    assert.equal(v.leg, "store", command);
    assert.equal(v.matched, clause, command);
  }
  // the tilde spelling of the real operator home
  const tildeWrite = selfModVerdict("Bash", { command: "echo '[]' > ~/.unjangled-guardrails/user-policy.json" }, { cwd: "/proj", env: { GUARD_HOME: home } });
  assert.ok(tildeWrite && tildeWrite.leg === "store");
});

test("real store reads deny as policy store access — the private store is not agent-readable (bash plane)", () => {
  const home = scratchHome();
  const store = join(home, "user-policy.json");
  for (const command of [`cat ${store}`, `grep -n effect ${store}`, `stat ${store}`, `wc -l ${join(home, "rulings-use.jsonl")}`]) {
    const v = leg(command, { home });
    assert.ok(v, command);
    assert.equal(v.leg, "store-access", command);
    assert.ok(v.matched.startsWith("the private store path "), command);
  }
  // a store path inside an executing payload (node -e) is a touch: the quoted span resolves
  const payload = leg(`node -e "require('fs').writeFileSync('${store}','[]')"`, { home });
  assert.ok(payload && payload.leg === "store-access");
  assert.match(payload.matched, /inside a quoted payload/);
});

test("look-alike names never fire: resolution is exact-path against the real store, no substrings", () => {
  const home = scratchHome();
  for (const command of [
    "cat /proj/rulings.json",                              // a sibling file in a project directory
    "cat docs/user-policy.json.example",                   // a safe-template spelling
    "echo 'the user-policy.json.lock is transient'",       // the lock file is not in the guard set
    "cat /proj/notes/user-lane-use.jsonl.bak",             // backup spelling elsewhere
  ]) assert.equal(leg(command, { cwd: "/proj", home }), null, command);
});

test("the operator-context env spoof still denies from command position only", () => {
  const home = scratchHome();
  const lead = leg("GUARD_OPERATOR_CLI=1 node src/cli.js policy list", { home });
  assert.ok(lead && lead.leg === "store");
  assert.match(lead.matched, /env assignment 'GUARD_OPERATOR_CLI=1'/);
  const viaEnv = leg("env GUARD_OPERATOR_CLI=1 git status", { home });
  assert.ok(viaEnv && viaEnv.leg === "store");
  assert.equal(leg("echo GUARD_OPERATOR_CLI=1", { home }), null);  // an argument, not an assignment
});

// ── the path branch: the same read split for file tools ──────────────────────────────────────

test("path branch: store-file reads deny (the 2026-11-09 split), sessions and ordinary files stay free", () => {
  const home = scratchHome();
  const env = { GUARD_HOME: home, GUARD_SESSIONS: join(home, "sessions") };
  const storeRead = pathSelfModVerdict("Read", { file_path: join(home, "user-policy.json") }, { cwd: "/proj", env });
  assert.ok(storeRead);
  assert.equal(storeRead.leg, "path-access");
  assert.match(storeRead.matched, new RegExp(`the store file ${join(home, "user-policy.json")}`));
  assert.equal(pathSelfModVerdict("mcp__fs__read", { path: join(home, "user-lane.json") }, { cwd: "/proj", env })?.leg, "path-access");
  // the config files are NOT the private store: the credential family's display/silent split
  // governs them (silent repair of the config stays allowed — the 2026-10-16 ruling)
  assert.equal(pathSelfModVerdict("mcp__fs__read", { path: join(home, "config.json") }, { cwd: "/proj", env }), null);
  // sessions hold the user's own words — readable; writes into them keep denying
  assert.equal(pathSelfModVerdict("view", { file_path: join(home, "sessions", "a.json") }, { cwd: "/proj", env }), null);
  assert.equal(pathSelfModVerdict("Write", { file_path: join(home, "sessions", "a.json"), content: "{}" }, { cwd: "/proj", env })?.leg, "path");
  assert.equal(pathSelfModVerdict("Write", { file_path: join(home, "user-policy.json"), content: "{}" }, { cwd: "/proj", env })?.leg, "path");
  assert.equal(pathSelfModVerdict("Read", { file_path: "/proj/README.md" }, { cwd: "/proj", env }), null);
});

// ── end to end: the surfaced verdicts and their named matches ────────────────────────────────

test("e2e: the repro allows, the CLI deny names its invocation, the store read names its path", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: scratchHome() };
  const store = join(env.GUARD_HOME, "user-policy.json");
  // the repro, through the real pipeline with the repo as cwd — a read, allowed
  const repro = await assessAction({ tool: "Bash", input: { command: `grep -n -E 'policy add|--dir|--effect|--expires|--scope' docs/policy.md` }, cwd: REPO },
    { env, fetchImpl: calmBrain });
  assert.equal(repro.level, "allow");
  // the CLI invocation denies pre-brain with the parens and the matched slot
  const cli = await assessAction({ tool: "Bash", input: { command: "node src/cli.js policy add --pattern '*'" }, cwd: "/proj" },
    { env, fetchImpl: calmBrain });
  assert.equal(cli.level, "deny");
  assert.equal(cli.stats, "policy store write");
  assert.equal(cli.category, "Gate Self-Protection");
  assert.match(cli.message, /\(matched: the gate policy-CLI invocation 'src\/cli\.js policy add'\)/);
  // the message skeleton is otherwise byte-identical: the remaining guidance sentences verbatim
  assert.match(cli.message, /Do not try to work around it in any way; no substitution serves the user's goal here\./);
  assert.match(cli.message, /they run it in their own terminal\.$/);
  // a real store read denies as policy store access, naming the resolved path
  const read = await assessAction({ tool: "Bash", input: { command: `cat ${store}` }, cwd: "/proj" }, { env, fetchImpl: calmBrain });
  assert.equal(read.level, "deny");
  assert.equal(read.stats, "policy store access");
  assert.match(read.message, new RegExp(`\\(matched: the private store path ${store.replace(/\//g, "\\/")}\\)`));
  // a redirect write keeps the store-write parens the decision record pins
  const write = await assessAction({ tool: "Bash", input: { command: `echo '[]' > ${store}` }, cwd: "/proj" }, { env, fetchImpl: calmBrain });
  assert.equal(write.stats, "policy store write");
  // gate source writes unchanged
  const src = await assessAction({ tool: "Bash", input: { command: "sed -i 's/a/b/' src/guard.js" }, cwd: "/proj" }, { env, fetchImpl: calmBrain });
  assert.equal(src.stats, "gate source write");
  assert.match(src.message, /\(matched: the write shape '/);
});

test("e2e: the floor needs no brain — a store read denies under a dead brain (degradation floor)", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: scratchHome() };
  const down = async () => { throw new Error("connect ECONNREFUSED"); };
  const r = await assessAction({ tool: "Bash", input: { command: `cat ${join(env.GUARD_HOME, "user-policy.json")}` }, cwd: "/proj" },
    { env, fetchImpl: down });
  assert.equal(r.level, "deny");
  assert.equal(r.stats, "policy store access");
});

test("the whole-layer shape: alwaysDeny classifies the family and carries no floor name for self-mod", () => {
  const home = scratchHome();
  const ad = alwaysDeny("Bash", { command: "unjangled-guardrails policy add --tool x" }, { cwd: "/proj", env: { GUARD_HOME: home } });
  assert.equal(ad.family, "self-mod");
  assert.equal(ad.stats, "policy store write");
  assert.ok(!("floor" in ad), "self-mod rows record no floor name (the decision-record shape)");
  assert.equal(alwaysDeny("Bash", { command: `grep -n effect docs/policy.md` }, { cwd: "/proj", env: { GUARD_HOME: home } }), null);
});
