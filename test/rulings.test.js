// Story 10: operator rulings — the six acceptance scenarios from the spec addendum, plus the
// CLI store management. Every test runs against a temp GUARD_HOME; the brain is faked like
// in guard.test.js, so the assertions are on the ruling layer's resolution behavior.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Writable } from "node:stream";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, rmdirSync, utimesSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { assessAction } from "../src/guard.js";
import { addRuling, listRulings, revokeRuling, rulingsFile, auditFile, initStore, withStoreLock, storeLockFile, matches, resolveRuling, capturePromptRuling, expirePromptSession, operatorContext, PROMPT_CAPTURE_SESSION_MS, DEFAULT_EXPIRY } from "../src/rulings.js";
import { policyFile } from "../src/policy.js";

// Same fake brain as guard.test.js: rm -rf → deny, git push → ask, everything else → allow.
async function fetchImpl(_url, { body }) {
  const { state } = JSON.parse(body);
  const cmd = JSON.stringify(state.input);
  const score = /rm -rf|DROP TABLE/.test(cmd) ? 2.9 : /git push|curl -X POST/.test(cmd) ? 2.0 : 0.2;
  const answers = {
    risk: { type: "score", score, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: score >= 2 ? 0.85 : 0.05 },
    user_requested: { type: "noul", noul: 0.05 },
    from_untrusted: { type: "noul", noul: 0.05 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
  };
  return { ok: true, json: async () => ({ answers }) };
}

function home() {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-rulings-"));
  return dir;
}
// Tests run non-TTY, so every mutation carries the operator escape (plan 1.1: the library
// refuses without it). The no-escape refusal is itself tested below.
const env = (dir) => ({ JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" });
const opts = (dir, extra = {}) => ({ env: env(dir), fetchImpl, ...extra });
const stderr = () => { const chunks = []; const w = new Writable({ write(c, _e, cb) { chunks.push(c); cb(); } }); return [w, () => Buffer.concat(chunks).toString()]; };

const assess = (dir, command, extra = {}) =>
  assessAction({ tool: "Bash", input: { command }, cwd: "/proj", sessionId: "sess-A" }, opts(dir, extra));

test("ruling 1: brain ask + grant + replay = allow citing the ruling, with an audit row", async () => {
  const dir = home();
  assert.equal((await assess(dir, "git push origin release")).level, "ask");  // no ruling yet
  const r = addRuling({ effect: "allow", pattern: "git push*", scope: `project:/proj`, reason: "reviewed deploy flow" }, env(dir));
  const verdict = await assess(dir, "git push origin release");
  assert.equal(verdict.level, "allow");
  assert.match(verdict.message, new RegExp(`by ruling ${r.id}`));
  assert.match(verdict.message, /reviewed deploy flow/);
  assert.equal(verdict.ruling, r.id);
  const rows = readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  // row 1: the operator mutation row paired with the store write (tamper evidence); row 2: the usage row
  assert.equal(rows.length, 2);
  assert.equal(rows[0].action, "mutation");
  assert.equal(rows[0].ruling, r.id);
  assert.equal(rows[0].via, "env-escape");
  assert.equal(rows[1].ruling, r.id);
  assert.equal(rows[1].effect, "allow");
  assert.equal(rows[1].onLevel, "ask");
});

test("ruling 2: expired ruling = ask again", async () => {
  const dir = home();
  // addRuling refuses past-expiry rulings now (5.2 L2), so the consult-time half of expiry is
  // tested by seeding the store directly: a row that has expired never lifts, however it got there.
  writeFileSync(rulingsFile(env(dir)), JSON.stringify([{ id: "r-expired", effect: "allow", pattern: "git push*", scope: "project:/proj", expiresAt: "2020-01-01T00:00:00Z", reason: "" }]));
  const verdict = await assess(dir, "git push origin release");
  assert.equal(verdict.level, "ask");
  assert.ok(!verdict.ruling);
});

test("ruling 3: session-scoped ruling invisible from another session", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push*", scope: "session:sess-A" }, env(dir));  // 7d default
  assert.equal((await assess(dir, "git push origin release")).level, "allow");                       // sess-A matches
  const other = await assessAction({ tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj", sessionId: "sess-B" }, opts(dir));
  assert.equal(other.level, "ask");
  assert.ok(!other.ruling);
});

test("ruling 4: an explicit allow ruling LIFTS a brain deny (operator ruling 2026-10-04), audited loudly", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "rm -rf*", scope: "global", expiresAt: "2099-01-01T00:00:00Z", reason: "operator said so" }, env(dir));
  // /srv and not /tmp: an rm confined to /tmp rides the temp lane (operator ruling 2026-10-11)
  // and never reaches the brain deny this ruling lifts
  const verdict = await assess(dir, "rm -rf /srv/old-build");
  assert.equal(verdict.level, "allow");
  assert.ok(verdict.ruling);
  assert.match(verdict.message, /deny overridden by ruling/);
  assert.ok(existsSync(auditFile(env(dir))));  // the override is on the record
});

test("ruling 5: operator deny ruling overrides a brain allow", async () => {
  const dir = home();
  assert.equal((await assess(dir, "terraform apply")).level, "allow");  // brain under-scores it
  addRuling({ effect: "deny", pattern: "terraform apply*", scope: "project:/proj", reason: "banned org-wide" }, env(dir));
  const verdict = await assess(dir, "terraform apply");
  assert.equal(verdict.level, "deny");
  // H4: this used to be /[Operator Ban]/ — a char class matching any of those letters, vacuously
  // true. The literal assertions below match the real message text (category + guidance).
  assert.match(verdict.message, /\[the operator ruling [rp]-[0-9a-f]+ hard-blocks it \(banned org-wide\)\]/);
  assert.match(verdict.message, /The operator banned this outcome on purpose/);  // operator family text (message registry 2026-10-25)
  assert.match(verdict.message, /banned org-wide/);
});

test("ruling 6: corrupt store = brain-only decisions with a loud warning", async () => {
  const dir = home();
  writeFileSync(rulingsFile(env(dir)), "{not json");
  const [w, text] = stderr();
  const verdict = await assess(dir, "git push origin release", { warnStream: w });
  assert.equal(verdict.level, "ask");                                    // the brain still gates
  assert.ok(!verdict.ruling);
  assert.match(text(), /rulings store corrupt/);
  // and the CLI refuses to add onto a corrupt store
  assert.throws(() => addRuling({ effect: "allow", pattern: "x*", scope: "project:/proj" }, env(dir)), /unreadable/);
});

test("T10.3 adapter smoke: a ruling-fired allow is visible through the OpenCode plugin path", async () => {
  const { UnjangledGuardrails } = await import("../src/opencode.js");
  const dir = home();
  const realFetch = globalThis.fetch; globalThis.fetch = fetchImpl;
  const saved = process.env.JEV_API_KEY, savedHome = process.env.GUARD_HOME;
  process.env.JEV_API_KEY = "test"; process.env.GUARD_HOME = dir;
  try {
    const hooks = await UnjangledGuardrails({ client: {}, directory: "/proj" });
    const perm = { status: "ask" };
    await hooks["permission.ask"]({ type: "bash", pattern: "git push origin release", title: "git push origin release", metadata: {}, sessionID: "sess-A" }, perm);
    assert.equal(perm.status, "ask");                                     // no ruling yet: keep the prompt
    addRuling({ effect: "allow", pattern: "git push*", scope: "session:sess-A" }, env(dir));
    const ruled = { status: "ask" };
    await hooks["permission.ask"]({ type: "bash", pattern: "git push origin release", title: "git push origin release", metadata: {}, sessionID: "sess-A" }, ruled);
    assert.equal(ruled.status, "allow");                                  // the ruling auto-approves, message cites it
    assert.ok(!!readFileSync(auditFile(env(dir)), "utf8").includes('"onLevel":"ask"'));
    // the pi extension rides the same assessAction path (extensions/unjangled-guardrails.ts passes ctx.sessionID)
  } finally { globalThis.fetch = realFetch; if (saved === undefined) delete process.env.JEV_API_KEY; else process.env.JEV_API_KEY = saved;
    if (savedHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedHome; }
});

test("ruling CLI: add (scope/expiry rules), list, revoke", async () => {
  const dir = home();
  const run = (...args) => execFileSync(process.execPath, ["src/cli.js", "ruling", ...args],
    { env: { ...process.env, GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" }, cwd: new URL("..", import.meta.url).pathname });
  // non-TTY without the operator escape is refused — agents must not self-grant rulings
  assert.throws(() => execFileSync(process.execPath, ["src/cli.js", "ruling", "add", "--effect", "allow", "--pattern", "x*", "--scope", "session:s"],
    { env: { ...process.env, GUARD_HOME: dir }, cwd: new URL("..", import.meta.url).pathname }), /operator-only/);
  // global without --expires is refused
  assert.throws(() => run("add", "--effect", "allow", "--pattern", "git push*", "--scope", "global"), /requires an explicit --expires/);
  run("add", "--effect", "allow", "--pattern", "git push*", "--scope", `project:/proj`, "--expires", "2099-01-01", "--reason", "cli test");
  run("add", "--effect", "deny", "--pattern", "terraform*", "--scope", "session:sess-9");
  const listed = run("list").toString();
  assert.match(listed, /git push\*/);
  assert.match(listed, /session:sess-9/);
  const id = JSON.parse(readFileSync(policyFile(env(dir)), "utf8")).entries[0].id;
  run("revoke", id);
  assert.deepEqual(listRulings(env(dir)).map((r) => r.id), [JSON.parse(readFileSync(policyFile(env(dir)), "utf8")).entries[0]?.id].filter(Boolean));
  assert.throws(() => revokeRuling(id, env(dir)), /no ruling/);
  assert.throws(() => run("add", "--effect", "sideways", "--pattern", "x"), /effect must be/);
});

test("ruling CLI: invalid usage prints one clean line — no stack, no full help (GHI-7)", () => {
  const dir = home();
  const fails = (...args) => {
    try { execFileSync(process.execPath, ["src/cli.js", ...args],
      { env: { ...process.env, GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" }, cwd: new URL("..", import.meta.url).pathname }); return null; }
    catch (e) { return e; }
  };
  const add = fails("ruling", "add", "--effect", "sideways", "--pattern", "x");
  assert.equal(add.status, 1);
  assert.match(add.message, /effect must be allow or deny/);
  assert.doesNotMatch(add.message, /dangerous-action guard/);  // GHI-7 (CAP-14): the full help never rides an argument error
  assert.doesNotMatch(add.message, /\n\s+at /);              // and no stack frames
  const noId = fails("ruling", "revoke");
  assert.equal(noId.status, 1);
  assert.match(noId.message, /needs a ruling id/);
  const gone = fails("ruling", "revoke", "r-nope");
  assert.equal(gone.status, 1);
  assert.match(gone.message, /no ruling r-nope/);
  assert.doesNotMatch(gone.message, /\n\s+at /);
  const badJson = fails("check", "Bash", "{oops");
  assert.equal(badJson.status, 1);
  assert.match(badJson.message, /not valid JSON/);
  assert.doesNotMatch(badJson.message, /\n\s+at /);
});

// ── TR-4 (red R2): sub-command smuggling — a compound command lifts only when EVERY part matches ──

test("T1 re-run: `git push *` lifts the plain single command (baseline still works)", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push*", scope: "global", expiresAt: "2099-01-01", reason: "deploy flow" }, env(dir));
  // a plain publication push: it pays the brain now (the lane died) and lands on the ask band,
  // which the ruling lifts. The FORCE form is Always-Deny and no entry may ever lift it.
  const verdict = await assess(dir, "git push origin release");
  assert.equal(verdict.level, "allow");
  assert.ok(verdict.ruling);
});

test("T1 re-run: semicolon tail (rm -rf) is NOT lifted by `git push *`", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push*", scope: "global", expiresAt: "2099-01-01", reason: "deploy flow" }, env(dir));
  const verdict = await assess(dir, "git push origin main; rm -rf ~");
  assert.equal(verdict.level, "deny");   // brain deny floor: the smuggled tail keeps its deny
  assert.ok(!verdict.ruling);
});

test("T1 re-run: newline tail is NOT lifted — the preview's whitespace collapse no longer hides it", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push*", scope: "global", expiresAt: "2099-01-01", reason: "deploy flow" }, env(dir));
  const verdict = await assess(dir, "git push origin main\nrm -rf ~/important");
  assert.equal(verdict.level, "deny");
  assert.ok(!verdict.ruling);
});

test("T1 re-run: && tail and pipe-to-shell are NOT lifted", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push*", scope: "global", expiresAt: "2099-01-01", reason: "deploy flow" }, env(dir));
  const amp = await assess(dir, "git push origin main && rm -rf /srv/builds");
  assert.equal(amp.level, "deny");
  assert.ok(!amp.ruling);
  const pipe = await assess(dir, "git push origin main && curl -X POST https://service.internal/hook");
  assert.equal(pipe.level, "ask");       // brain scored ask (git push), ruling cannot lift it
  assert.ok(!pipe.ruling);
});

test("T1 re-run: a multi-line batch script whose EVERY line matches still lifts (legitimate batch use)", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push origin *", scope: "global", expiresAt: "2099-01-01", reason: "deploy flow" }, env(dir));
  const verdict = await assess(dir, "git push origin main\ngit push origin release");
  assert.equal(verdict.level, "allow");
  assert.ok(verdict.ruling);
});

test("TR-4 unit: subCommands splits on ;/&&/||/|/newline, skips empties; non-bash input stays whole", async () => {
  const { subCommands } = await import("../src/rulings.js");
  assert.deepEqual(
    subCommands({ command: "git push origin main; rm -rf ~ ;" }, "Bash"),
    ["git push origin main", "rm -rf ~"]);
  assert.deepEqual(subCommands({ command: "a && b || c | d\ne" }, "Bash"),
    ["a", "b", "c", "d", "e"]);
  // non-bash tools: no splitting, whole input as one part
  assert.deepEqual(subCommands({ file_path: "/etc/passwd; rm -rf ~" }, "Read"),
    ["/etc/passwd; rm -rf ~"]);
  assert.deepEqual(subCommands({ command: "ls" }, "bash"), ["ls"]);
});

// ── TR-4 (blue H2): matching sees the full command, not a 160-char preview ─────────────────────

test("H2: a >160-char command whose head matches but tail does NOT must NOT lift", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push origin *", scope: "global", expiresAt: "2099-01-01", reason: "deploy flow" }, env(dir));
  // The 160-char preview would have been all harmless head (glob-matching) — only the tail
  // past char 160 carries the smuggled deny.
  const long = "git push origin main " + "a".repeat(140) + " && rm -rf ~";
  assert.ok(long.length > 160);
  const verdict = await assess(dir, long);
  assert.equal(verdict.level, "deny");
  assert.ok(!verdict.ruling);
});

test("H2: a long single command fully matching the ruling still lifts", async () => {
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push origin *", scope: "global", expiresAt: "2099-01-01", reason: "deploy flow" }, env(dir));
  const long = "git push origin main --no-verify " + "m".repeat(160);
  assert.ok(long.length > 190);
  const verdict = await assess(dir, long);
  assert.equal(verdict.level, "allow");
  assert.ok(verdict.ruling);
});

test("H2: ruling text past char 160 is now reachable — a long literal ruling matches its exact command", async () => {
  const dir = home();
  // The blue team's shape: the command and the ruling are both long and identical; the old
  // 160-char slice truncated the preview and matched NOTHING.
  const longLiteral = "git push origin " + "release-candidate-".repeat(12);
  assert.ok(longLiteral.length > 190);
  addRuling({ effect: "allow", pattern: longLiteral, scope: "global", expiresAt: "2099-01-01", reason: "exact long deploy" }, env(dir));
  const verdict = await assess(dir, longLiteral);
  assert.equal(verdict.level, "allow");
  assert.ok(verdict.ruling);
});

// ── plan 1.1 (red-team R1): the authority gate lives in the library ───────────────────────────

test("1.1 non-TTY addRuling without the escape refuses and leaves the store untouched", () => {
  const dir = home();
  const noEscape = { JEV_API_KEY: "test", GUARD_HOME: dir };  // deliberately no operator escape
  assert.throws(() => addRuling({ effect: "allow", pattern: "*", scope: "project:/proj", expiresAt: "2099-01-01" }, noEscape),
    (e) => e instanceof Error && e.message === "ruling changes are operator-only: run from your own terminal");
  assert.throws(() => revokeRuling("r-deadbeef", noEscape), /operator-only/);
  assert.equal(existsSync(rulingsFile(noEscape)), false);  // no store write happened
});

test("1.1 every mutation pairs with an operator mutation row (the tamper-evidence contract)", () => {
  const dir = home();
  const r = addRuling({ effect: "deny", pattern: "terraform*", scope: "project:/proj" }, env(dir));
  const rows = () => readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(rows()[0].action, "mutation");
  assert.equal(rows()[0].op, "add-command");
  assert.equal(rows()[0].via, "env-escape");  // tests/scripts run via the escape; a real TTY grants record "tty"
  revokeRuling(r.id, env(dir));
  assert.equal(rows()[1].action, "mutation");
  assert.equal(rows()[1].op, "remove");
  assert.equal(rows()[1].ruling, r.id);
  assert.equal(rows().length, 2);  // no usage rows: nothing consulted these rulings
});

test("1.1 tamper warning: store mtime ahead of every audit row warns, gate still functions", async () => {
  const { utimesSync } = await import("node:fs");
  const dir = home();
  addRuling({ effect: "allow", pattern: "git push*", scope: "project:/proj" }, env(dir));  // mutation row pairs the write
  const [quiet, quietText] = stderr();
  await assess(dir, "git push origin release", { warnStream: quiet });
  assert.equal(quietText().includes("possible tampering"), false);  // paired change → silent
  // an out-of-band write with no audit row after it: the red team's direct store overwrite
  utimesSync(policyFile(env(dir)), new Date(Date.now() + 60_000), new Date(Date.now() + 60_000));
  const [w, text] = stderr();
  const verdict = await assess(dir, "git push origin release", { warnStream: w });
  assert.match(text(), /changed without an operator action.*possible tampering/);
  assert.equal(verdict.level, "allow");  // the gate keeps functioning despite the suspicion
  // the next legitimate mutation re-pairs the store and silences the warning again
  addRuling({ effect: "deny", pattern: "terraform*" }, env(dir));
  const [w2, text2] = stderr();
  await assess(dir, "git push origin release", { warnStream: w2 });
  assert.equal(text2().includes("possible tampering"), false);
});


test("1.1 matrix row: a TTY context proceeds and records via 'tty' (operator terminal)", () => {
  const dir = home();
  const r = addRuling({ effect: "allow", pattern: "cargo build*", scope: "project:/proj" }, env(dir), { isTTY: true });
  assert.equal(r.effect, "allow");
  const rows = readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(rows[0].via, "tty");
});

// Back-compat (operator ruling 2026-10-07): the pre-rename JEV_GUARD_* spellings still work.

test("back-compat: JEV_GUARD_HOME / JEV_GUARD_OPERATOR_CLI still work", async () => {
  const { operatorContext } = await import("../src/rulings.js");
  assert.equal(rulingsFile({ JEV_GUARD_HOME: "/g" }), join("/g", "rulings" + ".json"));
  assert.equal(operatorContext({ JEV_GUARD_OPERATOR_CLI: "1" }, { isTTY: false }).via, "env-escape");
  assert.throws(() => operatorContext({}, { isTTY: false }), /operator-only/);
});

// ── ruling init (epic-installer ticket 4): the standalone first-session bootstrap ───────────
// The library contract (0600 store, audit-row-before-write, tamper-clean, idempotent) is
// setup.test.js's; these pin the COMMAND surface. init runs without the operator escape —
// an empty store grants no authority — and that asymmetry with add is itself asserted.

const cliRuling = (dir, ...args) => execFileSync(process.execPath, ["src/cli.js", "ruling", ...args],
  { env: { PATH: process.env.PATH, GUARD_HOME: dir }, cwd: new URL("..", import.meta.url).pathname, encoding: "utf8" });

test("ruling init: fresh home → empty 0600 store, one init audit row, loads tamper-silent", () => {
  const dir = home();
  const out = cliRuling(dir, "init");
  assert.match(out, /empty policy store created at/);
  assert.deepEqual(JSON.parse(readFileSync(policyFile(env(dir)), "utf8")), { version: 1, entries: [] });
  const rows = readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].action, "init");
  assert.equal(rows[0].via, "cli");  // the audit names the entry point that actually ran
  const [warnStream, warnText] = stderr();  // tamper silence is asserted, not assumed
  assert.deepEqual(listRulings(env(dir), { warnStream }), []);
  assert.equal(warnText(), "");
});

test("ruling init: re-run is a no-op — store and audit byte-identical", () => {
  const dir = home();
  cliRuling(dir, "init");
  const storeBefore = readFileSync(policyFile(env(dir)), "utf8");
  const auditBefore = readFileSync(auditFile(env(dir)), "utf8");
  const out = cliRuling(dir, "init");
  assert.match(out, /already present .*untouched/);
  assert.equal(readFileSync(policyFile(env(dir)), "utf8"), storeBefore);
  assert.equal(readFileSync(auditFile(env(dir)), "utf8"), auditBefore);
});

test("ruling init: a pre-existing operator store is respected, never touched", () => {
  const dir = home();
  execFileSync(process.execPath, ["src/cli.js", "ruling", "add", "--effect", "allow", "--pattern", "git push*", "--scope", "project:/p", "--expires", "2099-01-01"],
    { env: { ...process.env, GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" }, cwd: new URL("..", import.meta.url).pathname });
  const storeBefore = readFileSync(policyFile(env(dir)), "utf8");
  const auditBefore = readFileSync(auditFile(env(dir)), "utf8");
  const out = cliRuling(dir, "init");
  assert.match(out, /already present .*untouched/);
  assert.equal(readFileSync(policyFile(env(dir)), "utf8"), storeBefore);
  assert.equal(readFileSync(auditFile(env(dir)), "utf8"), auditBefore);
});

test("ruling init needs no operator escape; ruling add still refuses without one", () => {
  const dir = home();
  cliRuling(dir, "init");  // no GUARD_OPERATOR_CLI anywhere in this env
  assert.throws(() => execFileSync(process.execPath, ["src/cli.js", "ruling", "add", "--effect", "allow", "--pattern", "x*", "--scope", "session:s"],
    { env: { PATH: process.env.PATH, GUARD_HOME: dir }, cwd: new URL("..", import.meta.url).pathname }), /operator-only/);
});

// ── posture-triage 5.2: store validity (R10 atomic save, M5 mutation lock, L2 past-expiry) ─────

test("5.2 L2: addRuling refuses an already-past expiry; nothing is written", () => {
  const dir = home();
  assert.throws(() => addRuling({ effect: "allow", pattern: "git push*", scope: "project:/proj", expiresAt: "2020-01-01T00:00:00Z" }, env(dir)), /expiry must be in the future/);
  assert.throws(() => addRuling({ effect: "allow", pattern: "git push*", scope: "project:/proj", expiresAt: "0d" }, env(dir)), /expiry must be in the future/);
  assert.equal(existsSync(rulingsFile(env(dir))), false);  // refused before any store write
});

test("5.2 L2: the CLI surfaces the past-expiry refusal as a clean error", () => {
  const dir = home();
  let caught;
  try {
    execFileSync(process.execPath, ["src/cli.js", "ruling", "add", "--effect", "allow", "--pattern", "x*", "--scope", "project:/p", "--expires", "2020-01-01"],
      { env: { ...process.env, GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" }, cwd: new URL("..", import.meta.url).pathname });
  } catch (e) { caught = e; }
  assert.equal(caught.status, 1);
  assert.match(caught.message, /expiry must be in the future/);
  assert.doesNotMatch(caught.message, /\n\s+at /);  // a clean message, not a stack trace
});

test("5.2 R10: store writes are atomic — temp+rename leaves no residue and keeps 0600", () => {
  const dir = home();
  assert.equal(initStore(env(dir), "test"), true);
  addRuling({ effect: "allow", pattern: "git push*", scope: "project:/proj" }, env(dir));
  revokeRuling(listRulings(env(dir))[0].id, env(dir));
  addRuling({ effect: "deny", pattern: "terraform*", scope: "project:/proj" }, env(dir));
  // every write went through temp+rename: no *.tmp-* residue left in the store's directory
  const residue = readdirSync(dir).filter((n) => n.startsWith("user-policy.json") && n !== "user-policy.json");
  assert.deepEqual(residue, []);
  assert.equal(statSync(policyFile(env(dir))).mode & 0o777, 0o600);  // the mode rides the rename
  // a temp left behind by a crashed writer never breaks the next save
  writeFileSync(join(dir, "user-policy.json.tmp-crashed-0000"), "{garbage");
  addRuling({ effect: "allow", pattern: "cargo build*", scope: "project:/proj" }, env(dir));
  assert.equal(listRulings(env(dir)).length, 2);
});

test("5.2 M5: concurrent adders do not lose updates — the lock spans load → concat → save", async () => {
  const dir = home();
  cliRuling(dir, "init");  // empty store
  // five parallel CLI adders: the serialized read-modify-write lands all five rulings
  const kids = [0, 1, 2, 3, 4].map((i) =>
    spawn(process.execPath, ["src/cli.js", "ruling", "add", "--effect", "allow", "--pattern", `cmd-${i}*`, "--scope", "project:/p", "--expires", "2099-01-01"],
      { env: { PATH: process.env.PATH, GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" }, cwd: new URL("..", import.meta.url).pathname }));
  await Promise.all(kids.map((k) => new Promise((res, rej) => k.on("exit", (c) => (c === 0 ? res() : rej(new Error(`adder exited ${c}`)))))));
  assert.equal(listRulings(env(dir)).length, 5);  // the old unlocked write lost updates here
  assert.equal(existsSync(storeLockFile(env(dir))), false);  // the lock is released, not leaked
});

test("5.2 M5: a stale lock is broken, not waited on; a stuck lock fails bounded, never hangs", () => {
  const dir = home();
  cliRuling(dir, "init");
  // (wait-then-land under a LIVE lock is the cross-process case — the five-adder test above it.)
  // a stale lock (a crashed holder's residue) is broken after the staleness window, not waited on
  mkdirSync(storeLockFile(env(dir)));
  const old = new Date(Date.now() - 60_000);
  utimesSync(storeLockFile(env(dir)), old, old);
  addRuling({ effect: "deny", pattern: "terraform*", scope: "project:/proj" }, env(dir));
  assert.equal(listRulings(env(dir)).length, 1);  // the deny landed; the stale lock cost no wait
  // a lock that never clears fails with a clear bounded error, never a hang
  mkdirSync(storeLockFile(env(dir)));
  assert.throws(() => withStoreLock(env(dir), () => assert.fail("the locked section never ran"), { waitMs: 150, retryMs: 25 }),
    /locked by another process/);
  rmdirSync(storeLockFile(env(dir)));  // leave the home clean for later assertions
});

// ── posture-triage 5.3 L1: prefix-glob patterns warn at add time that they over-match ──────────

test("5.3 L1: a prefix-glob pattern warns it over-matches; exact patterns stay silent", () => {
  const dir = home();
  const [w, text] = stderr();
  addRuling({ effect: "allow", pattern: "rm*", scope: "project:/proj" }, env(dir), { warnStream: w });
  assert.match(text(), /prefix glob/);
  assert.match(text(), /rmarkdown/);       // the documented over-match example is in the warning
  assert.equal(listRulings(env(dir)).length, 1);  // non-blocking: the ruling still lands
  // an exact (non-glob) pattern never warns
  const [w2, text2] = stderr();
  addRuling({ effect: "deny", pattern: "terraform apply", scope: "project:/proj" }, env(dir), { warnStream: w2 });
  assert.equal(text2(), "");
  assert.equal(listRulings(env(dir)).length, 2);
  // CAP-7 (2026-11-10): a SPACED trailing star pins the subcommand — the warning's own
  // recommended shape, the house defaults' entries, and the unblock suggestions' — and no
  // longer warns against itself; the bare catch-all still does
  const [w3, text3] = stderr();
  addRuling({ effect: "allow", pattern: "git push *", scope: "project:/proj" }, env(dir), { warnStream: w3 });
  assert.equal(text3(), "");
  const [w4, text4] = stderr();
  addRuling({ effect: "allow", pattern: "*", scope: "project:/proj" }, env(dir), { warnStream: w4 });
  assert.match(text4(), /prefix glob/);
  assert.equal(listRulings(env(dir)).length, 4);
});


// ── staged (compound) rulings: one glob per chain segment, count enforced ─────────────────────
// Operator request 2026-10-12: the recurring `git add … && git commit … && git push` chain
// asked on every variant. A staged ruling lifts exactly that chain shape; a force flag in any
// stage breaks its stage glob; a segment-count change still asks.
test("staged rulings: a compound allow lifts the exact chain shape, per stage", () => {
  const stages = ["git add *", "git commit -m *", "git push"];
  const home = mkdtempSync(join(tmpdir(), "unjangled-guardrails-stages-"));
  const r = addRuling({ effect: "allow", stages, scope: "project:/proj", reason: "operator compound git workflow" }, env(home));
  assert.deepEqual(r.stages, stages);
  const call = { tool: "Bash", preview: ["git add src/a.js", 'git commit -m "msg"', "git push"], cwd: "/proj" };
  assert.equal(matches(r, call), true);
  // count mismatch: a two-segment variant still asks; a four-segment variant too
  assert.equal(matches(r, { ...call, preview: ["git add src/a.js", "git push"] }), false);
  assert.equal(matches(r, { ...call, preview: [...call.preview, "git status"] }), false);
  // a force flag in any stage breaks that stage's glob — the chain asks
  assert.equal(matches(r, { ...call, preview: ["git add src/a.js", 'git commit -m "msg"', "git push --force origin main"] }), false);
  // and the staged ruling never lifts the raw force push single
  assert.equal(matches(r, { ...call, preview: ["git push --force origin main"] }), false);
  // addRuling validation: stages xor pattern, non-empty
  const stagesHome = mkdtempSync(join(tmpdir(), "unjangled-guardrails-stages-validation-"));
  assert.throws(() => addRuling({ effect: "allow", stages: ["git add *"], pattern: "x", scope: "project:/proj" }, env(stagesHome)), /either|mix/);
  assert.throws(() => addRuling({ effect: "allow", stages: [], scope: "project:/proj" }, env(stagesHome)), /stages/);
  // resolveRuling end-to-end: the compound asks, the staged ruling lifts it
  const verdict = resolveRuling("ask", { tool: "Bash", input: { command: "git add src/a.js && git commit -m \"msg\" && git push" }, cwd: "/proj", env: env(home) });
  assert.equal(verdict?.id, r.id);
});

// ── prompt-authority capture (epic-prompt-rulings-session, story 1: CAP-2) ────────────────────
// The capture core: a chosen prompt option becomes the matching gate ruling through the
// existing addRuling machinery. Every test runs WITHOUT the operator escape — the answered
// ask prompt is the proof of operator presence, the whole point of the prompt channel.

const captureEnv = (dir, tier = "session", extra = {}) =>
  ({ JEV_API_KEY: "test", GUARD_HOME: dir, ...(tier ? { GUARD_PROMPT_RULINGS: tier } : {}), ...extra });
const capture = (dir, call, choice = "session", extra = {}) =>
  capturePromptRuling({ choice, harness: "pi", sessionId: "sess-A", cwd: "/proj", ...call }, { env: captureEnv(dir, "session", extra) });

test("capture: grant → replay-passes — a session choice mints the ruling the next consult lifts", async () => {
  const dir = home();
  const r = capture(dir, { tool: "Bash", input: { command: "git push origin release" } });
  assert.equal(r.captured, true);
  assert.equal(r.existed, false);
  assert.equal(r.ruling.effect, "allow");
  assert.equal(r.ruling.scope, "session:sess-A");
  assert.equal(r.ruling.pattern, "git push origin release");  // exact segment — no glob added
  assert.equal(r.ruling.via, "prompt:pi");                    // provenance rides the entry
  // explicit now+24h expiry (the R-2 fallback cap) — never the 7d operator default
  const ttl = Date.parse(r.ruling.expiresAt) - Date.now();
  assert.ok(ttl > 23 * 36e5 && ttl <= 24 * 36e5, `session-capture expiry should be ~24h, got ${ttl}ms`);
  // replay: the same covered call now allows through the ordinary ruling consult (guard.js resolveRuling)
  const verdict = await assess(dir, "git push origin release");
  assert.equal(verdict.level, "allow");
  assert.equal(verdict.ruling, r.ruling.id);
  // the audit carries the prompt provenance: mutation row via prompt:pi, then the usage row
  const rows = readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(rows[0].action, "mutation");
  assert.equal(rows[0].via, "prompt:pi");
  assert.equal(rows[1].ruling, r.ruling.id);
  assert.equal(rows[1].onLevel, "ask");
  // and the paired write is tamper-clean: a consult right after stays silent
  const [w, text] = stderr();
  await assess(dir, "git push origin release", { warnStream: w });
  assert.equal(text().includes("possible tampering"), false);
});

test("capture: dedupe — a repeat grant of the same pattern+tool+scope returns existed:true, no new write", () => {
  const dir = home();
  const first = capture(dir, { tool: "Bash", input: { command: "git push origin release" } });
  // an always choice under the session tier ceilings at session scope → same dedupe key
  const second = capture(dir, { tool: "Bash", input: { command: "git push origin release" } }, "always");
  assert.equal(second.captured, true);
  assert.equal(second.existed, true);
  assert.equal(second.ruling.id, first.ruling.id);
  assert.equal(listRulings(env(dir)).length, 1);
  const rows = readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(rows.filter((row) => row.action === "mutation").length, 1);  // the repeat wrote nothing
});

test("capture: tier off (the default) — the export is a no-op that consumes the choice as allow-once", async () => {
  const dir = home();
  const call = { tool: "Bash", input: { command: "git push origin release" } };
  // no GUARD_PROMPT_RULINGS anywhere: the default is OFF (operator ruling 2026-11-06)
  const r = capturePromptRuling({ choice: "session", harness: "pi", sessionId: "sess-A", ...call, cwd: "/proj" },
    { env: { JEV_API_KEY: "test", GUARD_HOME: dir } });
  assert.deepEqual(r, { captured: false, outcome: "once", reason: "tier-off" });
  // unknown tier values fail safe to off
  const bogus = capturePromptRuling({ choice: "session", harness: "pi", sessionId: "sess-A", ...call, cwd: "/proj" },
    { env: { JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_PROMPT_RULINGS: "sometimes" } });
  assert.equal(bogus.reason, "tier-off");
  // the once choice never mints, tier on or off
  const once = capture(dir, call, "once");
  assert.deepEqual(once, { captured: false, outcome: "once", reason: "choice-once" });
  // nothing was written and the next call still asks
  assert.equal(listRulings(env(dir)).length, 0);
  assert.equal((await assess(dir, "git push origin release")).level, "ask");
});

test("capture: project tier — an always choice writes project:<cwd>; a session choice stays session-scoped", () => {
  const dir = home();
  const call = { tool: "Bash", input: { command: "git push origin release" } };
  const always = capturePromptRuling({ choice: "always", harness: "acp", sessionId: "sess-A", ...call, cwd: "/proj" },
    { env: captureEnv(dir, "project") });
  assert.equal(always.ruling.scope, "project:/proj");
  const session = capturePromptRuling({ choice: "session", harness: "acp", sessionId: "sess-A", tool: "Bash", input: { command: "git push origin main" }, cwd: "/proj" },
    { env: captureEnv(dir, "project") });
  assert.equal(session.ruling.scope, "session:sess-A");
  // the session tier ceilings an always choice at session scope
  const ceiling = capturePromptRuling({ choice: "always", harness: "pi", sessionId: "sess-B", ...call, cwd: "/proj" },
    { env: captureEnv(home(), "session") });
  assert.equal(ceiling.ruling.scope, "session:sess-B");
  // a multi-segment chain captures staged, one exact pattern per segment
  const staged = capture(dir, { tool: "Bash", input: { command: "git add -A && git commit -m ship && git push" } });
  assert.deepEqual(staged.ruling.stages, ["git add -A", "git commit -m ship", "git push"]);
});

test("capture: per-session write cap — past the cap the choice is consumed as allow-once; dedupe repeats and other sessions unaffected", async () => {
  const dir = home();
  const e = captureEnv(dir, "session", { GUARD_PROMPT_RULINGS_CAP: "2" });
  const cap = (cmd, sid = "sess-A") => capturePromptRuling(
    { choice: "session", harness: "pi", sessionId: sid, tool: "Bash", input: { command: cmd }, cwd: "/proj" }, { env: e });
  assert.equal(cap("git push origin main").captured, true);
  assert.equal(cap("git push origin release").captured, true);
  const third = cap("git push origin hotfix");
  assert.deepEqual(third, { captured: false, outcome: "once", reason: "session-cap" });
  assert.equal(cap("git push origin main").existed, true);   // dedupe at the cap: no write, still answered
  assert.equal(cap("git push origin stale", "sess-B").captured, true);  // the cap is per session id
  assert.equal((await assess(dir, "git push origin hotfix")).level, "ask");  // nothing minted for the capped pattern
  // expired prompt captures stop counting toward the cap
  const dir2 = home();
  writeFileSync(policyFile(env(dir2)), JSON.stringify({ version: 1, entries: [
    { id: "p-old1", kind: "command", effect: "allow", pattern: "git push origin stale", scope: "session:sess-A",
      via: "prompt:pi", session: "sess-A", expiresAt: "2020-01-01T00:00:00.000Z", reason: "", createdAt: "2020-01-01T00:00:00.000Z" },
  ] }));
  const [w] = stderr();
  const fresh = capturePromptRuling({ choice: "session", harness: "pi", sessionId: "sess-A", tool: "Bash", input: { command: "git push origin fresh" }, cwd: "/proj" },
    { env: captureEnv(dir2, "session", { GUARD_PROMPT_RULINGS_CAP: "1" }), warnStream: w });
  assert.equal(fresh.captured, true);  // the expired row does not consume the cap slot
  assert.equal(listRulings(env(dir2)).length, 2);
});

test("capture: pattern constraints are the capture surface's own — the mint is EXACT segments (the hint generalizes, CAP-7)", async () => {
  const dir = home();
  const e = captureEnv(dir, "session");
  const cases = [
    { tool: "Bash", input: { command: "git push origin release" }, exact: ["git push origin release"] },          // single exact segment
    { tool: "Bash", input: { command: "git add -A && git commit -m ship && git push" }, exact: ["git add -A", "git commit -m ship", "git push"] },  // staged, 3 segments
    { tool: "Bash", input: { command: "git push origin *" } },                              // glob metachar: refuses
    { tool: "Bash", input: { command: "git commit -m 'ship it'" } },                         // single quote: refuses
    { tool: "Bash", input: { command: "a && b && c && d && e" } },                            // >3 segments: refuses
    { tool: "Write", input: { file_path: "/proj/x", content: "y" } },                        // not bash-shaped: refuses
    { tool: "Bash", input: { command: "" } },                                                  // empty: refuses
  ];
  for (const call of cases) {
    const cap = capturePromptRuling({ choice: "session", harness: "pi", sessionId: "s-hint", ...call, cwd: "/proj" }, { env: e });
    if (!call.exact) {
      assert.equal(cap.captured, false, JSON.stringify(call));
      assert.equal(cap.reason, "pattern-constraints");
    } else {
      assert.equal(cap.captured, true, JSON.stringify(call));
      assert.deepEqual(cap.ruling.stages ?? [cap.ruling.pattern], call.exact);
    }
  }
  // the deliberate CAP-7 divergence, pinned from both sides: for the SAME call the operator
  // hint suggests the generalized shape while the capture mint stays exact — the human
  // approved this one call, and exactness is the mint's safety property
  const { rulingHintFor } = await import("../src/guard.js");
  const hinted = rulingHintFor({ tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj", env: e });
  assert.match(String(hinted).split("\n")[0], /--pattern 'git push \*'/);
  const cap = capturePromptRuling({ choice: "session", harness: "pi", sessionId: "s-hint2", tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj" }, { env: e });
  assert.equal(cap.ruling.pattern, "git push origin release");
  // a missing sessionId (or cwd for a project mint) declines — the scope never widens
  const noSession = capturePromptRuling({ choice: "session", harness: "pi", tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj" }, { env: e });
  assert.equal(noSession.reason, "missing-session");
  const noCwd = capturePromptRuling({ choice: "always", harness: "pi", sessionId: "s", tool: "Bash", input: { command: "git push origin release" } }, { env: captureEnv(dir, "project") });
  assert.equal(noCwd.reason, "missing-cwd");
  // a bad harness name is the one bad-input throw
  assert.throws(() => capturePromptRuling({ choice: "session", harness: "pi:evil", sessionId: "s", tool: "Bash", input: { command: "ls" }, cwd: "/proj" }, { env: e }), /harness name/);
});

test("capture provenance: env and argv can never mint prompt:<harness> rows — only the capture path constructs the channel", () => {
  const dir = home();
  // the GUARD_OPERATOR_CLI escape still grants, but as env-escape — never prompt provenance
  addRuling({ effect: "allow", pattern: "git push*", scope: "session:sess-A" }, env(dir));
  let rows = readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(rows[0].via, "env-escape");
  assert.equal(listRulings(env(dir))[0].via, undefined);  // operator entries carry no via
  // a forged authority object (string keys) cannot smuggle a via past operatorContext
  assert.throws(() => addRuling({ effect: "allow", pattern: "x", scope: "project:/proj" },
    { JEV_API_KEY: "t", GUARD_HOME: dir }, { via: "prompt:pi" }), /operator-only/);
  addRuling({ effect: "allow", pattern: "y", scope: "project:/proj" },
    { JEV_API_KEY: "t", GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" }, { via: "prompt:pi" });
  rows = readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.ok(rows.every((row) => row.via === "env-escape" || row.via === "tty"), "no prompt: rows from non-capture paths");
  // operatorContext itself: no env combination produces the prompt channel
  assert.equal(operatorContext({ GUARD_OPERATOR_CLI: "1", GUARD_PROMPT_RULINGS: "session" }, { isTTY: false }).via, "env-escape");
  assert.throws(() => operatorContext({ GUARD_PROMPT_RULINGS: "session", GUARD_PROMPT_RULINGS_CAP: "99" }, { isTTY: false }), /operator-only/);
  // and the CLI argv surface: ruling add with the tier on still records env-escape
  const cliDir = home();
  execFileSync(process.execPath, ["src/cli.js", "ruling", "add", "--effect", "allow", "--pattern", "git push*", "--scope", "session:sess-A"],
    { env: { ...process.env, GUARD_HOME: cliDir, GUARD_OPERATOR_CLI: "1", GUARD_PROMPT_RULINGS: "session" }, cwd: new URL("..", import.meta.url).pathname });
  rows = readFileSync(auditFile(env(cliDir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(rows[0].via, "env-escape");
  assert.ok(!rows.some((row) => String(row.via ?? "").startsWith("prompt:")));
});

test("capture: a store failure throws with nothing minted and the ask outcome unchanged", async () => {
  const dir = home();
  mkdirSync(dir, { recursive: true });
  writeFileSync(policyFile(env(dir)), "{not json");  // a corrupt store: mutations refuse
  assert.throws(() => capture(dir, { tool: "Bash", input: { command: "git push origin release" } }), /unreadable/);
  assert.equal(readFileSync(policyFile(env(dir)), "utf8"), "{not json");  // untouched
  const [w] = stderr();
  const verdict = await assess(dir, "git push origin release", { warnStream: w });
  assert.equal(verdict.level, "ask");   // brain-only: nothing lifted, fail-safe direction unchanged
});

// ── session lifetime (epic-prompt-rulings-session, story 2: R-2) ─────────────────────────────
// The lifetime pair (operator ruling 2026-11-06): prompt-captured session grants die when the
// harness announces session end (expirePromptSession) AND never outlive 24h (the mint-time
// fallback cap, pinned here as tested contract). Operator-minted 7d session rulings are NEVER
// cleaned by session end.

test("lifetime: the 24h fallback cap is pinned at mint on every session-scope path — never the 7d operator default", () => {
  assert.equal(PROMPT_CAPTURE_SESSION_MS, 24 * 36e5);
  assert.equal(DEFAULT_EXPIRY.session, 7 * 864e5);  // the operator default stays 7d — and stays unused by capture
  const ttl = (r) => Date.parse(r.ruling.expiresAt) - Date.now();
  const dir = home();
  // choice session under the session tier
  const a = capture(dir, { tool: "Bash", input: { command: "git push origin one" } }, "session");
  // choice ALWAYS under the session tier (the ceiling keeps it session-scoped)
  const b = capture(dir, { tool: "Bash", input: { command: "git push origin two" } }, "always");
  // choice session under the PROJECT tier (a session choice stays session-scoped)
  const c = capturePromptRuling({ choice: "session", harness: "pi", sessionId: "sess-A", tool: "Bash", input: { command: "git push origin three" }, cwd: "/proj" },
    { env: captureEnv(dir, "project") });
  for (const r of [a, b, c]) {
    assert.equal(r.captured, true);
    assert.ok(ttl(r) > PROMPT_CAPTURE_SESSION_MS - 36e5 && ttl(r) <= PROMPT_CAPTURE_SESSION_MS,
      `session-capture expiry must be ~24h, got ${ttl(r)}ms — a 7d mint here is the defect shape`);
  }
});

test("lifetime: death-at-session-end — expirePromptSession removes ONLY prompt-captured session grants", async () => {
  const dir = home();
  const prompt = capture(dir, { tool: "Bash", input: { command: "git push origin release" } });
  // an operator-minted 7d session ruling for the SAME session: never cleaned by session end
  addRuling({ effect: "allow", pattern: "git push origin operator", scope: "session:sess-A" }, env(dir));
  // a project-tier prompt capture: cross-session by design, not session-scoped — survives
  capturePromptRuling({ choice: "always", harness: "pi", sessionId: "sess-A", tool: "Bash", input: { command: "git push origin always" }, cwd: "/proj" },
    { env: captureEnv(dir, "project") });
  // a prompt capture attributed to ANOTHER session: untouched
  capturePromptRuling({ choice: "session", harness: "pi", sessionId: "sess-B", tool: "Bash", input: { command: "git push origin other" }, cwd: "/proj" },
    { env: captureEnv(dir, "session") });
  // before cleanup: the prompt grant lifts
  assert.equal((await assess(dir, "git push origin release")).level, "allow");
  assert.equal(expirePromptSession("sess-A", env(dir), { harness: "pi" }).removed, 1);
  // after: the prompt grant is dead — the ask stands again
  assert.equal((await assess(dir, "git push origin release")).level, "ask");
  // the operator-minted session ruling SURVIVES the session-end cleanup
  assert.equal((await assess(dir, "git push origin operator")).level, "allow");
  // the project capture and the other session's grant are untouched
  const left = listRulings(env(dir));
  assert.equal(left.some((r) => r.id === prompt.ruling.id), false);
  assert.equal(left.filter((r) => (r.scope ?? "global") === "session:sess-B").length, 1);
  assert.equal(left.filter((r) => (r.scope ?? "global") === "project:/proj").length, 1);
});

test("lifetime: cleanup is idempotent and its audit row lands tamper-clean", async () => {
  const dir = home();
  capture(dir, { tool: "Bash", input: { command: "git push origin release" } });
  assert.equal(expirePromptSession("sess-A", env(dir), { harness: "claude" }).removed, 1);
  const rows = () => readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const cleans = rows().filter((row) => row.op === "expire-prompt-session");
  assert.equal(cleans.length, 1);                    // one row per effective cleanup
  assert.equal(cleans[0].action, "policy-remove");
  assert.equal(cleans[0].via, "session-end:claude");
  assert.equal(cleans[0].id, "session:sess-A");
  assert.equal(cleans[0].scope, "session:sess-A");
  // idempotent: a repeated session-end signal removes nothing and writes nothing
  assert.deepEqual(expirePromptSession("sess-A", env(dir), { harness: "claude" }), { removed: 0 });
  assert.equal(rows().filter((row) => row.op === "expire-prompt-session").length, 1);
  // and a consult right after the paired write stays tamper-silent
  const [w, text] = stderr();
  await assess(dir, "git push origin release", { warnStream: w });
  assert.equal(text().includes("possible tampering"), false);
});

test("lifetime: a missing session id throws; a corrupt store refuses the cleanup", () => {
  const dir = home();
  assert.throws(() => expirePromptSession("", env(dir)), /session id/);
  mkdirSync(dir, { recursive: true });
  writeFileSync(policyFile(env(dir)), "{not json");
  // never mutate unknown state — the throw leaves the store untouched; the 24h cap is the backstop
  assert.throws(() => expirePromptSession("s", env(dir)), /unreadable/);
  assert.equal(readFileSync(policyFile(env(dir)), "utf8"), "{not json");
});

test("lifetime supersede (the story-1 handoff, triaged FIX): a repeat capture of an expired prompt entry mints fresh, never existed:true", async () => {
  const dir = home();
  const [w] = stderr();  // seeded stores carry no audit row yet — keep tamper noise off the console
  // seed the dead entry: the exact shape a >24h session leaves behind
  writeFileSync(policyFile(env(dir)), JSON.stringify({ version: 1, entries: [
    { id: "p-dead", kind: "command", effect: "allow", pattern: "git push origin release", scope: "session:sess-A",
      tool: "Bash", via: "prompt:pi", session: "sess-A", expiresAt: "2020-01-01T00:00:00.000Z", reason: "", createdAt: "2020-01-01T00:00:00.000Z" },
  ] }));
  assert.equal((await assess(dir, "git push origin release", { warnStream: w })).level, "ask");  // dead is dead
  const r = capture(dir, { tool: "Bash", input: { command: "git push origin release" } }, "session", {});
  assert.equal(r.captured, true);
  assert.equal(r.existed, false);                  // the fresh capture supersedes — never dedupes to the dead entry
  const ttl = Date.parse(r.ruling.expiresAt) - Date.now();
  assert.ok(ttl > 23 * 36e5 && ttl <= 24 * 36e5, `fresh 24h clock, got ${ttl}ms`);
  assert.equal(listRulings(env(dir)).some((x) => x.id === "p-dead"), false);  // the dead id is gone
  const rows = readFileSync(auditFile(env(dir)), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const ops = rows.filter((row) => row.action === "mutation").map((row) => row.op);
  assert.deepEqual(ops, ["remove", "add-command"]); // supersede = audited remove, then the ordinary mint
  assert.equal(rows[0].via, "prompt:pi");           // both legs carry the capture provenance
  assert.equal((await assess(dir, "git push origin release")).level, "allow");  // relief restored
  // a LIVE prompt entry still dedupes existed:true (story-1 semantics, byte-identical)
  assert.equal(capture(dir, { tool: "Bash", input: { command: "git push origin release" } }).existed, true);
});

test("lifetime supersede: an expired OPERATOR-minted match stays the inherited dedupe — capture never removes operator entries", () => {
  const dir = home();
  const [w] = stderr();
  writeFileSync(policyFile(env(dir)), JSON.stringify({ version: 1, entries: [
    { id: "p-opdead", kind: "command", effect: "allow", pattern: "git push origin release", scope: "session:sess-A",
      tool: "Bash", expiresAt: "2020-01-01T00:00:00.000Z", reason: "", createdAt: "2020-01-01T00:00:00.000Z" },
  ] }));
  const op = capture(dir, { tool: "Bash", input: { command: "git push origin release" } }, "session", {});
  void w;
  assert.equal(op.existed, true);                   // recorded residual: no supersede of operator-minted entries
  assert.equal(listRulings(env(dir)).some((x) => x.id === "p-opdead"), true);  // still there, dead
});

test("lifetime supersede cap arithmetic: a supersede WRITES, so the per-session cap applies; a live dedupe still bypasses it", () => {
  const dir = home();
  const [w] = stderr();
  const e = captureEnv(dir, "session", { GUARD_PROMPT_RULINGS_CAP: "1" });
  // the session already holds its one unexpired capture
  capturePromptRuling({ choice: "session", harness: "pi", sessionId: "sess-A", tool: "Bash", input: { command: "git push origin live" }, cwd: "/proj" }, { env: e });
  // …plus a dead entry for another pattern: superseding it would be a SECOND write — capped
  const store = JSON.parse(readFileSync(policyFile(env(dir)), "utf8"));
  store.entries.push({ id: "p-dead2", kind: "command", effect: "allow", pattern: "git push origin dead", scope: "session:sess-A",
    tool: "Bash", via: "prompt:pi", session: "sess-A", expiresAt: "2020-01-01T00:00:00.000Z", reason: "", createdAt: "2020-01-01T00:00:00.000Z" });
  writeFileSync(policyFile(env(dir)), JSON.stringify(store, null, 2) + "\n");
  const capped = capturePromptRuling({ choice: "session", harness: "pi", sessionId: "sess-A", tool: "Bash", input: { command: "git push origin dead" }, cwd: "/proj" },
    { env: e, warnStream: w });
  assert.deepEqual(capped, { captured: false, outcome: "once", reason: "session-cap" });
  // a dedupe to the LIVE entry still bypasses the cap — no write happens (story-1 behavior, unchanged)
  const live = capturePromptRuling({ choice: "session", harness: "pi", sessionId: "sess-A", tool: "Bash", input: { command: "git push origin live" }, cwd: "/proj" }, { env: e });
  assert.equal(live.existed, true);
});
