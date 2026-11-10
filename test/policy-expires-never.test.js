// GHI-7 (CAP-14, the policy CLI input contract): `--expires never` is accepted as the
// explicit permanent spelling on command entries, a bad value refuses with ONE line naming
// the accepted forms, an argument error never dumps the full help, and --expires on the
// tool kinds refuses cleanly instead of being silently dropped. Entry 17 (operator ruling
// 5) has since LANDED dir-entry expiry — the dir refusal this file pinned was the marked
// seam and is DELIBERATELY flipped: dir entries take --expires now, and that acceptance
// lives in test/policy-flag-matrix.test.js ("the flipped seam").
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { addCommandEntry, policyFile } from "../src/policy.js";
import { addRuling, resolveRuling } from "../src/rulings.js";

const REPO = new URL("..", import.meta.url).pathname;

function home() {
  return mkdtempSync(join(tmpdir(), "unjangled-guardrails-expires-never-"));
}

// The CLI runs non-TTY in tests, so mutations carry the operator escape (plan 1.1) — same
// env shape as test/rulings.test.js.
const env = (dir) => ({ JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" });

const run = (dir, ...args) => execFileSync(process.execPath, ["src/cli.js", ...args],
  { env: env(dir), cwd: REPO });
const fails = (dir, ...args) => {
  try { run(dir, ...args); return null; }
  catch (e) { return e; }
};
const store = (dir) => JSON.parse(readFileSync(policyFile(env(dir)), "utf8"));
const commandEntries = (dir) => store(dir).entries.filter((e) => (e.kind ?? "tool") === "command");
const USAGE_HEADER = /dangerous-action guard for coding agents/;  // the full-help banner — never after an error

test("the repro: policy add --expires never creates a permanent entry (GHI-7)", () => {
  const dir = home();
  const out = run(dir, "policy", "add", "--effect", "allow", "--pattern", "git add *", "--expires", "never").toString();
  assert.match(out, /expires never\)/);                    // the confirm line speaks the display grammar
  const [entry] = commandEntries(dir);
  assert.equal(entry.effect, "allow");
  assert.equal(entry.pattern, "git add *");
  assert.equal("expiresAt" in entry, false);               // never = NO field, byte-identical to expiry-less entries
  const list = run(dir, "policy", "list").toString();
  assert.match(list, /expires=never/);
  assert.doesNotMatch(list, /\[EXPIRED\]/);
});

test("a permanent GLOBAL entry is creatable explicitly on both surfaces (the ticket's acceptance)", () => {
  const policyHome = home();
  run(policyHome, "policy", "add", "--effect", "allow", "--pattern", "git add *", "--scope", "global", "--expires", "never");
  const [policyEntry] = commandEntries(policyHome);
  assert.equal(policyEntry.scope, "global");
  assert.equal("expiresAt" in policyEntry, false);

  const rulingHome = home();
  // the alias's kept refusal demands an explicit --expires for global — never satisfies it
  const out = run(rulingHome, "ruling", "add", "--effect", "allow", "--pattern", "git add *", "--scope", "global", "--expires", "never").toString();
  assert.match(out, /expires never\)/);
  const [rulingEntry] = commandEntries(rulingHome);
  assert.equal(rulingEntry.scope, "global");
  assert.equal("expiresAt" in rulingEntry, false);
  // and the no-flag refusal still fires, its text now naming the never spelling
  const refused = fails(rulingHome, "ruling", "add", "--effect", "allow", "--pattern", "x*", "--scope", "global");
  assert.equal(refused.status, 1);
  assert.match(refused.message, /requires an explicit --expires \(ISO date, 7d\/12h\/30m, or never/);
});

test("the never spelling folds case; an explicit never is never defaulted", () => {
  const dir = home();
  run(dir, "policy", "add", "--effect", "allow", "--pattern", "make build*", "--scope", "session:sess-N", "--expires", "NEVER");
  const [entry] = commandEntries(dir);
  assert.equal("expiresAt" in entry, false);               // explicit never beats the session 7d default
  run(dir, "policy", "add", "--effect", "allow", "--pattern", "make test*", "--scope", "session:sess-N");
  const [, defaulted] = commandEntries(dir);
  assert.match(defaulted.expiresAt, /^\d{4}-\d{2}-\d{2}T/);  // absent flag keeps the 7d default — unchanged
});

test("a bad --expires value refuses with ONE line naming the accepted forms, before any store write", () => {
  const dir = home();
  const bad = fails(dir, "policy", "add", "--effect", "allow", "--pattern", "git add *", "--expires", "soon");
  assert.equal(bad.status, 1);
  assert.match(bad.message, /bad --expires soon \(accepted: <ISO date> \| 7d \| 12h \| 30m \| never\)/);
  assert.doesNotMatch(bad.message, USAGE_HEADER);           // the issue's dumped help is gone
  assert.doesNotMatch(bad.message, /\n\s+at /);             // a message, not a stack
  assert.equal(existsSync(policyFile(env(dir))), false);    // refused before the store lock
  const alias = fails(dir, "ruling", "add", "--effect", "allow", "--pattern", "x*", "--scope", "project:/p", "--expires", "7x");
  assert.equal(alias.status, 1);
  assert.match(alias.message, /ruling add: bad --expires 7x \(accepted: <ISO date> \| 7d \| 12h \| 30m \| never\)/);
  assert.doesNotMatch(alias.message, USAGE_HEADER);
});

test("the past-expiry refusal stays, now one clean line (no help dump)", () => {
  const dir = home();
  const past = fails(dir, "policy", "add", "--effect", "allow", "--pattern", "git add *", "--expires", "2020-01-01");
  assert.equal(past.status, 1);
  assert.match(past.message, /expiry must be in the future/);
  assert.doesNotMatch(past.message, USAGE_HEADER);
});

test("valid spellings are byte-identical at the library layer; never normalizes to no expiry", () => {
  const dir = home();
  const iso = addCommandEntry({ effect: "allow", pattern: "git push*", scope: "project:/proj", expiresAt: "2099-01-01" }, env(dir));
  assert.match(iso.expiresAt, /^2099-01-01T/);
  const span = addCommandEntry({ effect: "allow", pattern: "cargo build*", scope: "project:/proj", expiresAt: "12h" }, env(dir));
  assert.equal(new Date(span.expiresAt).getTime() - Date.now() > 11 * 36e5, true);
  const never = addCommandEntry({ effect: "allow", pattern: "make ci*", scope: "project:/proj", expiresAt: "never" }, env(dir));
  assert.equal("expiresAt" in never, false);
  const aliasNever = addRuling({ effect: "allow", pattern: "make cd*", scope: "global", expiresAt: "Never" }, env(dir));
  assert.equal("expiresAt" in aliasNever, false);
  assert.throws(() => addCommandEntry({ effect: "allow", pattern: "x*", scope: "project:/proj", expiresAt: "0d" }, env(dir)), /expiry must be in the future/);
  assert.throws(() => addCommandEntry({ effect: "allow", pattern: "x*", scope: "project:/proj", expiresAt: "whenever" }, env(dir)), /bad --expires whenever \(accepted/);
});

test("a never entry consults as permanent: resolveRuling lifts a matching call citing its id", () => {
  const dir = home();
  run(dir, "policy", "add", "--effect", "allow", "--pattern", "git add *", "--scope", "project:/proj", "--expires", "never");
  const [entry] = commandEntries(dir);
  const verdict = resolveRuling("ask", { tool: "Bash", input: { command: "git add src/a.js" }, cwd: "/proj", env: env(dir) });
  assert.equal(verdict?.id, entry.id);                     // unexpired() needs no change: absent field = permanent
});

test("--expires on tool entries refuses cleanly (dir entries take --expires since ruling 5 — entry 17)", () => {
  const dir = home();
  const tool = fails(dir, "policy", "add", "--tool", "mcp__demo", "--expires", "never");
  assert.equal(tool.status, 1);
  assert.match(tool.message, /--expires is a command-entry flag \(use it with --pattern\), not a tool entry/);
  assert.doesNotMatch(tool.message, USAGE_HEADER);
  const lane = fails(dir, "lane", "add", "--tool", "mcp__demo", "--expires", "7d");
  assert.equal(lane.status, 1);
  assert.match(lane.message, /not a tool entry/);
  // the dir rows moved: ruling 5 (operator 2026-11-09) gave dir entries the same expiry
  // grammar — `policy add --dir <path> --expires never` now SUCCEEDS. The acceptance pin
  // lives in test/policy-flag-matrix.test.js ("the flipped seam").
});

test("the full help keeps its own surfaces — no command and unknown command (never after an error)", () => {
  const dir = home();
  const bare = run(dir).toString();                        // bare invocation: USAGE on stdout, exit 0
  assert.match(bare, USAGE_HEADER);
  const unknown = fails(dir, "definitely-not-a-command");
  assert.equal(unknown.status, 1);
  assert.match(unknown.stdout.toString(), USAGE_HEADER);   // the default case prints it itself
});
