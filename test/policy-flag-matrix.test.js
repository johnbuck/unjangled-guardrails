// GHI-17 (CAP-14, the flag-matrix half + operator ruling 5, 2026-11-09): dir entries carry
// expiry like command entries — widening is add-new-and-let-old-expire, nothing deleted by
// hand — the per-kind flag matrix is a real `policy --help` / `policy add --help` surface
// the main help names, and the last silently dropped flag (--scope on tool/dir adds)
// refuses naming its home. 1.7's dir-entry --expires refusal was this ticket's marked
// seam; its deliberate flip is pinned here, and the docs matrix is pinned with it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { addDirEntry, addCommandEntry, dirEffect, adoptDefaults, policyFile } from "../src/policy.js";

const REPO = new URL("..", import.meta.url).pathname;

function home() {
  return mkdtempSync(join(tmpdir(), "unjangled-guardrails-flag-matrix-"));
}

// The CLI runs non-TTY in tests, so mutations carry the operator escape (plan 1.1) — same
// env shape as test/policy-expires-never.test.js.
const env = (dir) => ({ JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" });

const run = (dir, ...args) => execFileSync(process.execPath, ["src/cli.js", ...args],
  { env: env(dir), cwd: REPO });
const fails = (dir, ...args) => {
  try { run(dir, ...args); return null; }
  catch (e) { return e; }
};
const store = (dir) => JSON.parse(readFileSync(policyFile(env(dir)), "utf8"));
const dirEntries = (dir) => store(dir).entries.filter((e) => e.kind === "dir");
const USAGE_HEADER = /dangerous-action guard for coding agents/;  // the full-help banner — never after an error

test("the repro: a dir entry widens by add-new-and-let-old-expire — no remove-and-re-add (ruling 5)", () => {
  const dir = home();
  const out7 = run(dir, "policy", "add", "--dir", "/scratch", "--effect", "allow", "--expires", "7d").toString();
  assert.match(out7, /expires \d{4}-\d{2}-\d{2}T/);              // the confirm line names what was minted
  run(dir, "policy", "add", "--dir", "/scratch", "--effect", "allow", "--expires", "30d");
  const entries = dirEntries(dir);
  assert.equal(entries.length, 2);                                // both statements stand — nothing was removed
  assert.equal(new Set(entries.map((e) => e.id)).size, 2);        // distinct ids: a statement is (directory, expiry)
  const list = run(dir, "policy", "list").toString();
  assert.match(list, /d-[0-9a-f]{4}  dir   allow  \/scratch  expires=\d{4}-\d{2}-\d{2}T/);
  assert.equal((list.match(/\/scratch  expires=/g) ?? []).length, 2);  // both rows render their expiry
  // the consult stays covered by the live statement throughout — the widening's whole point
  assert.equal(dirEffect("Write", { file_path: "/scratch/x.js" }, { env: env(dir) }).effect, "allow");
  // idempotence keys on the expiry VALUE: an exact-ISO repeat is the same statement; a
  // re-typed span mints a fresh clock (a new statement — the command-entry semantics)
  const isoAdd = run(dir, "policy", "add", "--dir", "/scratch", "--effect", "allow", "--expires", "2099-01-01").toString();
  assert.match(isoAdd, /saved/);
  const again = run(dir, "policy", "add", "--dir", "/scratch", "--effect", "allow", "--expires", "2099-01-01").toString();
  assert.match(again, /already present/);
  assert.equal(dirEntries(dir).length, 3);                       // 7d + 30d + one 2099 statement — no shadow twins
});

test("the flipped seam: --expires never on a dir add mints the explicit permanent entry", () => {
  const dir = home();
  const out = run(dir, "policy", "add", "--dir", "/scratch", "--expires", "never").toString();
  assert.match(out, /expires never\)/);                          // 1.7's refusal is gone — the seam flipped
  const [entry] = dirEntries(dir);
  assert.equal(entry.effect, "allow");
  assert.equal("expiresAt" in entry, false);                     // never = NO field, the command-entry normalization
  assert.match(entry.id, /^d-[0-9a-f]{4}$/);
  run(dir, "policy", "add", "--dir", "/other", "--expires", "NEVER");  // case folds
  assert.equal("expiresAt" in dirEntries(dir)[1], false);
  const list = run(dir, "policy", "list").toString();
  assert.match(list, /^d-[0-9a-f]{4}  dir   allow  \/other$/m);  // a permanent dir line keeps its byte shape (no expires suffix)
});

test("the grammar on dir adds: bad values and past dates refuse with 1.7's one-line contract", () => {
  const dir = home();
  const bad = fails(dir, "policy", "add", "--dir", "/scratch", "--expires", "soon");
  assert.equal(bad.status, 1);
  assert.match(bad.message, /policy: bad --expires soon \(accepted: <ISO date> \| 7d \| 12h \| 30m \| never\)/);
  assert.doesNotMatch(bad.message, USAGE_HEADER);                // no help dump after an error
  assert.doesNotMatch(bad.message, /\n\s+at /);                  // a message, not a stack
  assert.equal(existsSync(policyFile(env(dir))), false);         // refused before the store write
  const past = fails(dir, "policy", "add", "--dir", "/scratch", "--expires", "2020-01-01");
  assert.equal(past.status, 1);
  assert.match(past.message, /expiry must be in the future/);
  assert.doesNotMatch(past.message, USAGE_HEADER);
});

test("library rows: addDirEntry resolves spans, ISO dates, and never; throws on bad values", () => {
  const dir = home();
  const E = env(dir);
  const span = addDirEntry({ path: "/scratch", effect: "ask", expiresAt: "12h" }, E);
  assert.ok(new Date(span.expiresAt).getTime() - Date.now() > 11 * 36e5);
  const iso = addDirEntry({ path: "/other", effect: "deny", expiresAt: "2099-01-01" }, E);
  assert.match(iso.expiresAt, /^2099-01-01T/);
  const never = addDirEntry({ path: "/perm", effect: "allow", expiresAt: "Never" }, E);
  assert.equal("expiresAt" in never, false);
  assert.throws(() => addDirEntry({ path: "/x", effect: "allow", expiresAt: "whenever" }, E), /bad --expires whenever \(accepted/);
  assert.throws(() => addDirEntry({ path: "/x", effect: "allow", expiresAt: "0d" }, E), /expiry must be in the future/);
});

test("consult-time expiry: a lapsed dir statement never covers — the live one does (seeded rows)", () => {
  const dir = home();
  const E = env(dir);
  // addDirEntry refuses past dates, so the consult-time half is tested by seeding the store
  // directly (the ruling-2 idiom): a row that has expired never covers, however it got there.
  writeFileSync(policyFile(E), JSON.stringify({ version: 1, entries: [
    { id: "d-old", kind: "dir", path: "/scratch", effect: "allow", at: "2020-01-01T00:00:00Z", expiresAt: "2020-01-02T00:00:00Z" },
    { id: "d-new", kind: "dir", path: "/scratch", effect: "allow", at: "2026-01-01T00:00:00Z", expiresAt: "2099-01-01T00:00:00Z" },
    { id: "d-dead", kind: "dir", path: "/frozen", effect: "deny", at: "2020-01-01T00:00:00Z", expiresAt: "2020-01-02T00:00:00Z" },
    { id: "d-live", kind: "dir", path: "/frozen", effect: "allow", at: "2026-01-01T00:00:00Z" },
  ] }, null, 2) + "\n");
  assert.equal(dirEffect("Write", { file_path: "/scratch/x.js" }, { env: E }).id, "d-new");   // lapsed never covers
  assert.equal(dirEffect("Write", { file_path: "/frozen/x.js" }, { env: E }).effect, "allow"); // a lapsed deny blocks nothing
  assert.equal(dirEffect("Write", { file_path: "/nowhere/x.js" }, { env: E }), null);          // uncovered: plain verdict
});

test("policy list renders a lapsed dir entry [EXPIRED]; live ones carry their expiry", () => {
  const dir = home();
  run(dir, "policy", "add", "--dir", "/scratch", "--expires", "2099-01-01");
  const s = store(dir);                                          // seed a lapsed sibling (the ruling-2 idiom)
  s.entries.push({ id: "d-old", kind: "dir", path: "/scratch", effect: "deny", at: "2020-01-01T00:00:00Z", expiresAt: "2020-01-02T00:00:00Z" });
  writeFileSync(policyFile(env(dir)), JSON.stringify(s, null, 2) + "\n");
  const list = run(dir, "policy", "list").toString();
  assert.match(list, /expires=2020-01-02T00:00:00Z  \[EXPIRED\]/);
  assert.match(list, /expires=2099-01-01(?!T00:00:00Z  \[EXPIRED\])/);  // the live row carries no marker
});

test("--scope on tool, lane, and dir adds refuses naming the command-entry surface — no silent drops", () => {
  const dir = home();
  const tool = fails(dir, "policy", "add", "--tool", "mcp__demo", "--scope", "global");
  assert.equal(tool.status, 1);
  assert.match(tool.message, /--scope is a command-entry flag \(use it with --pattern\), not a tool entry/);
  assert.doesNotMatch(tool.message, USAGE_HEADER);
  const lane = fails(dir, "lane", "add", "--tool", "mcp__demo", "--scope", "project:/p");
  assert.equal(lane.status, 1);
  assert.match(lane.message, /not a tool entry/);
  const dirEntry = fails(dir, "policy", "add", "--dir", "/scratch", "--scope", "global");
  assert.equal(dirEntry.status, 1);
  assert.match(dirEntry.message, /--scope is a command-entry flag \(use it with --pattern\), not a directory entry/);
  assert.doesNotMatch(dirEntry.message, USAGE_HEADER);
  // 1.7's kept refusals hold on the kinds without an expiry dimension
  const toolExp = fails(dir, "policy", "add", "--tool", "mcp__demo", "--expires", "7d");
  assert.match(toolExp.message, /--expires is a command-entry flag \(use it with --pattern\), not a tool entry/);
  const laneExp = fails(dir, "lane", "add", "--tool", "mcp__demo", "--expires", "never");
  assert.match(laneExp.message, /not a tool entry/);
});

test("policy --help and policy add --help are exit-0 surfaces carrying the flag matrix", () => {
  const dir = home();
  for (const argv of [["policy", "--help"], ["policy", "add", "--help"], ["ruling", "--help"], ["lane", "add", "--help"]]) {
    const out = run(dir, ...argv).toString();                    // execFileSync throws on exit != 0 — exit 0 pinned
    assert.match(out, /flag matrix/);
    assert.match(out, /--dir <absolute path> \[--effect allow\|deny\|ask\] \[--expires <ISO date \| 7d \| 12h \| 30m \| never>\]/);
    assert.match(out, /policy list/);
  }
  // bare policy keeps its needs-a-subcommand error: exit 1, same text after the first line
  const bare = fails(dir, "policy");
  assert.equal(bare.status, 1);
  assert.match(bare.message, /policy needs a subcommand: add \| list \| remove \| set \| adopt-defaults \| where/);
  assert.match(bare.message, /flag matrix/);
});

test("the main help names policy add --help as the matrix surface", () => {
  const dir = home();
  const usage = run(dir).toString();                             // bare invocation: USAGE on stdout, exit 0
  assert.match(usage, USAGE_HEADER);
  assert.match(usage, /policy add --help/);
  assert.match(usage, /optional --expires in the/);              // the dir grammar reached the main help too
});

test("docs/policy.md carries the per-kind flag matrix and the ruling-5 dir sentences", () => {
  const doc = readFileSync(join(REPO, "docs", "policy.md"), "utf8");
  assert.match(doc, /## The flag matrix \(per entry kind\)/);
  assert.match(doc, /\| `--expires` \| no — refused \| ISO/);    // the matrix table's expiry row
  assert.match(doc, /let the old lapse/);                       // the widening sentence
  assert.match(doc, /One statement per \*\*\(directory, expiry\)\*\*/);
});

test("adopt-defaults honors a dir entry's expiresAt from a named example file (dupe by path+expiry)", () => {
  const dir = home();
  const E = env(dir);
  const example = join(dir, "example-dirs.json");
  writeFileSync(example, JSON.stringify({ entries: [
    { kind: "dir", path: "/scratch", effect: "allow", expiresAt: "2099-01-01", reason: "bounded" },
    { kind: "dir", path: "/scratch", effect: "allow", reason: "permanent sibling" },
  ] }, null, 2) + "\n");
  adoptDefaults(E, { file: example });
  const entries = dirEntries(dir).filter((e) => e.path === "/scratch");
  assert.equal(entries.length, 2);                               // path+expiry are different statements
  assert.ok(entries.some((e) => e.expiresAt === "2099-01-01"));
  assert.ok(entries.some((e) => !("expiresAt" in e)));
  adoptDefaults(E, { file: example });
  assert.equal(dirEntries(dir).length, 2);                       // re-adopt skips both
});

test("command entries keep 1.7's grammar through the shared parser (regression guard)", () => {
  const dir = home();
  const E = env(dir);
  const never = addCommandEntry({ effect: "allow", pattern: "x*", scope: "session:s1", expiresAt: "never" }, E);
  assert.equal("expiresAt" in never, false);                     // explicit never beats the session 7d default
  addCommandEntry({ effect: "allow", pattern: "y*", scope: "session:s1" }, E);
  const defaulted = store(dir).entries.find((e) => e.pattern === "y*");
  assert.ok(new Date(defaulted.expiresAt).getTime() - Date.now() > 6 * 864e5);  // absent → 7d default, unchanged
  assert.throws(() => addCommandEntry({ effect: "allow", pattern: "z*", scope: "session:s1", expiresAt: "nope" }, E), /bad --expires nope \(accepted/);
});
