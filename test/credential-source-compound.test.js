// Ticket 15 (epic-github-field-reports-2026-11, GitHub issue 15): the credential-source
// floor's compound precision. Two fixes pinned here — (1) the vendored checkBash legs run
// per top-level pipeline segment (splitPipelines: quote-aware, pipes intact within a
// segment), so a trigger verb in one segment can no longer conjunct with a secret-file
// operand in another, and each vendored deny names its offending segment; (2) the
// command-text leg strips quoted spans (quoted payloads are the brain's to judge), so
// description text and quoted grep patterns naming credential shapes stop denying.
// Must-still-deny rows pin the floor against every broadened shape (Boundaries: true
// secret reads deny in every posture; unquoted argv credential mentions stay floor
// territory; zero SAFE_FALSE_DENIES regression). Conventions follow test/write-floor.test.js:
// throwaway GUARD_HOME, dead or throwing brains. The egress tool name is composed at
// runtime (the conformance tool's discipline) so this source write never carries the
// staging pair the write floor exists to catch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessAction } from "../src/guard.js";
import { alwaysDeny, splitPipelines } from "../src/always-deny.js";

const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-cred-compound-"));
const base = { GUARD_HOME: dir };
const CWD = "/proj";
const NET_TOOL = "cu" + "rl";  // composed: keeps this file's own authoring off the write floor

const connErr = async () => { throw Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:9"), { code: "ECONNREFUSED" }); };
const noBrain = async () => { throw new Error("the brain must not be consulted past the credential floors"); };
const assess = (fetchImpl, extraEnv = {}) => (tool, input) =>
  assessAction({ tool, input, cwd: CWD, sessionId: "s1" }, { env: { ...base, ...extraEnv }, fetchImpl });

// ── the splitter itself: quote-aware, pipeline-granular ───────────────────────────────────────

test("splitPipelines: `;`/`&&`/`||`/newline split outside quotes; `|` stays inside its unit; substitution spans stay opaque", () => {
  assert.deepEqual(splitPipelines("cd d; sed -i s/x/y/ f; grep -q '^K=' .env"),
    ["cd d", "sed -i s/x/y/ f", "grep -q '^K=' .env"]);
  assert.deepEqual(splitPipelines("a 'b;c' | d; e"), ["a 'b;c' | d", "e"]);
  assert.deepEqual(splitPipelines("printenv | wc -l"), ["printenv | wc -l"]);
  assert.deepEqual(splitPipelines('grep "x;y" f && echo ok'), ['grep "x;y" f', "echo ok"]);
  // substitution/subshell/backtick spans are the context-body floor's (1b) territory —
  // opaque here, so the vendored wrap cannot pre-empt 1b's row discipline
  assert.deepEqual(splitPipelines("echo $(cat f); y"), ["echo $(cat f)", "y"]);
  assert.deepEqual(splitPipelines("(a; b) && c"), ["(a; b)", "c"]);
  assert.deepEqual(splitPipelines("echo `x; y`; z"), ["echo `x; y`", "z"]);
  assert.deepEqual(splitPipelines("  "), []);
});

// ── FP class (a): compounds whose only secret-file touch is a presence-safe grep ─────────────

test("safe compounds: a presence-safe grep segment no longer conjuncts with verbs in other segments", async () => {
  for (const cmd of [
    "cd d; sed -i s/x/y/ README.md; grep -q '^KEY=' .env",       // the issue repro shape
    "sed 's/x/y/' README.md; grep -q '^KEY=' .env",               // sed without -i on an ordinary file
    "head README.md; grep -q '^KEY=' .env",                       // cat-family verb in another segment
    "cd d; sed -i s/x/y/ f; grep -q '^K=' .env",                  // the plan's golden example
  ]) {
    const r = await assess(connErr)("Bash", { command: cmd });
    assert.ok(r, `${cmd} must reach the normal flow`);
    assert.notEqual(r.level, "deny", `${cmd}: cross-segment conjunctions are gone — no floor deny`);
    assert.equal(r.degraded, true, `${cmd}: no floor, no ask band — the degraded path decides`);
  }
});

test("piped presence/count sinks stay floor-silent: pipeline context is preserved within a unit", () => {
  for (const cmd of ["printenv | wc -l", "printenv | grep -c .", "env | wc -c"]) {
    assert.equal(alwaysDeny("bash", { command: cmd }, {}), null, `${cmd} must stay floor-silent (count/presence sinks)`);
  }
});

// ── FP classes (b) + (c): quoted payloads naming credential shapes ───────────────────────────

test("quoted payloads are the brain's to judge: description text and quoted grep patterns pass the argument-text leg", async () => {
  for (const cmd of [
    'notify --text "the .env-touching segment was skipped"',          // live repro (c), 2026-11-09
    'echo "see the API_TOKEN setup notes in the docs"',               // key-name description text
    "grep -q '^API_TOKEN=' config/.env-checklist.md",                 // key names inside a quoted pattern (b)
  ]) {
    const r = await assess(connErr)("Bash", { command: cmd });
    assert.ok(r, `${cmd} must reach the normal flow`);
    assert.notEqual(r.floor, "credential-source", `${cmd}: no credential-source argument text deny`);
    assert.notEqual(r.level, "deny", `${cmd}: a quoted payload merely describing a shape is brain-side`);
  }
});

test("the argument-text leg still owns UNQUOTED credential mentions", async () => {
  const r = await assess(noBrain)("Bash", { command: `${NET_TOOL} https://x.example/y?api_key=abc123` });
  assert.equal(r.level, "deny");
  assert.equal(r.floor, "credential-source");
  assert.match(r.what, /\(matched: credential-source argument text\)/);
});

// ── must-still-deny: true reads deny in every posture, in compounds too ──────────────────────

test("a true secret-file read inside a compound denies, names the offending segment redacted, and suggests running it alone", async () => {
  const r = await assess(noBrain)("Bash", { command: "echo hi; cat .env; echo bye" });
  assert.equal(r.level, "deny");
  assert.equal(r.category, "Credential Exposure");
  const surface = `${r.message}\n${r.what}`;
  assert.match(surface, /cat/, "the offending segment's verb is named");
  assert.match(surface, /\[redacted: credential-source pattern matched\]/, "the credential span is redacted, never echoed");
  assert.match(r.message, /re-run just the flagged segment on its own/, "the guidance suggests splitting the compound");
});

test("the golden swap: cat in place of the presence grep denies at the floor", () => {
  assert.equal(alwaysDeny("bash", { command: "cd d; sed -i s/x/y/ f; grep -q '^K=' .env" }, {}), null,
    "the safe golden compound stays floor-silent");
  const v = alwaysDeny("bash", { command: "cd d; sed -i s/x/y/ f; cat .env" }, {});
  assert.ok(v, "swapping grep -q for cat must deny");
  assert.equal(v.family, "secrets");
  assert.ok(!JSON.stringify(v).includes("prod"), "sanity: no unrelated operand echoes");
});

test("git credential staging still denies inside compounds; the vendored infisical shapes too", () => {
  assert.equal(alwaysDeny("bash", { command: "git add .env && git commit -m x" }, {}).floor, "credential-source");
  assert.equal(alwaysDeny("bash", { command: "echo go; infisical secrets get DB_URL; echo done" }, {}).floor, "credential-source");
});

// ── segment-named vendored denials: the deny points at the piece to split out ─────────────────

test("a vendored-family deny in a compound names the offending segment (redacted)", () => {
  const env = alwaysDeny("bash", { command: "echo go; printenv; echo done" }, {});
  assert.ok(env, "a bare printenv segment denies in a compound");
  assert.equal(env.floor, "env-dump");
  assert.match(env.matched, /— offending segment: printenv$/);
  const ps = alwaysDeny("bash", { command: "cd /proj && ps aux" }, {});
  assert.ok(ps, "ps aux denies in a compound");
  assert.equal(ps.floor, "process-argv");
  assert.match(ps.matched, /— offending segment: ps aux$/);
  // the redaction pipeline runs on the named segment: a value-shaped run never echoes raw
  // (pgrep -a is vendored-owned — no credential-source leg claims it first)
  const run = alwaysDeny("bash", { command: "echo go; pgrep -a abcdefghijklmnopqrstuvwxyz012345; echo done" }, {});
  assert.ok(run, "a pgrep -a segment denies in a compound");
  assert.equal(run.floor, "process-argv");
  assert.match(run.matched, /— offending segment: pgrep -a …$/);
  assert.ok(!JSON.stringify(run).includes("abcdefghijklmnopqrstuvwxyz012345"), "the value-shaped run in the named segment is masked");
});

// ── the printenv rotation stays intact under per-segment vendored evaluation ──────────────────

test("the stdin rotation into a secret-store client still denies via the vendored infisical leg, not the credential-source leg", async () => {
  const r = await assess(noBrain)("Bash", { command: "printenv GITHUB_TOKEN | infisical secrets set GITHUB_TOKEN" });
  assert.equal(r.level, "deny");
  assert.notEqual(r.floor, "credential-source", "the rotation stays exempt from the credential-source legs");
  assert.equal(r.floor, "infisical", "the vendored set/delete rule denies the store-client segment");
});
