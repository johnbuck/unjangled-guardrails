// Ticket 9 (epic-github-field-reports-2026-11, GitHub issue 9): the safe local VCS band.
// Three behaviors pinned here — (1) a message-only local commit (`git commit -m …`, the
// house default's own vouched shape: "message-only commits of what add already gated;
// -a/--all and --amend stay brain-side") lands in the safe band: its APPROVAL driver cannot
// hold it, solo or inside a compound, while the brain's risk and leak say stays full force;
// (2) a held commit-shaped command names the element that raised the score — the driver
// (risk/approval/leak) and, for out-of-band shapes, the disqualifying flag that kept it out
// of the band (the repro's complaint: the verdict never said what raised it); (3) zero drift
// on push-containing commands and on the CAP-8 walls: operator asks never release, denies
// never release, degraded rows and fan-out failures keep their shapes, cap exclusions stay
// visible, and single-segment NON-commit calls are byte-identical. The band composes through
// the CAP-8 justification predicate — a commit segment is still ASKED and renders its real
// risk (it is a tier-1 workspace change, not a floor utility). Conventions follow
// test/compound-segment-floor.test.js: throwaway GUARD_HOME, scripted brains, no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessAction, askBlockedDeny, messageOnlyLocalCommit, commitBandDisqualifier } from "../src/guard.js";

const env0 = (extra = {}) => ({ GUARD_HOME: mkdtempSync(join(tmpdir(), "commit-band-")), SYSTEMONE_URL: "http://brain.test", ...extra });
const CWD = "/proj";

/** Scripted brain: a call whose command matches a `segs` matcher answers it; the whole
 *  command answers `whole`. Default 0.4/0.10. leak sets leaks_secrets p. */
function brain(counter, { whole, segs = [], failAfter = Infinity } = {}) {
  return async (_url, { body }) => {
    counter.calls += 1;
    if (counter.calls > failAfter) throw new Error("fan-out down");
    const { state } = JSON.parse(body);
    const cmd = String(state.input?.command ?? "");
    const m = (whole && cmd === whole.cmd) ? whole : segs.find((s) => s.re.test(cmd)) ?? { risk: 0.4, approval: 0.1 };
    return {
      ok: true,
      json: async () => ({
        answers: {
          risk: { type: "score", score: m.risk, probabilities: {}, confidence: 0.8 },
          approval: { type: "noul", noul: m.approval },
          user_requested: { type: "noul", noul: 0.05 },
          from_untrusted: { type: "noul", noul: 0.05 },
          leaks_secrets: { type: "noul", noul: m.leak ?? 0.05 },
          dumps_env_argv: { type: "noul", noul: 0.05 },
          dumps_process_argv: { type: "noul", noul: 0.05 },
          reads_credential_file: { type: "noul", noul: 0.05 },
        },
      }),
    };
  };
}

// The GHI-9 repro numbers: add passes at 0.9/0.31, the message-only commit asks on approval
// noise alone (risk 1.2 tier-1, approval p 0.78 over the 0.75 bar).
const PATHS = Array.from({ length: 15 }, (_, i) => `src/f${i}.js`).join(" ");
const REPRO_COMMIT = `git commit -m 'BMad: refresh project runtime scripts after the spec session' -- ${PATHS}`;

// ── the classifier itself ─────────────────────────────────────────────────────────────────────

test("messageOnlyLocalCommit: the band-in shapes (the house default's own vouched family)", () => {
  for (const seg of ["git commit -m x", "git commit -m 'ship it'", 'git commit -m "a b"',
    "git commit -m 'title' -m 'body'", "git commit --message=inline", "git commit -q -m 'quiet'",
    "git commit -m 'repro' -- src/a.js src/b.js", "git commit -m x -- src/c.js", "FOO=1 git commit -m x",
    "/usr/bin/git commit -m 'path spelling'", `git commit -m 'BMad: refresh' -- ${PATHS}`])
    assert.equal(messageOnlyLocalCommit(seg), true, `${seg} rides the band`);
});

test("messageOnlyLocalCommit: the band-out shapes stay brain-side (flag analysis, no remote/destructive flags in band)", () => {
  for (const seg of ["git commit --amend -m 'reword'", "git commit -a -m 'all'", "git commit --all -m x",
    "git commit -C HEAD~1", "git commit -F msg.txt", "git commit --author='x <x@y>' -m x",
    "git commit --no-verify -m x", "git commit --allow-empty -m x", "git commit -v -m x",
    "git commit", "git commit -- src/a.js", "git -C /p commit -m x", "sudo git commit -m x",
    "git push origin main", "git add src/a.js", "git commit -m 'fix; polish'", "git commit -m 'a | b'",
    "git commit -m 'costs $5'", "git commit -m x && git push", ""])
    assert.equal(messageOnlyLocalCommit(seg), false, `${seg} stays brain-side`);
});

test("commitBandDisqualifier names the element that keeps a commit-shaped segment out", () => {
  assert.equal(commitBandDisqualifier("git commit --amend -m x"), "--amend");
  assert.equal(commitBandDisqualifier("git commit -a -m x"), "-a");
  assert.equal(commitBandDisqualifier("git commit -C HEAD~1"), "-C");
  assert.equal(commitBandDisqualifier("git commit"), "no -m/--message flag");
  assert.equal(commitBandDisqualifier("git commit -m 'fix; polish'"), "shell metacharacters in the command");
  assert.equal(commitBandDisqualifier("git commit -m x"), null, "in band: no disqualifier");
  assert.equal(commitBandDisqualifier("git push origin main"), null, "not commit-shaped: no disqualifier");
});

// ── the safe band: the repro lands allow, solo, with ONE brain call ──────────────────────────

test("the GHI-9 repro: a message-only local commit on staged paths lands in the safe band, one brain call", async () => {
  const counter = { calls: 0 };
  const r = await assessAction({ tool: "Bash", input: { command: REPRO_COMMIT }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { whole: { risk: 1.2, approval: 0.78, cmd: REPRO_COMMIT } }) });
  assert.equal(r.level, "allow", `the repro must pass: ${JSON.stringify(r)}`);
  assert.match(r.why, /a message-only local commit does not justify a hold \(risk 1\.2\/3, approval p=0\.78 not held against the safe local VCS band\) — the commit band released the ask/);
  assert.match(r.stats, /risk 1\.2\/3, approval p=0\.78/, "the whole-command measurement stays in stats");
  assert.ok(!r.segments, "an allow row never carries segments (decision-export biconditional)");
  assert.ok(!r.rulingHint, "a released allow carries no unblock hint");
  assert.equal(counter.calls, 1, `the whole-command answers ARE the segment answers — no second call, got ${counter.calls}`);
});

test("the repro's git add passes unchanged (the pair CAP-9 names)", async () => {
  const add = `git add -- ${PATHS}`;
  const r = await assessAction({ tool: "Bash", input: { command: add }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 0.9, approval: 0.31, cmd: add } }) });
  assert.equal(r.level, "allow");
  assert.ok(!r.why, "a plain brain allow carries no why — byte-identical to pre-band");
});

test("a banded commit the brain scores at risk ≥ askScore still holds — the band neutralizes approval only", async () => {
  const cmd = "git commit -m 'restructure everything'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.4, cmd } }) });
  assert.equal(r.level, "ask", "the brain's risk say is untouched by the band");
  assert.match(r.message, /Commit verdict: "git commit -m 'restructure everything'" 2\.2\/3 \(risk ≥ 2\.0\) drove the hold\./);
  assert.ok(Array.isArray(r.segments) && r.segments.length === 1, "the ask carries its structured row");
  assert.equal(r.segments[0].risk, 2.2, "the row carries the real measured risk, never a 0.0 lie");
});

// ── held commit-shaped commands name the element that raised the score ───────────────────────

test("a held out-of-band solo commit names the driver AND the disqualifying element", async () => {
  for (const [cmd, flag] of [
    ["git commit --amend -m 'reword'", "--amend"],
    ["git commit -a -m 'all'", "-a"],
  ]) {
    const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
      { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.2, approval: 0.8, cmd } }) });
    assert.equal(r.level, "ask", cmd);
    assert.match(r.message, new RegExp(`Commit verdict: ".*" 1\\.2/3 \\(approval p=0\\.80\\) drove the hold; ${flag.replace(/[-[\]/{}()*+?.,\\^$|]/g, "\\$&")} keeps it out of the message-only local commit band\\.`), cmd);
  }
});

test("a bare commit (no message flag) names the missing element", async () => {
  const r = await assessAction({ tool: "Bash", input: { command: "git commit" }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.2, approval: 0.8, cmd: "git commit" } }) });
  assert.equal(r.level, "ask");
  assert.match(r.message, /Commit verdict: "git commit" 1\.2\/3 \(approval p=0\.80\) drove the hold; no -m\/--message flag keeps it out of the message-only local commit band\./);
});

test("askBlockedDeny carries the Commit verdict sentence on no-prompt hosts", async () => {
  const cmd = "git commit --amend -m 'reword'";
  const ask = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.2, approval: 0.8, cmd } }) });
  assert.equal(ask.level, "ask");
  const blocked = askBlockedDeny(ask);
  assert.equal(blocked.level, "deny");
  assert.match(blocked.message, /no approval prompt/);
  assert.match(blocked.message, /Commit verdict: .* drove the hold; --amend keeps it out of the message-only local commit band\./);
});

// ── compounds: the band rides the CAP-8 predicate, floor and band compose ────────────────────

test("the 1.8 approval-holder compound now releases, the band clause naming the neutralized approval", async () => {
  const cmd = "cut -c1-2 out.txt; git commit -m 'refresh'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: [{ re: /git commit/, risk: 1.2, approval: 0.8 }] }) });
  assert.equal(r.level, "allow", "the commit's p=0.80 no longer holds the compound");
  assert.match(r.why, /no compound segment alone justifies a hold \(highest segment risk 1\.2\/3, approval p=0\.80\) — the read-only segment floor released the compound ask; the message-only local commit sits in the safe local VCS band \(its approval driver p=0\.80 is not held against it\)/,
    "the release sentence keeps 1.8's raw-approval semantics (inclusive, per its pinned repro) and the band clause names the same number as neutralized");
  assert.ok(!r.segments, "no segments on the released allow");
});

test("a banded commit still pays its per-segment brain ask (not a pin) and renders its real risk when held", async () => {
  const counter = { calls: 0 };
  const cmd = "git status; git commit -m 'big restructure'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: [{ re: /git commit/, risk: 2.3, approval: 0.9 }] }) });
  assert.equal(r.level, "ask", "risk 2.3 ≥ 2.0 holds even in band");
  assert.match(r.message, /Segment scores: "git commit -m 'big restructure'" 2\.3\/3 \(risk ≥ 2\.0\) drove the hold/);
  assert.equal(r.segments.find((s) => s.text.includes("git commit")).risk, 2.3, "the row risk is the measured one");
  assert.equal(counter.calls, 3, "whole + status + commit — the commit segment is asked, not pinned");
});

test("a leak answer on a commit segment still holds the compound (the band never touches the leak tier)", async () => {
  const cmd = "git status; git commit -m 'ship it'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: [{ re: /git commit/, risk: 1.2, approval: 0.8, leak: 0.9 }] }) });
  assert.equal(r.level, "ask");
  assert.match(r.message, /"git commit -m 'ship it'" 1\.2\/3 \(leak p=0\.90\) drove the hold/);
});

test("cap exclusions stay visible with a banded commit: asked slots, unscored named, release blocked", async () => {
  const counter = { calls: 0 };
  const cmd = "cut -c1-2 f; sort f; git status; git add a; git commit -m x";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0({ GUARD_ATTRIBUTION_CAP: "2" }), fetchImpl: brain(counter, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: [{ re: /git (status|add)/, risk: 0.9, approval: 0.31 }, { re: /git commit/, risk: 1.2, approval: 0.8 }] }) });
  assert.equal(r.level, "ask", "unscored segments block the release — the commit among them, unscoreable is never silent");
  assert.match(r.message, /1 more segment over the attribution cap \(2\) unattributed/);
  assert.ok(!/drove the hold/.test(r.message), "no scored segment holds — the ask stands on the unscored remainder");
  assert.equal(counter.calls, 3, "whole + two asked segments (cut/sort pinned, the commit NOT pinned — it would take a slot)");
});

// ── no drift on push-containing commands ─────────────────────────────────────────────────────

test("a push-bearing compound still holds: the push drives it, the banded commit renders in the band note", async () => {
  const cmd = "git commit -m 'ship it' && git push origin main";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: [{ re: /git push/, risk: 2.4, approval: 0.9 }, { re: /git commit/, risk: 1.2, approval: 0.8 }] }) });
  assert.equal(r.level, "ask");
  assert.match(r.message, /Segment scores: "git push origin main" 2\.4\/3 \(risk ≥ 2\.0\) drove the hold/);
  assert.ok(!/"git commit -m 'ship it'".*drove the hold/.test(r.message), "the commit is no longer a named holder — that delta is the fix");
  assert.match(r.message, /Safe local VCS band: "git commit -m 'ship it'" in band \(its approval driver is not held against it\)\./);
});

test("a solo push asks unchanged — push is not commit-shaped", async () => {
  const cmd = "git push origin main";
  const counter = { calls: 0 };
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { whole: { risk: 2.4, approval: 0.9, cmd } }) });
  assert.equal(r.level, "ask");
  assert.equal(counter.calls, 1);
  assert.ok(!/Commit verdict:/.test(r.message));
  assert.ok(!/Segment scores:/.test(r.message), "single-segment non-commit: byte-identical, no attribution");
});

// ── the walls: operator asks, denies, degradation, failures, single-segment identity ─────────

test("an operator ask entry holds a banded commit ask — the band never lifts an operator ask", async () => {
  const home = mkdtempSync(join(tmpdir(), "commit-band-lane-"));
  mkdirSync(home, { recursive: true, mode: 0o700 });
  writeFileSync(join(home, "user-policy.json"), JSON.stringify({ version: 1, entries: [{ id: "t-ask", kind: "tool", pattern: "bash", effect: "ask" }] }), { mode: 0o600 });
  const cmd = "git commit -m 'ship it'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: { GUARD_HOME: home, SYSTEMONE_URL: "http://brain.test" }, fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.2, approval: 0.78, cmd } }) });
  assert.equal(r.level, "ask");
  assert.match(r.why, /user lane: always asks by operator rule/);
  assert.ok(!/Commit verdict:/.test(r.message) || !/drove the hold/.test(r.message), "below-band answers under an operator ask render no driver naming");
});

test("a deny verdict on a commit-shaped command never releases and keeps its family", async () => {
  const cmd = "git commit -m 'ship it'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.9, approval: 0.9, cmd } }) });
  assert.equal(r.level, "deny", "the brain's deny line is untouched by the band");
  assert.match(r.category, /Dangerous Action/);
  assert.ok(!/Commit verdict:/.test(r.message), "the solo attribution sentence is ask-band copy; a deny keeps its registry text");
});

test("a degraded verdict never runs the band — the posture decides", async () => {
  const down = async () => { throw Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:9"), { code: "ECONNREFUSED" }); };
  const r = await assessAction({ tool: "Bash", input: { command: REPRO_COMMIT }, cwd: CWD }, { env: env0(), fetchImpl: down });
  assert.equal(r.degraded, true);
  assert.ok(!/Commit verdict:|commit band/.test(r.message));
});

test("a fan-out failure on a commit-bearing compound leaves the verdict and message unchanged", async () => {
  const counter = { calls: 0 };
  const cmd = "git status; git commit -m 'ship it'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: [{ re: /git commit/, risk: 1.2, approval: 0.8 }], failAfter: 1 }) });
  assert.equal(r.level, "ask", "conservative: the whole-command verdict keeps");
  assert.ok(!/Segment scores:|Commit verdict:/.test(r.message));
});

test("single-segment non-commit calls stay byte-identical: no band, no attribution, no release", async () => {
  const counter = { calls: 0 };
  const cmd = "cat out.txt";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { whole: { risk: 2.0, approval: 0.05, cmd } }) });
  assert.equal(r.level, "ask");
  assert.equal(counter.calls, 1);
  assert.ok(!/Segment scores:|Commit verdict:/.test(r.message));
});

test("the message with a metacharacter stays brain-side: banded recognition refuses, the disqualifier names the guard", async () => {
  const cmd = "git commit -m 'fix; polish'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.2, approval: 0.8, cmd } }) });
  assert.equal(r.level, "ask");
  assert.match(r.message, /Commit verdict: .* \(approval p=0\.80\) drove the hold; shell metacharacters in the command keeps it out of the message-only local commit band\./);
});
