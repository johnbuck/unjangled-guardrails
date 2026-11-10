// Ticket 8 (epic-github-field-reports-2026-11, GitHub issue 8): the read-only segment floor.
// Three behaviors pinned here — (1) read-only text utilities (cut/sort/uniq/wc/head/tail) and
// presence-only greps pin at risk 0 inside compounds, making no brain call and consuming no
// attribution-cap slot; (2) a brain-held compound RELEASES to allow when no segment alone
// justifies the hold (no whole-command risk inheritance from a benign segment) — operator ask
// entries never release, cap-excluded segments block the release, fan-out failures keep the
// verdict; (3) a held compound's attribution names the segment that DROVE the hold with its
// driver (risk/approval/leak), never merely the highest raw score (the repro named `cut`
// 1.2/3 as a compound's highest segment). The deny line, single-segment calls, and degraded
// verdicts stay byte-identical. Conventions follow test/attribution.test.js: throwaway
// GUARD_HOME, scripted brains, no live network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessAction, askBlockedDeny, floorUtilitySegment } from "../src/guard.js";

const env0 = (extra = {}) => ({ GUARD_HOME: mkdtempSync(join(tmpdir(), "seg-floor-")), SYSTEMONE_URL: "http://brain.test", ...extra });
const CWD = "/proj";

/** Scripted brain: the whole-command call answers `whole`; a segment call answers the first
 *  `segs` matcher its command matches (default 0.4/0.10). leak sets leaks_secrets p. */
function brain(counter, { whole, segs = [], failAfter = Infinity } = {}) {
  return async (_url, { body }) => {
    counter.calls += 1;
    if (counter.calls > failAfter) throw new Error("fan-out down");
    const { state } = JSON.parse(body);
    const cmd = String(state.input?.command ?? "");
    const m = state.wholeCommand === cmd || (whole && cmd === whole.cmd)
      ? whole
      : segs.find((s) => s.re.test(cmd)) ?? { risk: 0.4, approval: 0.1 };
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

// The GHI-8 repro shape: the chained status pipeline plus add/commit/show. The whole command
// asks on compound-shape noise (risk 1.4, approval p 0.78 — under the 2.0 risk band, over the
// 0.75 approval bar); every segment scores below the band on its own.
const REPRO = "git status --short | cut -c1-2 | sort | uniq -c; git add src/a.js; git commit -m 'refresh'; git show --stat";
const reproSpec = {
  whole: { risk: 1.4, approval: 0.78, cmd: REPRO },
  segs: [
    { re: /git push/, risk: 2.4, approval: 0.9 },
    { re: /git commit/, risk: 1.2, approval: 0.4 },
    { re: /git (status|add|show)/, risk: 0.9, approval: 0.31 },
  ],
};

// ── the classifier itself ─────────────────────────────────────────────────────────────────────

test("floorUtilitySegment: the utility set, presence-only greps, and the conservative shape guard", () => {
  for (const seg of ["cut -c1-2", "sort", "uniq -c", "wc -l f", "head -20 notes.txt", "tail -1",
    "grep -q '^KEY=' .env", "grep -qi x f", "grep --quiet x f", "FOO=1 sort f", "/usr/bin/wc -l f"])
    assert.equal(floorUtilitySegment(seg), true, `${seg} pins at the floor`);
  for (const seg of ["cat f", "python3 -c x", "grep x f", "grep -n x f", "sudo cut f", "awk '{print $1}'",
    "sort > ~/.bashrc", "sort f | sh", "cut -d'|' -f2", "head -2 $(cat f)", "sort f; rm x", "echo hi", ""])
    assert.equal(floorUtilitySegment(seg), false, `${seg} stays brain-side`);
});

// ── the release: no whole-command risk inheritance from a benign segment ──────────────────────

test("the GHI-8 repro releases: the chained status pipeline compound passes, no segments on the allow", async () => {
  const counter = { calls: 0 };
  const r = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: CWD }, { env: env0(), fetchImpl: brain(counter, reproSpec) });
  assert.equal(r.level, "allow", `the repro must pass: ${JSON.stringify(r)}`);
  assert.match(r.why, /no compound segment alone justifies a hold \(highest segment risk 1\.2\/3, approval p=0\.40\)/);
  assert.match(r.stats, /risk 1\.4\/3, approval p=0\.78/, "the whole-command measurement stays in stats");
  assert.ok(!r.segments, "an allow row never carries segments (decision-export biconditional)");
  assert.ok(!r.rulingHint, "a released allow carries no unblock hint");
  assert.match(r.message, /Unjangled Guardrails: ok/);
});

test("pinned utilities make no brain call and consume no cap slot (repro: 5 calls, not 8)", async () => {
  const counter = { calls: 0 };
  await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: CWD }, { env: env0(), fetchImpl: brain(counter, reproSpec) });
  assert.equal(counter.calls, 5, `one whole-command call plus the four git segments (cut/sort/uniq pinned) — got ${counter.calls}`);
});

test("an all-utility compound releases with zero segment calls", async () => {
  const counter = { calls: 0 };
  const cmd = "cut -c1-2 out.txt; sort out.txt; uniq -c out.txt";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { whole: { risk: 1.6, approval: 0.76, cmd } }) });
  assert.equal(r.level, "allow");
  assert.equal(counter.calls, 1, "every segment pinned — only the whole-command call ran");
  assert.match(r.why, /highest segment risk 0\.0\/3, approval p=0\.00/);
});

test("the read-only python3 -c compound releases too (below-band per-segment, not pinned)", async () => {
  const counter = { calls: 0 };
  const cmd = "cat out.json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"v\"])'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: [{ re: /python3/, risk: 0.8, approval: 0.3 }] }) });
  assert.equal(r.level, "allow", "the JSON-parsing python segment scores below the band on its own");
  assert.equal(counter.calls, 3, "whole + cat + python3 — the python segment is asked, not pinned");
});

// ── must-still-hold: a genuinely risky segment still drives the verdict and is named ──────────

test("a push-bearing segment still drives the verdict, named with its risk driver; utilities render at the floor", async () => {
  const counter = { calls: 0 };
  const cmd = "git status --short | cut -c1-2 | sort | uniq -c; git add src/a.js; git push origin main";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { whole: { risk: 2.1, approval: 0.85, cmd }, segs: reproSpec.segs }) });
  assert.equal(r.level, "ask", "the push segment alone justifies the hold");
  assert.match(r.message, /Segment scores: "git push origin main" 2\.4\/3 \(risk ≥ 2\.0\) drove the hold/);
  assert.match(r.message, /Read-only utilities at the floor: "cut -c1-2", "sort", "uniq -c"\./);
  assert.ok(Array.isArray(r.segments), "the ask keeps its structured segment rows");
  assert.equal(r.segments.find((s) => s.text.includes("git push")).risk, 2.4);
  assert.equal(r.segments.find((s) => s.text === "cut -c1-2").risk, 0, "the pinned utility row reads 0");
});

test("an approval-driven holder is named with its approval driver", async () => {
  // CAP-9 (entry 9, the paired ticket): the plain `git commit -m 'refresh'` no longer holds
  // an approval-driven compound — it rides the safe local VCS band and this compound now
  // RELEASES (pinned in test/commit-band.test.js). The approval-driver pin keeps its intent
  // on an out-of-band commit shape: --amend stays brain-side, so its approval driver (0.80)
  // still holds the compound and is named.
  const cmd = "cut -c1-2 out.txt; git commit --amend -m 'refresh'";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: [{ re: /git commit/, risk: 1.2, approval: 0.8 }] }) });
  assert.equal(r.level, "ask");
  assert.match(r.message, /"git commit --amend -m 'refresh'" 1\.2\/3 \(approval p=0\.80\) drove the hold/);
});

test("a leak-justified segment holds the compound and is named with its leak driver", async () => {
  const cmd = "echo start; bat out.txt";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: [{ re: /bat /, risk: 1.1, approval: 0.3, leak: 0.9 }] }) });
  assert.equal(r.level, "ask", "a confident leak answer on one segment justifies the hold");
  assert.match(r.message, /"bat out\.txt" 1\.1\/3 \(leak p=0\.90\) drove the hold/);
});

// ── cap transparency: pinned segments are attributed free; unscored segments block the release ─

test("cap exclusions stay visible and block the release; pinned utilities never consume cap slots", async () => {
  const counter = { calls: 0 };
  const cmd = "cut -c1-2 f; sort f; git status; git add a; git commit -m x";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0({ GUARD_ATTRIBUTION_CAP: "2" }), fetchImpl: brain(counter, { whole: { risk: 1.4, approval: 0.78, cmd }, segs: reproSpec.segs }) });
  assert.equal(r.level, "ask", "unscored unpinned segments block the release — unscored is not floor");
  assert.match(r.message, /1 more segment over the attribution cap \(2\) unattributed/);
  assert.match(r.message, /Read-only utilities at the floor: "cut -c1-2 f", "sort f"\./);
  assert.equal(counter.calls, 3, "whole + two asked segments; cut and sort are free");
});

// ── the walls: operator asks, single segments, denies, failures, degradation ──────────────────

test("an operator ask entry holds the compound — the release never lifts an operator ask", async () => {
  const home = mkdtempSync(join(tmpdir(), "seg-floor-lane-"));
  mkdirSync(home, { recursive: true, mode: 0o700 });
  writeFileSync(join(home, "user-policy.json"), JSON.stringify({ version: 1, entries: [{ id: "t-ask", kind: "tool", pattern: "bash", effect: "ask" }] }), { mode: 0o600 });
  const r = await assessAction({ tool: "Bash", input: { command: "cut -c1-2 out.txt; sort out.txt" }, cwd: CWD },
    { env: { GUARD_HOME: home, SYSTEMONE_URL: "http://brain.test" }, fetchImpl: brain({ calls: 0 }, { whole: { risk: 0.4, approval: 0.1, cmd: "cut -c1-2 out.txt; sort out.txt" } }) });
  assert.equal(r.level, "ask", "the whole-command verdict was allow and the operator entry asks — no release question arises");
  assert.match(r.why, /user lane: always asks by operator rule/);
});

test("single-segment calls are byte-identical: no fan-out, no pins, no release", async () => {
  const counter = { calls: 0 };
  const cmd = "cut -c1-2 out.txt";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { whole: { risk: 2.0, approval: 0.05, cmd } }) });
  assert.equal(r.level, "ask", "the whole-command ask stands — a lone segment is never re-judged");
  assert.equal(counter.calls, 1);
  assert.ok(!/Segment scores:/.test(r.message));
});

test("deny verdicts keep worst-risk naming and never release", async () => {
  const cmd = "rm -rf /tmp/x; echo done";
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.9, approval: 0.9, cmd }, segs: [{ re: /rm -rf/, risk: 2.9, approval: 0.9 }] }) });
  assert.equal(r.level, "deny", "the brain's deny line is untouched by the release");
  assert.match(r.message, /Segment scores: "rm -rf \/tmp\/x" 2\.9\/3 highest/);
  assert.ok(!/drove the hold/.test(r.message));
});

test("a fan-out failure leaves the verdict unchanged — the ask stands, no release", async () => {
  const counter = { calls: 0 };
  const r = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: CWD },
    { env: env0(), fetchImpl: brain(counter, { ...reproSpec, failAfter: 1 }) });
  assert.equal(r.level, "ask", "a flaky fan-out is conservative: the whole-command verdict keeps");
  assert.ok(!/Segment scores:/.test(r.message));
});

test("a degraded verdict never fans out — the posture decides", async () => {
  const down = async () => { throw Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:9"), { code: "ECONNREFUSED" }); };
  const r = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: CWD }, { env: env0(), fetchImpl: down });
  assert.equal(r.degraded, true);
  assert.ok(!/Segment scores:/.test(r.message));
});

// ── the no-prompt-host conversion carries the attribution (the verdict names the piece) ───────

test("askBlockedDeny preserves the trigger-named attribution on the converted deny", async () => {
  const cmd = "git status --short | cut -c1-2 | sort | uniq -c; git push origin main";
  const ask = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: CWD },
    { env: env0(), fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.1, approval: 0.85, cmd }, segs: reproSpec.segs }) });
  assert.equal(ask.level, "ask");
  assert.match(ask.attribution, /git push origin main.*drove the hold/);
  const blocked = askBlockedDeny(ask);
  assert.equal(blocked.level, "deny");
  assert.match(blocked.message, /no approval prompt/);
  assert.match(blocked.message, /Segment scores: "git push origin main" 2\.4\/3 \(risk ≥ 2\.0\) drove the hold/,
    "the converted deny names the piece that drove the hold");
});
