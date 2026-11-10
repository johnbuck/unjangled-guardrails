// Ticket 12 (epic-github-field-reports-2026-11, GitHub issue 12): generated-output cleanup.
// Four surfaces pinned here — (1) the repro: a session that earlier created an untracked
// render tree inside the project through allowed calls gets its solo `rm -rf` released
// (allow, one brain call, the numbers named in why); (2) tracked and operator-owned paths
// are unaffected: git-tracked operands and files the session did not create hold the ask,
// named by the `Cleanup verdict:` disqualifier; (3) the walls: the deny line never releases,
// operator ask entries never release, the leak tier holds, multi-segment compounds and
// single-segment non-cleanup calls are byte-identical, degraded rows keep the posture; (4)
// the recording half: the agentCreatedPaths miner (write tools, mkdir/-p prefixes, touch
// arg-flag skips, redirect targets) and rememberCreated (dedupe, cap). Conventions follow
// test/commit-band.test.js: throwaway GUARD_HOME + GUARD_SESSIONS, scripted brains, real
// throwaway git repos (init + config only, no network), no real brain.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { assessAction, askBlockedDeny, agentCleanupCommand, cleanupDisqualifier, agentCreatedPaths, agentCleanupEligible } from "../src/guard.js";
import { rememberCreated, readSession } from "../src/session.js";

const env0 = (extra = {}) => ({ GUARD_HOME: mkdtempSync(join(tmpdir(), "cleanup-band-")), GUARD_SESSIONS: mkdtempSync(join(tmpdir(), "cleanup-sessions-")), SYSTEMONE_URL: "http://brain.test", ...extra });

/** A throwaway real git repo (init + identity only — the untracked check reads the index). */
function repo() {
  const r = mkdtempSync(join(tmpdir(), "cleanup-repo-"));
  execSync("git init -q", { cwd: r });
  execSync("git config user.email t@t", { cwd: r });
  execSync("git config user.name t", { cwd: r });
  return r;
}
function track(repoDir, rel) {
  mkdirSync(dirname(join(repoDir, rel)), { recursive: true });
  writeFileSync(join(repoDir, rel), "tracked\n");
  execSync("git add -- " + rel, { cwd: repoDir });
}

/** Scripted brain (the commit-band idiom): the whole command answers `whole`, a `segs`
 *  matcher answers segment calls; default 0.4/0.10. */
function brain(counter, { whole, segs = [], failAfter = Infinity } = {}) {
  return async (_url, { body }) => {
    counter.calls += 1;
    if (counter.calls > failAfter) throw new Error("brain down");
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

// The GHI-12 repro numbers: the solo rm asks on generic destructiveness (risk 2.2 over the
// 2.0 bar, approval 0.80 over the 0.75 bar — both drivers noise for a verified shape).
const REPRO = "rm -rf _bmad/render";

// ── the classifier ───────────────────────────────────────────────────────────────────────────

test("agentCleanupCommand: the in-shape forms (plain rm/rmdir, allowlisted flags, plain operands)", () => {
  for (const seg of ["rm -rf _bmad/render", "rm _bmad/render/out.txt", "rm -r _bmad/render",
    "rm -R _bmad/render", "rm -f -- _bmad/render", "rm -rfv _bmad/render", "rm --recursive --force _bmad/render",
    "rmdir _bmad/render", "rmdir -p a/b", "FOO=1 rm -rf _bmad/render", "/usr/bin/rm -rf _bmad/render",
    "rm -rf _bmad/render _bmad/cache"])
    assert.equal(agentCleanupCommand(seg), true, `${seg} is cleanup-shaped`);
});

test("agentCleanupCommand: the out-of-shape forms stay brain-side", () => {
  for (const seg of ["rm -ri _bmad/render", "rm --interactive _bmad/render", "rm --one-file-system _bmad/render",
    "rm -rf _bmad/render/*", "rm -rf", "rmdir --ignore-failures a", "sudo rm -rf _bmad/render",
    "rm -rf _bmad/render; echo done", "rm -rf $(pwd)", "rm -rf 'unbalanced quote", "git commit -m x",
    "find . -delete", ""])
    assert.equal(agentCleanupCommand(seg), false, `${seg} stays brain-side`);
  // `rm -rf ~/stuff` PARSES as cleanup-shaped (the shape guard does not resolve ~) — the
  // eligibility rules it out instead: an operand outside the work tree never releases.
});

test("cleanupDisqualifier names the element that keeps a cleanup-shaped segment out", () => {
  assert.equal(cleanupDisqualifier("rm -ri _bmad/render"), "an unsupported flag (-ri)");
  assert.equal(cleanupDisqualifier("rm --one-file-system _bmad/render"), "an unsupported flag (--one-file-system)");
  assert.equal(cleanupDisqualifier("rm -rf _bmad/render/*"), "a wildcard operand");
  assert.equal(cleanupDisqualifier("rm -rf"), "an empty operand list");
  assert.equal(cleanupDisqualifier("rm -rf _bmad/render"), null, "in shape: no disqualifier");
  assert.equal(cleanupDisqualifier("git commit -m x"), null, "not cleanup-shaped: no disqualifier");
});

// ── the recording half: the miner and rememberCreated ────────────────────────────────────────

test("agentCreatedPaths: write-family tools record their path field", () => {
  assert.deepEqual(agentCreatedPaths("Write", { file_path: "/proj/out/a.md" }, "/proj"), ["/proj/out/a.md"]);
  assert.deepEqual(agentCreatedPaths("edit", { path: "out/a.md" }, "/proj"), ["/proj/out/a.md"]);
  assert.deepEqual(agentCreatedPaths("mcp__fs__write_file", { filePath: "b.md" }, "/proj"), ["/proj/b.md"]);
  assert.deepEqual(agentCreatedPaths("delete", { path: "/proj/x" }, "/proj"), [], "delete is not a creator");
  assert.deepEqual(agentCreatedPaths("read", { path: "/proj/x" }, "/proj"), [], "read is not a creator");
});

test("agentCreatedPaths: mkdir records the operand, and every prefix with -p", () => {
  assert.deepEqual(agentCreatedPaths("Bash", { command: "mkdir _bmad/render" }, "/proj"), ["/proj/_bmad/render"]);
  assert.deepEqual(agentCreatedPaths("Bash", { command: "mkdir -p a/b/c" }, "/proj"), ["/proj/a", "/proj/a/b", "/proj/a/b/c"]);
  assert.deepEqual(agentCreatedPaths("Bash", { command: "mkdir -m 755 d" }, "/proj"), ["/proj/d"], "the -m argument is not an operand");
});

test("agentCreatedPaths: touch arg-carrying flags skip their argument (a read source is never created)", () => {
  assert.deepEqual(agentCreatedPaths("Bash", { command: "touch out.txt" }, "/proj"), ["/proj/out.txt"]);
  assert.deepEqual(agentCreatedPaths("Bash", { command: "touch -r notes.txt out.txt" }, "/proj"), ["/proj/out.txt"], "-r's argument skipped");
  assert.deepEqual(agentCreatedPaths("Bash", { command: "touch -t 202001010000 stamp.txt" }, "/proj"), ["/proj/stamp.txt"], "-t's argument skipped");
});

test("agentCreatedPaths: standalone redirect targets record; /dev and globs never do", () => {
  assert.deepEqual(agentCreatedPaths("Bash", { command: "sort f > out.txt" }, "/proj"), ["/proj/out.txt"]);
  assert.deepEqual(agentCreatedPaths("Bash", { command: "cmd >> log.txt 2> err.txt" }, "/proj"), ["/proj/log.txt", "/proj/err.txt"]);
  assert.deepEqual(agentCreatedPaths("Bash", { command: "cmd > /dev/null 2>&1" }, "/proj"), []);
  assert.deepEqual(agentCreatedPaths("Bash", { command: "cmd > *.tmp" }, "/proj"), []);
});

test("agentCreatedPaths: only targets that do not exist yet are creations (the existsSync oracle)", () => {
  const r = repo();
  writeFileSync(join(r, "operator-notes.txt"), "operator");
  mkdirSync(join(r, "existing-tree", "deep"), { recursive: true });
  writeFileSync(join(r, "existing-tree", "deep", "f.md"), "operator");
  // touch/mkdir/redirects over EXISTING paths claim nothing — the operator's files stay undeletable
  assert.deepEqual(agentCreatedPaths("Bash", { command: "touch operator-notes.txt" }, r), []);
  assert.deepEqual(agentCreatedPaths("Bash", { command: "cmd >> operator-notes.txt" }, r), []);
  assert.deepEqual(agentCreatedPaths("Bash", { command: "mkdir -p existing-tree/deep/new" }, r), [join(r, "existing-tree/deep/new")], "only the missing prefix records");
  assert.deepEqual(agentCreatedPaths("Bash", { command: "touch -c absent.txt" }, r), [], "touch -c creates nothing");
  // and the absent case still records (the call will create it)
  assert.deepEqual(agentCreatedPaths("Bash", { command: "mkdir -p fresh/tree" }, r), [join(r, "fresh"), join(r, "fresh/tree")]);
});

test("rememberCreated dedupes, caps, and reads back through readSession", () => {
  const env = env0();
  rememberCreated("s1", "/proj/a", env);
  rememberCreated("s1", "/proj/b", env);
  rememberCreated("s1", "/proj/a", env); // dedupe: refreshes, never doubles
  assert.deepEqual(readSession("s1", env).created.map((c) => c.path), ["/proj/b", "/proj/a"]);
  for (let i = 0; i < 80; i++) rememberCreated("s1", `/proj/f${i}`, env);
  assert.equal(readSession("s1", env).created.length, 64, "the created list caps at 64");
});

// ── the eligibility: the three deterministic checks against real git repos ────────────────────

test("agentCleanupEligible: the repro shape verifies (created, untracked, inside the work tree)", () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  writeFileSync(join(r, "_bmad", "render", "step-05.md"), "render snapshot");
  rememberCreated("s2", join(r, "_bmad/render"), env);
  assert.deepEqual(agentCleanupEligible(REPRO, { cwd: r, sessionId: "s2", env }), { ok: true });
});

test("agentCleanupEligible: a write-tool-built tree verifies through the walk", () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  for (const f of ["a.md", "b.md"]) writeFileSync(join(r, "_bmad", "render", f), "x");
  rememberCreated("s3", join(r, "_bmad/render/a.md"), env);
  rememberCreated("s3", join(r, "_bmad/render/b.md"), env);
  assert.deepEqual(agentCleanupEligible(REPRO, { cwd: r, sessionId: "s3", env }), { ok: true });
});

test("agentCleanupEligible: tracked content and operator files hold", () => {
  const env = env0();
  const r = repo();
  track(r, "src/a.js");
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  rememberCreated("s4", join(r, "_bmad/render"), env);
  assert.equal(agentCleanupEligible("rm -rf src", { cwd: r, sessionId: "s4", env }).why, "a tracked path (git lists content under it)");
  // A write-tool-built tree (the folder itself never recorded — only its files): an
  // operator-dropped untracked file inside it is caught by the walk and holds the ask.
  // (A tree whose ROOT the session mkdir'd claims its subtree — the repro's script-filled
  // shape — recorded as the deliberate residual in the plan change log.)
  mkdirSync(join(r, "gen"), { recursive: true });
  writeFileSync(join(r, "gen", "a.md"), "x");
  writeFileSync(join(r, "gen", "notes.txt"), "operator notes");
  rememberCreated("s4", join(r, "gen/a.md"), env);
  assert.equal(agentCleanupEligible("rm -rf gen", { cwd: r, sessionId: "s4", env }).why, "file content this session did not create");
});

test("agentCleanupEligible: no session record, outside the work tree, .git, and no repo all hold", () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  assert.equal(agentCleanupEligible(REPRO, { cwd: r, sessionId: undefined, env }).why, "a path this session did not create", "no session → nothing proven created (an empty tree proves nothing)");
  writeFileSync(join(r, "_bmad", "render", "a.md"), "x");
  assert.equal(agentCleanupEligible(REPRO, { cwd: r, sessionId: undefined, env }).why, "file content this session did not create", "files with no record hold");
  rememberCreated("s5", join(r, "_bmad/render/a.md"), env);
  assert.equal(agentCleanupEligible("rm -rf ~/stuff", { cwd: r, sessionId: "s5", env }).why, "a path outside the project work tree");
  assert.equal(agentCleanupEligible("rm -rf /tmp/x", { cwd: r, sessionId: "s5", env }).why, "a path outside the project work tree");
  assert.equal(agentCleanupEligible("rm -rf .git", { cwd: r, sessionId: "s5", env }).why, "the git metadata directory");
  assert.equal(agentCleanupEligible(REPRO, { cwd: mkdtempSync(join(tmpdir(), "norepo-")), sessionId: "s5", env }).why, "a path outside the project work tree");
  track(r, "src/a.js");
  assert.equal(agentCleanupEligible("rm -rf _bmad/render src", { cwd: r, sessionId: "s5", env }).ok, false, "one tracked operand poisons the command");
});

test("agentCleanupEligible: an oversized tree is unverifiable, never released", () => {
  const env = env0();
  const r = repo();
  const big = join(r, "big");
  mkdirSync(big, { recursive: true });
  // 64 recorded subdirs × 21 files each = 1344 covered entries — the operand itself is not
  // covered, so the walk runs, every file is covered by its recorded parent, and only the
  // SIZE defeats verification (the created list caps at 64, so volume rides ancestors).
  for (let d = 0; d < 64; d++) {
    const sub = join(big, `s${d}`);
    mkdirSync(sub);
    rememberCreated("s6", sub, env);
    for (let i = 0; i < 21; i++) writeFileSync(join(sub, `f${i}.txt`), "x");
  }
  assert.equal(agentCleanupEligible("rm -rf big", { cwd: r, sessionId: "s6", env }).why, "a tree too large to verify");
  rmSync(big, { recursive: true, force: true });
});

// ── the repro through assessAction: release, one brain call, no segments ──────────────────────

test("the GHI-12 repro: a solo rm of the session's untracked render tree releases, one brain call", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  writeFileSync(join(r, "_bmad", "render", "step-05.md"), "render snapshot");
  rememberCreated("s7", join(r, "_bmad/render"), env);
  const counter = { calls: 0 };
  const res = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: r, sessionId: "s7" },
    { env, fetchImpl: brain(counter, { whole: { risk: 2.2, approval: 0.8, cmd: REPRO } }) });
  assert.equal(res.level, "allow", `the repro must pass: ${JSON.stringify(res)}`);
  assert.match(res.why, /removing untracked paths this session created inside the project does not justify a hold \(risk 2\.2\/3, approval p=0\.80 not held against it\) — the generated-output cleanup release allowed the ask/);
  assert.match(res.stats, /risk 2\.2\/3, approval p=0\.80/, "the whole-command measurement stays in stats");
  assert.ok(!res.segments, "an allow row never carries segments (decision-export biconditional)");
  assert.equal(counter.calls, 1, `the whole-command answers ARE the segment answers — no second call, got ${counter.calls}`);
});

test("the write-tool-built tree (no mkdir) releases through the walk", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  writeFileSync(join(r, "_bmad", "render", "a.md"), "x");
  rememberCreated("s8", join(r, "_bmad/render/a.md"), env);
  const res = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: r, sessionId: "s8" },
    { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, cmd: REPRO } }) });
  assert.equal(res.level, "allow");
});

test("a plain rm of one recorded untracked file releases", async () => {
  const env = env0();
  const r = repo();
  writeFileSync(join(r, "out.txt"), "x");
  rememberCreated("s9", join(r, "out.txt"), env);
  const CMD = "rm out.txt";
  const res = await assessAction({ tool: "Bash", input: { command: CMD }, cwd: r, sessionId: "s9" },
    { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, cmd: CMD } }) });
  assert.equal(res.level, "allow");
});

// ── held cleanups: tracked, operator content, and the naming ─────────────────────────────────

test("a tracked operand holds and the Cleanup verdict names it", async () => {
  const env = env0();
  const r = repo();
  track(r, "src/a.js");
  const CMD = "rm -rf src";
  const res = await assessAction({ tool: "Bash", input: { command: CMD }, cwd: r, sessionId: "s10" },
    { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, cmd: CMD } }) });
  assert.equal(res.level, "ask");
  assert.match(res.attribution, /Cleanup verdict: "rm -rf src" 2\.2\/3 \(risk ≥ 2\.0\) drove the hold; a tracked path \(git lists content under it\) keeps it out of the agent-cleanup shape\./);
});

test("an operator file inside a write-built tree holds and names the content", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  writeFileSync(join(r, "_bmad", "render", "a.md"), "x");
  writeFileSync(join(r, "_bmad", "render", "notes.txt"), "operator notes");
  rememberCreated("s11", join(r, "_bmad/render/a.md"), env);
  const res = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: r, sessionId: "s11" },
    { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, cmd: REPRO } }) });
  assert.equal(res.level, "ask");
  assert.match(res.attribution, /file content this session did not create keeps it out of the agent-cleanup shape\./);
});

test("no session record holds and names it", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  writeFileSync(join(r, "_bmad", "render", "a.md"), "x");
  const res = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: r },
    { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, cmd: REPRO } }) });
  assert.equal(res.level, "ask");
  assert.match(res.attribution, /file content this session did not create keeps it out of the agent-cleanup shape\./);
});

test("an unsupported flag and a wildcard operand stay brain-side and are named", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  rememberCreated("s12", join(r, "_bmad/render"), env);
  for (const [cmd, why] of [["rm -ri _bmad/render", "an unsupported flag (-ri)"], ["rm -rf _bmad/render/*", "a wildcard operand"]]) {
    const res = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: r, sessionId: "s12" },
      { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, cmd } }) });
    assert.equal(res.level, "ask", cmd);
    assert.match(res.attribution, new RegExp(why.replace(/[()]/g, "\\$&") + " keeps it out of the agent-cleanup shape\\."), cmd);
  }
});

// ── the walls ────────────────────────────────────────────────────────────────────────────────

test("the deny line never releases and carries no Cleanup verdict sentence", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  rememberCreated("s13", join(r, "_bmad/render"), env);
  const res = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: r, sessionId: "s13" },
    { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.9, approval: 0.9, cmd: REPRO } }) });
  assert.equal(res.level, "deny");
  assert.ok(!/Cleanup verdict/.test(res.message), "the deny keeps today's shape");
});

test("the leak tier holds an eligible cleanup shape (the wall), with the driver named", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  rememberCreated("s14", join(r, "_bmad/render"), env);
  const res = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: r, sessionId: "s14" },
    { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, leak: 0.9, cmd: REPRO } }) });
  assert.equal(res.level, "ask", "an eligible shape with leak-tier answers does not release — the leak wall holds");
  assert.match(res.attribution, /Cleanup verdict: "rm -rf _bmad\/render" 2\.2\/3 \(risk ≥ 2\.0\) drove the hold\./, "the driver names risk first (the 1.9 priority: risk, then approval, then leak)");
  assert.ok(!/keeps it out/.test(res.attribution), "the shape was eligible — no disqualifier clause");
});

test("an operator lane ask never releases an eligible cleanup shape", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  rememberCreated("s15", join(r, "_bmad/render"), env);
  // an operator ask entry on the bash lane, seeded through the lane store (the lane.test idiom)
  mkdirSync(env.GUARD_HOME, { recursive: true });
  writeFileSync(join(env.GUARD_HOME, "user-lane.json"),
    JSON.stringify({ tools: [{ pattern: "bash", effect: "ask", id: "cleanup-lane-test" }] }));
  const res = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: r, sessionId: "s15" },
    { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, cmd: REPRO } }) });
  assert.equal(res.level, "ask");
  assert.match(res.why, /user lane: always asks by operator rule/);
  assert.ok(!/generated-output cleanup release/.test(res.why), "the operator ask holds");
});

test("degraded rows keep the posture (no 2c, no release)", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  rememberCreated("s16", join(r, "_bmad/render"), env);
  const res = await assessAction({ tool: "Bash", input: { command: REPRO }, cwd: r, sessionId: "s16" },
    { env, fetchImpl: brain({ calls: 0 }, { failAfter: 0 }) });
  assert.ok(res.degraded, "brain down is the posture verdict");
  assert.ok(!/Cleanup verdict/.test(res.message));
});

test("multi-segment compounds keep their shapes (the cleanup branch is solo-only)", async () => {
  const env = env0();
  const r = repo();
  mkdirSync(join(r, "_bmad", "render"), { recursive: true });
  rememberCreated("s17", join(r, "_bmad/render"), env);
  const two = "rm -rf _bmad/render; echo done";
  const res = await assessAction({ tool: "Bash", input: { command: two }, cwd: r, sessionId: "s17" },
    { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, cmd: two }, segs: [{ re: /rm -rf/, risk: 2.2, approval: 0.8 }] }) });
  assert.equal(res.level, "ask");
  assert.match(res.attribution, /Segment scores: "rm -rf _bmad\/render" 2\.2\/3 \(risk ≥ 2\.0\) drove the hold/);
  assert.ok(!/Cleanup verdict/.test(res.attribution), "compounds keep the CAP-8 naming, not the solo cleanup sentence");
});

test("a held cleanup ask converts on no-prompt hosts carrying the Cleanup verdict", async () => {
  const env = env0();
  const r = repo();
  track(r, "src/a.js");
  const CMD = "rm -rf src";
  const counter = { calls: 0 };
  const res = await assessAction({ tool: "Bash", input: { command: CMD }, cwd: r, sessionId: "s18" },
    { env, fetchImpl: brain(counter, { whole: { risk: 2.2, approval: 0.8, cmd: CMD } }) });
  assert.equal(res.level, "ask");
  const blocked = askBlockedDeny(res);
  assert.equal(blocked.level, "deny");
  assert.match(blocked.message, /Cleanup verdict: "rm -rf src" 2\.2\/3 \(risk ≥ 2\.0\) drove the hold; a tracked path \(git lists content under it\) keeps it out of the agent-cleanup shape\./);
});

// ── the adapter recording path: hook judge records created paths on allow ────────────────────

test("handleHook records created paths for allowed creator calls (the adapter layer)", async () => {
  const { handleHook } = await import("../src/hook.js");
  const env = env0();
  const r = repo();
  const saved = { GUARD_HOME: process.env.GUARD_HOME, GUARD_SESSIONS: process.env.GUARD_SESSIONS, SYSTEMONE_URL: process.env.SYSTEMONE_URL };
  Object.assign(process.env, { GUARD_HOME: env.GUARD_HOME, GUARD_SESSIONS: env.GUARD_SESSIONS, SYSTEMONE_URL: "http://brain.test" });
  try {
    const brainFn = brain({ calls: 0 }, { whole: { risk: 0.4, approval: 0.1, cmd: "mkdir -p _bmad/render" } });
    const out = await handleHook({ hook_event_name: "PreToolUse", session_id: "s19", cwd: r, tool_name: "Bash", tool_input: { command: "mkdir -p _bmad/render" } }, { env, fetchImpl: brainFn });
    assert.equal(out, null, "a low-risk mkdir allows");
    const created = readSession("s19", env).created.map((c) => c.path);
    assert.deepEqual(created, [join(r, "_bmad"), join(r, "_bmad/render")], "every created prefix recorded");
    // and the released cleanup works end to end through the hook path
    const rm = await handleHook({ hook_event_name: "PreToolUse", session_id: "s19", cwd: r, tool_name: "Bash", tool_input: { command: REPRO } },
      { env, fetchImpl: brain({ calls: 0 }, { whole: { risk: 2.2, approval: 0.8, cmd: REPRO } }) });
    assert.equal(rm, null, "the cleanup released — the hook passes it through");
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
});

// (no global teardown needed — the OS tmpdir sweeps; the walk-cap repo is eagerly removed below)

test("the 1.8/1.9 surfaces hold: a commit band release and a floor release are unchanged", async () => {
  const env = env0();
  const counter = { calls: 0 };
  const commit = await assessAction({ tool: "Bash", input: { command: "git commit -m 'ship it'" }, cwd: "/proj" },
    { env, fetchImpl: brain(counter, { whole: { risk: 1.2, approval: 0.78, cmd: "git commit -m 'ship it'" } }) });
  assert.equal(commit.level, "allow", "the commit band still releases");
  assert.match(commit.why, /the commit band released the ask/);
});
