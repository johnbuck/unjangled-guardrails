// Ticket 1.13 / CAP-12 (epic-github-field-reports, GitHub issue 13): the suggested
// defaults never allow push and never lift leak denies. Operator rulings 2026-11-09
// (spec-field-response-doctrine memlog): 2a — the two push entries left the defaults for
// the opt-in example file, adopted deliberately by name or not at all; 3 — that same file
// carries the projects-folder-scoped commit allows (matchable since 1.6's workdir-resolved
// scope, 767afd5); 2b — the cat/grep/echo leak-lift trio left the defaults outright, its
// removal condition met by 1.15 landing as dd65c4c with battery evidence (routine reads
// stay quiet through leak-guard precision, not blanket allows). Every consult row runs
// against a scripted brain — the day's documented degraded-until-proven brain posture;
// rows are deterministic against the script.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { assessAction } from "../src/guard.js";
import { adoptDefaults, listEntries, addCommandEntry } from "../src/policy.js";
import { matches } from "../src/rulings.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const DEFAULTS_FILE = join(REPO, "examples", "user-policy.default.json");
const OPT_IN_FILE = join(REPO, "examples", "user-policy.git-work.json");
const DEFAULTS = JSON.parse(readFileSync(DEFAULTS_FILE, "utf8"));
const OPT_IN = JSON.parse(readFileSync(OPT_IN_FILE, "utf8"));

const PUSH_SHAPES = ["git push", "git push origin *"];
const LEAK_LIFT_TRIO = ["cat *", "grep *", "echo *"];
const LISTING_UTILITIES = ["ls *", "head *", "tail *", "wc *", "find *"];

// ── file-content pins ────────────────────────────────────────────────────────────────────────

test("the defaults file carries no push entry and no leak-lift trio (rulings 2a/2b)", () => {
  const patterns = DEFAULTS.entries.map((e) => e.pattern);
  for (const p of PUSH_SHAPES) assert.ok(!patterns.includes(p), `${p} must not ship in the defaults (ruling 2a: push is opt-in only)`);
  for (const p of LEAK_LIFT_TRIO) assert.ok(!patterns.includes(p), `${p} must ship nowhere (ruling 2b: removed outright, not moved)`);
  // the ruling's own boundary: the plain listing utilities keep their entries
  for (const p of LISTING_UTILITIES) assert.ok(patterns.includes(p), `${p} keeps its listing-utility entry`);
  assert.ok(patterns.includes("git commit -m *"), "message-only commits keep the defaults entry");
  assert.ok(patterns.includes("rm -rf build/*"), "the throwaway list (ticket 1.12's located list) is untouched");
});

test("the opt-in git-work file carries exactly the ruled shape, placeholder documented in-file", () => {
  assert.equal(OPT_IN.entries.length, 4, "two push entries plus two folder-scoped commit allows");
  for (const p of PUSH_SHAPES) {
    const e = OPT_IN.entries.find((x) => x.pattern === p);
    assert.ok(e, `${p} is an opt-in entry`);
    assert.equal(e.effect, "allow");
    assert.equal(e.scope, "global");
  }
  for (const p of ["git add *", "git commit *"]) {
    const e = OPT_IN.entries.find((x) => x.pattern === p);
    assert.ok(e, `${p} is an opt-in entry (ruling 3: the projects-folder mitigation)`);
    assert.equal(e.effect, "allow");
  }
  // the no-topology rule: every project-scoped entry carries the ONE conventional generic
  // placeholder spelling — never a real operator path
  for (const e of OPT_IN.entries.filter((x) => String(x.scope ?? "").startsWith("project:")))
    assert.equal(e.scope, "project:~/projects", "the generic placeholder, and only the placeholder");
  assert.ok(!OPT_IN.entries.some((e) => LEAK_LIFT_TRIO.includes(e.pattern)), "no leak-lift entry rides the opt-in file either (ruling 2b removed them, moved nothing)");
  const readme = OPT_IN.readme.join("\n");
  assert.match(readme, /placeholder/i, "the file documents its own placeholder");
  assert.match(readme, /by name/, "the file documents adoption by name");
  assert.match(readme, /never\s+deletes/i, "the file tells already-adopted installs what holds");
});

// ── adoption pins ────────────────────────────────────────────────────────────────────────────

test("a fresh adopt-defaults produces no standing push allow and no leak-lifting allow (the verify row)", () => {
  const home = mkdtempSync(join(tmpdir(), "unjangled-guardrails-posture-"));
  const r = adoptDefaults({ GUARD_HOME: home, GUARD_OPERATOR_CLI: "1" });
  assert.ok(r.added > 30, `the suggested set still loads (${r.added} added)`);
  assert.equal(r.source, DEFAULTS_FILE);
  const patterns = listEntries({ GUARD_HOME: home }).map((e) => e.pattern);
  for (const p of [...PUSH_SHAPES, ...LEAK_LIFT_TRIO])
    assert.ok(!patterns.includes(p), `${p} must not land in a fresh store`);
  for (const p of [...LISTING_UTILITIES, "git commit -m *", "rm -rf .tmp/*", "mkdir -p /tmp/*"])
    assert.ok(patterns.includes(p), `${p} still lands`);
});

test("adopt by name loads the opt-in file; re-adopt skips; a defaults adopt on top adds without touching it", () => {
  const home = mkdtempSync(join(tmpdir(), "unjangled-guardrails-posture-optin-"));
  const E = { GUARD_HOME: home, GUARD_OPERATOR_CLI: "1" };
  const first = adoptDefaults(E, { file: OPT_IN_FILE });
  assert.equal(first.source, OPT_IN_FILE);
  assert.equal(first.added, 4);
  const entries = listEntries(E);
  const bare = entries.find((e) => e.pattern === "git push");
  assert.ok(bare && bare.effect === "allow" && bare.scope === "global", "the push entries land verbatim");
  const scoped = entries.find((e) => e.pattern === "git commit *");
  assert.equal(scoped.scope, "project:~/projects", "the placeholder rides into the store as written");
  const second = adoptDefaults(E, { file: OPT_IN_FILE });
  assert.equal(second.added, 0);
  assert.equal(second.skipped, 4);
  // additive both ways: the defaults on top add their set, the opt-in entries untouched
  const third = adoptDefaults(E);
  assert.ok(third.added > 30);
  assert.equal(listEntries(E).filter((e) => e.pattern === "git push").length, 1);
  assert.ok(!listEntries(E).some((e) => LEAK_LIFT_TRIO.includes(e.pattern)), "the opt-in file pulls no leak-lift entry either");
});

test("an already-adopted install keeps its pre-rework entries: adoption is additive and never deletes", () => {
  const home = mkdtempSync(join(tmpdir(), "unjangled-guardrails-posture-legacy-"));
  const E = { GUARD_HOME: home, GUARD_OPERATOR_CLI: "1" };
  addCommandEntry({ effect: "allow", pattern: "git push", scope: "global", reason: "pre-rework adoptee" }, E);
  adoptDefaults(E);
  const patterns = listEntries(E).map((e) => e.pattern);
  assert.ok(patterns.includes("git push"), "the operator's standing entry survives the reworked defaults (hand removal is the documented path)");
  // skipped counts DEFAULTS-vs-store dupes: the reworked defaults carry nothing push-shaped,
  // so the seeded entry simply never comes up — nothing removed it, nothing overwrote it
});

// ── consult rows (scripted brain; deterministic against the script) ──────────────────────────

// The house fake brain (rulings.test.js's shape): push/commit-shaped commands ask at 2.0 —
// the band a standing allow must lift.
async function askBrain(_url, { body }) {
  const { state } = JSON.parse(body);
  const cmd = JSON.stringify(state.input);
  const score = /rm -rf|DROP TABLE/.test(cmd) ? 2.9 : /git push|git commit|git add/.test(cmd) ? 2.0 : 0.2;
  const answers = {
    risk: { type: "score", score, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: score >= 2 ? 0.85 : 0.05 },
    user_requested: { type: "noul", noul: 0.05 }, from_untrusted: { type: "noul", noul: 0.05 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
  };
  return { ok: true, json: async () => ({ answers }) };
}

// A leak-denying brain (leak.test.js's shape): the probe command carries a confident
// leaks_secrets answer — the brain-side deny a standing `echo *` allow used to lift. The
// probe text itself is shape-free (leak.test.js's own Always-Deny-clean spelling); the
// brain supplies the verdict, the command text is only the entry's match key.
async function leakBrain(_url, { body }) {
  const { state } = JSON.parse(body);
  const cmd = JSON.stringify(state.input);
  const leak = /echo printenv/.test(cmd) ? 0.95 : 0.05;
  const answers = {
    risk: { type: "score", score: 0.3, probabilities: {}, confidence: 0.7 },
    approval: { type: "noul", noul: 0.1 },
    user_requested: { type: "noul", noul: 0.05 }, from_untrusted: { type: "noul", noul: 0.05 },
    leaks_secrets: { type: "noul", noul: leak, confidence: 0.9 },
    dumps_env_argv: { type: "noul", noul: 0.05 }, dumps_process_argv: { type: "noul", noul: 0.05 },
    reads_credential_file: { type: "noul", noul: 0.05 },
  };
  return { ok: true, json: async () => ({ answers }) };
}

const env = (dir) => ({ SYSTEMONE_URL: "http://127.0.0.1:9", GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" });
const opts = (dir, brain = askBrain) => ({ env: env(dir), fetchImpl: brain });

test("defaults only: a held push asks with no lifter — no standing push allow (ruling 2a's default posture)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-posture-ask-"));
  adoptDefaults(env(dir));
  const verdict = await assessAction({ tool: "Bash", input: { command: "git push origin main" }, cwd: "/proj/repo", sessionId: "s-13" }, opts(dir));
  assert.equal(verdict.level, "ask");
  assert.ok(!verdict.ruling, "no entry consulted — nothing push-shaped in the store");
});

test("opt-in adopted: the same held push lifts through the push entries", async () => {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-posture-ask-"));
  adoptDefaults(env(dir), { file: OPT_IN_FILE });
  for (const command of ["git push", "git push origin main"]) {
    const verdict = await assessAction({ tool: "Bash", input: { command }, cwd: "/proj/repo", sessionId: "s-13" }, opts(dir));
    assert.equal(verdict.level, "allow", command);
    assert.ok(verdict.ruling, `${command}: the entry did the lifting (not the fail-open posture)`);
  }
  // the floor above the entries: force shapes deny before any entry is consulted
  assert.equal((await assessAction({ tool: "Bash", input: { command: "git push --force origin main" }, cwd: "/proj/repo", sessionId: "s-13" }, opts(dir))).level, "deny");
  assert.equal((await assessAction({ tool: "Bash", input: { command: "git push origin +main" }, cwd: "/proj/repo", sessionId: "s-13" }, opts(dir))).level, "deny");
});

test("ruling 2b's payoff: a brain leak deny stands under the fresh-adopted defaults — and a hand-minted echo allow is the control that proves the absence has teeth", async () => {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-posture-leak-"));
  adoptDefaults(env(dir));
  const call = { tool: "Bash", input: { command: "echo printenv details" }, cwd: "/proj", sessionId: "s-13" };
  const held = await assessAction(call, opts(dir, leakBrain));
  assert.equal(held.level, "deny", "no leak-lifting allow shipped: the brain's deny stands");
  assert.match(held.message, /Credential Exposure/);
  // the control: the SAME deny under a store carrying a hand-minted `echo *` allow flips —
  // the pre-rework defaults' own shape — proving the removal is what stands, not unliftable denies
  const control = mkdtempSync(join(tmpdir(), "unjangled-guardrails-posture-leakctl-"));
  addCommandEntry({ effect: "allow", pattern: "echo *", scope: "global", reason: "control: the removed shape" }, env(control));
  const lifted = await assessAction(call, opts(control, leakBrain));
  assert.equal(lifted.level, "allow", "the control row lifts exactly as the issue complained — the entry absence above is the fix");
});

// ── ruling 3: the folder-scoped commit allows, matchable through 1.6's workdir resolution ────

test("the scoped commit allows lift a held commit whose workdir is inside the folder (the subagent mitigation)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-posture-scope-"));
  const projects = join(dir, "projects");
  // the operator's act: the placeholder substituted with a real absolute folder, then adopted by name
  const localized = JSON.parse(JSON.stringify(OPT_IN));
  for (const e of localized.entries) if (String(e.scope ?? "").startsWith("project:")) e.scope = `project:${projects}`;
  const localizedFile = join(dir, "git-work-localized.json");
  writeFileSync(localizedFile, JSON.stringify(localized, null, 2) + "\n");
  adoptDefaults(env(dir), { file: localizedFile });
  // the GHI-6 shape: the payload cwd is the harness home, the call's workdir is the repo inside the folder
  const harnessHome = join(dir, "harness-home");
  const repoWd = join(projects, "repo-a");
  for (const command of ["git commit --amend -m wip", "git add -A src"]) {
    const verdict = await assessAction({ tool: "Bash", input: { command, workdir: repoWd }, cwd: harnessHome, sessionId: "s-13" }, opts(dir));
    assert.equal(verdict.level, "allow", command);
    assert.ok(verdict.ruling, `${command}: the scoped entry lifted the ask`);
  }
  // the must-not: workdir outside the folder — the ask stands, no widening
  const outside = await assessAction({ tool: "Bash", input: { command: "git commit --amend -m wip", workdir: join(dir, "elsewhere") }, cwd: harnessHome, sessionId: "s-13" }, opts(dir));
  assert.equal(outside.level, "ask");
  assert.ok(!outside.ruling);
});

test("the unedited placeholder never matches — the safe direction (topology rule's payoff)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-posture-placeholder-"));
  adoptDefaults(env(dir), { file: OPT_IN_FILE });
  const verdict = await assessAction({ tool: "Bash", input: { command: "git commit --amend -m wip", workdir: "/proj/repo" }, cwd: "/harness", sessionId: "s-13" }, opts(dir));
  assert.equal(verdict.level, "ask");
  assert.ok(!verdict.ruling, "project:~/projects is a literal prefix — it matches no absolute workdir");
});

test("the scoped entries match through the real matcher only under the localized scope", () => {
  const asStored = (e) => ({ id: "x", kind: "command", effect: e.effect, pattern: e.pattern, scope: e.scope ?? "global", reason: e.reason ?? "" });
  const scoped = OPT_IN.entries.find((e) => e.pattern === "git commit *");
  const localized = { ...scoped, scope: "project:/Users/you/projects" };
  assert.equal(matches(asStored(localized), { preview: ["git commit --amend -m wip"], cwd: "/Users/you/projects/repo-a" }), true);
  assert.equal(matches(asStored(localized), { preview: ["git commit --amend -m wip"], cwd: "/Users/you/elsewhere" }), false);
  assert.equal(matches(asStored(scoped), { preview: ["git commit --amend -m wip"], cwd: "/Users/you/projects/repo-a" }), false, "the tilde placeholder itself matches no absolute cwd — localization is the operator's act");
});

// ── documentation pins ───────────────────────────────────────────────────────────────────────

test("the opt-in path is documented: policy.md names the file and the by-name command; the CLI help names it too", () => {
  const md = readFileSync(join(REPO, "docs", "policy.md"), "utf8");
  assert.match(md, /user-policy\.git-work\.json/, "policy.md names the opt-in file");
  assert.match(md, /adopt-defaults examples\/user-policy\.git-work\.json/, "the by-name adopt command is spelled out");
  const cli = readFileSync(join(REPO, "src", "cli.js"), "utf8");
  assert.match(cli, /user-policy\.git-work\.json/, "the main help names the opt-in file");
});
