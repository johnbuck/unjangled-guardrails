// Ticket 1.1 / CAP-13 (epic-github-field-reports, GitHub issue 1): the README's Install
// section ends with the recommended-next-steps checklist — the last surface of the
// doctrine 1.19 started (the install command's tail and the plugin README carry the same
// block) and the reason this one is written after 1.13 (the opt-in git-work variant the
// checklist names) and 1.16 (the readiness-report posture section the posture step points
// at). One source of truth per fact, the repo's README-fact discipline: every path and
// command spelling the block names is pinned against the surface that owns it —
// suggestedDefaultsFile() (the export setup's warning renders and adoptDefaults reads), the
// opt-in file on disk, the by-name spelling docs/policy.md already pins, the CLI's own
// accepted-values refusal, and the USAGE vocabulary.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { suggestedDefaultsFile } from "../src/policy.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const README = readFileSync(join(REPO, "README.md"), "utf8");

// policy-flag-matrix.test.js's env shape: temp GUARD_HOME so no leg touches a real store.
const env = (dir) => ({ JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" });
const run = (dir, ...args) =>
  execFileSync(process.execPath, ["src/cli.js", ...args], { cwd: REPO, env: env(dir) });
const fails = (dir, ...args) => {
  try { run(dir, ...args); return null; }
  catch (e) { return e; }
};

const block = () => {
  const start = README.indexOf("### Recommended next steps");
  const end = README.indexOf("## How decisions are made");
  return { start, end, text: README.slice(start, end) };
};

test("the block ends the Install section — heading order pinned, nothing after it before the next ##", () => {
  const at = ["## Install", "### Hermes", "### Brain configuration", "### Recommended next steps", "## How decisions are made"].map((s) => README.indexOf(s));
  assert.ok(at.every((i) => i >= 0), "every heading present");
  assert.deepEqual(at, [...at].sort((a, b) => a - b), "the block is the Install section's tail");
  const { text } = block();
  assert.ok(!text.includes("\n## "), "no top-level section inside the block");
});

test("item 1 — review-then-adopt the defaults, never automatic, the opt-in variant by name", () => {
  const { text } = block();
  assert.match(text, /nothing is adopted\nautomatically, ever/, "the intro's never-automatic truth (1.19's shared wording)");
  assert.match(text, /examples\/user-policy\.default\.json/, "the defaults file is named for review");
  assert.match(text, /node src\/cli\.js policy adopt-defaults`/, "the adopt command, checkout form");
  assert.match(text, /never automatic/, "adoption stays explicit in the item itself");
  assert.match(text, /policy adopt-defaults examples\/user-policy\.git-work\.json/, "the opt-in file loads only by name");
  assert.match(text, /[Pp]ush allows and projects-folder-scoped\s+commit allows/, "the variant's contents are said");
  // one source of truth: the defaults path is the export adoptDefaults reads (1.19's pin)
  assert.equal(relative(REPO, suggestedDefaultsFile()), join("examples", "user-policy.default.json"));
  assert.ok(README.includes(relative(REPO, suggestedDefaultsFile())), "the README names exactly that path");
  assert.ok(existsSync(join(REPO, "examples", "user-policy.git-work.json")), "the opt-in file exists on disk");
  const policyDoc = readFileSync(join(REPO, "docs", "policy.md"), "utf8");
  assert.match(policyDoc, /policy\s+adopt-defaults examples\/user-policy\.git-work\.json/, "docs/policy.md pins the same by-name spelling");
});

test("item 2 — the posture step: the change command, where the report shows it, env wins", () => {
  const { text } = block();
  assert.match(text, /node src\/cli\.js policy set --degradation fail-open \| fail-closed/, "the change command");
  assert.match(text, /fail-open by\s+default/, "the default is named");
  assert.match(text, /GUARD_FALLBACK` \/ `GUARD_FAIL_CLOSED` env still wins over the per-install\s+setting/, "the env-wins caveat, both spellings");
  assert.match(text, /setup`'s readiness report names the active posture/, "where the report shows it (1.16's section)");
});

test("item 3 — calibrate named with the node entry", () => {
  const { text } = block();
  assert.match(text, /node src\/cli\.js calibrate/, "the certify step, checkout form");
});

test("the settled shape — exactly three numbered items, no sprawling fourth", () => {
  const { text } = block();
  assert.equal((text.match(/^\d+\. /gm) ?? []).length, 3);
});

test("the posture vocabulary is the CLI's own — a bad value's refusal names the accepted forms, no store write", () => {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-readme-next-steps-"));
  const e = fails(dir, "policy", "set", "--degradation", "nope");
  assert.ok(e, "the bad value refuses");
  assert.equal(e.status, 1);
  assert.match(String(e.stderr), /policy set --degradation takes fail-open \| fail-closed/);
  assert.ok(!existsSync(join(dir, "user-policy.json")), "the refusal dies before any store write");
});

test("the named commands are real CLI commands — every checklist spelling lives in the CLI's own help", () => {
  const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-readme-next-steps-"));
  const usage = run(dir).toString();                             // bare invocation: USAGE on stdout, exit 0
  for (const spelling of ["setup", "calibrate"]) {
    assert.match(usage, new RegExp(spelling), spelling);        // the top-level commands, named in the USAGE
  }
  const policyHelp = run(dir, "policy", "--help").toString();   // 1.17's exit-0 help: the policy family's own surface
  for (const spelling of ["policy adopt-defaults", "policy set --degradation fail-open | fail-closed"]) {
    assert.match(policyHelp, new RegExp(spelling.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), spelling);
  }
});
