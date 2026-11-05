// Standing workflow allowances (consolidation 2026-10-20; the rulings formerly baked into code
// by operator rulings 2026-10-07/08/11). The in-code skip classes died in the de-identity
// pass; their shapes re-emerged as entries in examples/user-policy.default.json. What is
// pinned HERE: the suggested-defaults entries lift these same shapes through the REAL consult
// (assessAction end to end, adopted store), and the band order still holds — Always-Deny
// shapes deny even with the defaults adopted, and near-misses the entries do not match keep
// the normal flow. All runs use an empty env (no backend): an unlifted call degrades instantly
// and offline, so allow-vs-ask/deny is decided by the entries alone.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { assessAction } from "../src/guard.js";
import { adoptDefaults, listEntries } from "../src/policy.js";

const EXAMPLE = join(dirname(fileURLToPath(import.meta.url)), "..", "examples", "user-policy.default.json");

// A home with the suggested defaults adopted (the operator's post-install step).
const home = mkdtempSync(join(tmpdir(), "unjangled-guardrails-workflow-"));
mkdirSync(home, { recursive: true });
const adopted = adoptDefaults({ GUARD_HOME: home, GUARD_OPERATOR_CLI: "1" });
// GUARD_CONFIG points at an absent scratch file: "no backend" must be explicit, not an
// accident of the operator's real config being missing (2026-10-22: restoring the brain
// config flipped these runs onto the live brain mid-suite). readConfig() honors it first.
const NO_CONFIG = { GUARD_CONFIG: join(home, "no-config-by-design.json") };
const bash = (command) => assessAction({ tool: "Bash", input: { command }, cwd: "/proj", sessionId: "s1" }, { env: { GUARD_HOME: home, GUARD_OPERATOR_CLI: "1", ...NO_CONFIG } });
const deadBrain = async () => { throw new Error("connect ECONNREFUSED 127.0.0.1:9"); };

test("the suggested defaults adopted: the workflow entry set is present", () => {
  assert.ok(adopted.added > 30, `expected the full suggested set, added ${adopted.added}`);
  assert.ok(listEntries({ GUARD_HOME: home }).some((e) => e.kind === "command" && e.pattern === "git push origin *"));
});

test("coordination plane entries pass the coordination tools (the paseo ruling, de-identified)", async () => {
  for (const tool of ["mcp__paseo__respond_to_permission", "mcp__paseo__browser_snapshot", "paseo_create_agent", "sendmessage", "ListAgents", "CronCreate"]) {
    const r = await assessAction({ tool, input: {}, cwd: "/proj" }, { env: { GUARD_HOME: home, ...NO_CONFIG }, fetchImpl: deadBrain });
    assert.equal(r.level, "allow", `${tool} rides the coordination entries (allow even degraded)`);
  }
  // other MCP servers are not the plane — no entry, degraded fail-open tells the truth
  const other = await assessAction({ tool: "mcp__playwright__browser_click", input: {}, cwd: "/proj" }, { env: { GUARD_HOME: home, ...NO_CONFIG }, fetchImpl: deadBrain });
  assert.equal(other.level, "allow");
  assert.equal(other.degraded, true);
  assert.match(other.why, /brain is unreachable/);
});

test("the coordination match is real: flipping the entry to deny DENIES a capitalized tool", async () => {
  // the allow rows above would pass vacuously through the fail-open posture — this row proves
  // the ENTRY matched: the same capitalized spelling under a deny entry denies even degraded
  // (effects are deterministic), and the case-insensitive match covers how Claude Code
  // delivers the names (TaskStop, CronCreate) against the documented pattern spelling.
  const denyHome = mkdtempSync(join(tmpdir(), "unjangled-guardrails-workflow-deny-"));
  mkdirSync(denyHome, { recursive: true });
  const { addToolEntry } = await import("../src/policy.js");
  for (const pattern of ["taskstop", "CronCreate", "ScheduleWakeup"]) {
    addToolEntry({ pattern, effect: "deny", reason: "prove-the-match" }, { GUARD_HOME: denyHome, GUARD_OPERATOR_CLI: "1" });
  }
  for (const [pattern, tool] of [["taskstop", "TaskStop"], ["CronCreate", "croncreate"], ["ScheduleWakeup", "schedulewakeup"]]) {
    const r = await assessAction({ tool, input: {}, cwd: "/proj" }, { env: { GUARD_HOME: denyHome, ...NO_CONFIG }, fetchImpl: deadBrain });
    assert.equal(r.level, "deny", `${tool} under the deny entry '${pattern}' must deny (the entry matched, case-insensitively)`);
    assert.match(r.why, /user lane: denied by operator rule/);
  }
});

test("workflow script entries lift the bookkeeping commands", async () => {
  assert.equal((await bash("uv run /home/u/ug/_bmad/scripts/resolve_config.py --project-root /home/u/ug --key core.output_folder")).level, "allow");
  assert.equal((await bash("python3 /home/u/.claude/skills/bmad-ticket/scripts/read_toml.py --file /x.toml -k tickets")).level, "allow");
  assert.equal((await bash("git add _bmad-output/initiative-v1/x.md && git commit -m 'feat: the plan record' _bmad-output/initiative-v1/x.md")).level, "allow");
});

test("everyday-git entries lift the mandated workflow shapes; force variants die at layer 1 first", async () => {
  assert.equal((await bash("git push")).level, "allow");
  assert.equal((await bash("git push origin main")).level, "allow");
  assert.equal((await bash("git status")).level, "allow");
  assert.equal((await bash("git add src/guard.js _bmad-output/a.md")).level, "allow");
  assert.equal((await bash("git checkout -b feature/x")).level, "allow");
  // publication-shaped danger never reaches the entries: Always-Deny denies first
  assert.equal((await bash("git push --force origin main")).level, "deny");
  assert.equal((await bash("git push origin +main")).level, "deny");
});

test("near-misses the entries do not match keep the normal flow (degraded: fail-open pass, no lift marker)", async () => {
  for (const cmd of ["git reset --hard HEAD~1", "git clean -fd", "git branch -D main", "git commit -a -m 'done'",
    "uv run /tmp/evil.py --project-root /home/u/ug"]) {
    const r = await bash(cmd);
    assert.notEqual(r.level, "deny", cmd);
    assert.ok(!r.ruling, `${cmd}: no entry consulted (no lift row in the audit)`);  // degraded pass, not an entry lift
  }
  // command substitution: no entry matches the segment shape
  const sub = await bash("git add _bmad-output/$(boom)");
  assert.ok(!sub.ruling, "command substitution does not ride the bookkeeping entry");
});

test("Always-Deny still gates the adopted install: the credential floor denies inside the normal flow", async () => {
  const r = await bash("cat /home/u/.ssh/id_ed25519");
  assert.equal(r.level, "deny");
});
