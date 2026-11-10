// Story 5 (CAP-4/R-5): capture visibility. The two store-entry list surfaces mark
// prompt-captured rulings by their provenance (the via field prompt:<harness> already lands
// on the rows — story 1), and the capture tier GUARD_PROMPT_RULINGS surfaces where the
// other knobs surface (the policy list status head, beside degradation). Provenance is
// minted through the REAL capturePromptRuling (the only constructor of a prompt: via);
// rendering is the spawned CLI child's stdout — the rendering is the story.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { addRuling, capturePromptRuling } from "../src/rulings.js";

const REPO = new URL("..", import.meta.url).pathname;
const home = () => mkdtempSync(join(tmpdir(), "unjangled-guardrails-visibility-"));

// The list child: hermetic HOME + GUARD_HOME. Deliberately NO tier env — the provenance
// marker is a property of the entry, not of the current tier (a capture minted under
// tier=session stays marked after the tier is turned back off).
const list = (dir, args, extraEnv = {}) =>
  execFileSync(process.execPath, ["src/cli.js", ...args], {
    cwd: REPO, encoding: "utf8",
    env: { PATH: process.env.PATH, HOME: dir, GUARD_HOME: dir, ...extraEnv },
  });

// One fixture with every mint shape: session-tier session capture, project-tier always
// capture, project-tier session capture, and an operator-minted row that must stay bare.
function seedEveryShape(dir) {
  const pi = capturePromptRuling(
    { choice: "session", harness: "pi", sessionId: "sess-A", tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj" },
    { env: { JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_PROMPT_RULINGS: "session" } });
  const acpAlways = capturePromptRuling(
    { choice: "always", harness: "acp", sessionId: "sess-A", tool: "Bash", input: { command: "make deploy" }, cwd: "/proj" },
    { env: { JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_PROMPT_RULINGS: "project" } });
  const acpSession = capturePromptRuling(
    { choice: "session", harness: "acp", sessionId: "sess-B", tool: "Bash", input: { command: "make check" }, cwd: "/proj" },
    { env: { JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_PROMPT_RULINGS: "project" } });
  const operator = addRuling(
    { effect: "allow", pattern: "terraform apply", scope: "project:/proj", reason: "reviewed" },
    { JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" });
  assert.equal(pi.captured && acpAlways.captured && acpSession.captured, true, "the captures minted");
  return { pi, acpAlways, acpSession, operator };
}

const lineFor = (out, id) => {
  const l = out.split("\n").find((x) => x.startsWith(`${id}  `));
  assert.ok(l, `a list line for ${id} exists in:\n${out}`);
  return l;
};

test("ruling list marks prompt captures with their (prompt:<harness>) tag; operator rows stay unmarked", () => {
  const dir = home();
  const { pi, acpAlways, acpSession, operator } = seedEveryShape(dir);
  const out = list(dir, ["ruling", "list"]);

  // every mint shape is marked, the tag is the via value verbatim at end of line
  assert.match(lineFor(out, pi.ruling.id), /\(prompt:pi\)$/);
  assert.match(lineFor(out, acpAlways.ruling.id), /\(prompt:acp\)$/);
  assert.match(lineFor(out, acpSession.ruling.id), /\(prompt:acp\)$/);

  // the marker follows the existing line grammar: scope/expires fields still render
  assert.match(lineFor(out, pi.ruling.id), /scope=session:sess-A/);
  assert.match(lineFor(out, acpAlways.ruling.id), /scope=project:\/proj/);

  // the operator-minted row carries no marker and keeps its reason continuation
  const opLine = lineFor(out, operator.id);
  assert.doesNotMatch(opLine, /prompt:/);
  assert.match(out, /reason: reviewed/);

  // no marker leaks onto any other line
  assert.equal(out.split("\n").filter((l) => /\(prompt:/.test(l)).length, 3);
});

test("each harness spelling renders its own tag — the tag is the stored via, verbatim", () => {
  const dir = home();
  const mint = (harness, command) => capturePromptRuling(
    { choice: "session", harness, sessionId: `s-${harness}`, tool: "Bash", input: { command } },
    { env: { JEV_API_KEY: "test", GUARD_HOME: dir, GUARD_PROMPT_RULINGS: "session" } });
  for (const h of ["pi", "acp", "claude", "gemini"]) {
    const r = mint(h, `git push origin ${h}`);
    assert.equal(r.captured, true);
  }
  const out = list(dir, ["ruling", "list"]);
  for (const h of ["pi", "acp", "claude", "gemini"])
    assert.match(out, new RegExp(`\\(prompt:${h}\\)$`, "m"), `the ${h} spelling renders verbatim`);
});

test("policy list marks the same provenance on its command-entry lines; the operator row stays bare", () => {
  const dir = home();
  const { pi, acpAlways, operator } = seedEveryShape(dir);
  const out = list(dir, ["policy", "list"]);
  assert.match(lineFor(out, pi.ruling.id), /\(prompt:pi\)$/);
  assert.match(lineFor(out, acpAlways.ruling.id), /\(prompt:acp\)$/);
  assert.doesNotMatch(lineFor(out, operator.id), /prompt:/);
});

test("policy list surfaces the capture tier beside the degradation knob — every tier value incl. the off default and an unknown fail-safe", () => {
  const dir = home();
  const out = (tierEnv) => list(dir, ["policy", "list"], tierEnv).split("\n").find((l) => l.startsWith("prompt-capture:"));
  // unset: the off default still SHOWS (visibility is the point — an absent line says nothing)
  assert.equal(out({}), "prompt-capture: off", "the unset tier reads off");
  assert.equal(out({ GUARD_PROMPT_RULINGS: "session" }), "prompt-capture: session");
  assert.equal(out({ GUARD_PROMPT_RULINGS: "project" }), "prompt-capture: project");
  // unknown values fail safe to off — the line shows what the mint honors, never a state the core refuses
  assert.equal(out({ GUARD_PROMPT_RULINGS: "bogus" }), "prompt-capture: off");
  assert.equal(out({ GUARD_PROMPT_RULINGS: "SESSION" }), "prompt-capture: session", "the parse lowercases — the effective tier is what shows");

  // the tier line prints on an empty store too, and the knob order is degradation then tier
  const empty = home();
  const emptyOut = list(empty, ["policy", "list"]);
  assert.match(emptyOut, /^prompt-capture: off$/m, "empty policy still shows the tier");
  assert.match(emptyOut, /policy is empty/);
});

test("ruling list carries no tier line — the knob surfaces once, in the policy status head", () => {
  const dir = home();
  seedEveryShape(dir);
  assert.doesNotMatch(list(dir, ["ruling", "list"], { GUARD_PROMPT_RULINGS: "session" }), /prompt-capture:/);
});
