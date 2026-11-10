// Runnable unblock suggestions (CAP-7, epic-github-field-reports entry 4 / GitHub issue 4):
// the ask-band hint must run as printed in an operator terminal and create a generalized
// entry in the store the gate consults. The report's five defects, one pin each: (1) the
// pattern was the entire literal command — single-use; (2) the scope pointed at the harness
// home (fixed upstream by entry 6's callWorkdir; pinned here); (3) the command named a bare
// binary clone installs do not have; (4) the subcommand was the retired `ruling` alias; (5)
// no destination store was named, so the paste wrote a store nothing reads (the issue-5
// split). The acceptance bar is the doctrine's own: paste the suggestion (spawned CLI, the
// operator escape standing in for the terminal TTY), it succeeds, and the following matching
// call passes — the identical call AND a variant, proving the entry generalized. Conventions
// follow rulings.test.js / workdir-scope.test.js: temp GUARD_HOME, the fake brain behind the
// keyless local-backend env shape, hermetic HOME for every spawned child.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { assessAction, askBlockedDeny, rulingHintFor } from "../src/guard.js";
import { matches, capturePromptRuling } from "../src/rulings.js";
import { policyFile } from "../src/policy.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const CLI_ENTRY = join(REPO, "src", "cli.js");

// Same fake brain as workdir-scope.test.js: rm -rf → deny, git push/git commit → ask (the
// reporter's held shapes — that is why the entries existed), everything else → allow.
// Served behind the keyless local-backend env shape (SYSTEMONE_URL selects it; fetchImpl
// intercepts, nothing reaches the network).
async function fetchImpl(_url, { body }) {
  const { state } = JSON.parse(body);
  const cmd = JSON.stringify(state.input);
  const score = /rm -rf|DROP TABLE/.test(cmd) ? 2.9 : /git push|git commit|curl -X POST/.test(cmd) ? 2.0 : 0.2;
  const answers = {
    risk: { type: "score", score, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: score >= 2 ? 0.85 : 0.05 },
    user_requested: { type: "noul", noul: 0.05 },
    from_untrusted: { type: "noul", noul: 0.05 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
  };
  return { ok: true, json: async () => ({ answers }) };
}

const home = () => mkdtempSync(join(tmpdir(), "unjangled-guardrails-unblock-"));
const gateEnv = (dir) => ({ SYSTEMONE_URL: "http://127.0.0.1:9", GUARD_HOME: dir });
const captureEnv = (dir) => ({ SYSTEMONE_URL: "http://127.0.0.1:9", GUARD_HOME: dir, GUARD_PROMPT_RULINGS: "session" });
const opts = (dir) => ({ env: gateEnv(dir), fetchImpl });

// The hint's command lines (everything except the trailing store comment).
const hintLines = (hint) => String(hint).split("\n").filter((l) => !l.startsWith("#"));
// The --pattern value of one hint line.
const patternOf = (line) => {
  const m = line.match(/--pattern '(.*)' --scope/);
  assert.ok(m, `not a hint line: ${line}`);
  return m[1];
};

// ── the five defects, pinned in one line ──────────────────────────────────────────────────────

test("the hint line carries the current command, the real invocation, the right store, and a generalized pattern", () => {
  const H = home();
  const hint = rulingHintFor({ tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj", env: gateEnv(H) });
  const [line, comment] = String(hint).split("\n");
  // the whole line, byte-exact — defects 3 (node entry, never a bare binary), 4 (policy add,
  // never the alias), 5 (GUARD_HOME prefix), 1 (the generalized pattern), 2 (the cwd scope)
  assert.equal(line,
    `GUARD_HOME='${H}' node '${CLI_ENTRY}' policy add --effect allow --pattern 'git push *' --scope 'project:/proj' --reason 'operator unblock'`);
  // defect 5's second half: the exact policy file the pasted rule lands in, by name
  assert.equal(comment, `# policy store: ${policyFile(gateEnv(H))}`);
  assert.equal(policyFile(gateEnv(H)), join(H, "user-policy.json"));
  // the retired shapes appear nowhere (defects 3 and 4, negatively)
  assert.ok(!hint.includes("unjangled-guardrails ruling add"), `the bare-binary alias shape must be gone: ${hint}`);
  assert.ok(!hint.startsWith("unjangled-guardrails"), `never a bare binary name: ${hint}`);
});

// ── the pattern generalization: the docs' verb-plus-wildcard shape ────────────────────────────

test("patterns generalize: verb + subcommand + flag run pinned, the variable tail wildcarded", () => {
  const H = home();
  const cases = [
    ["git push origin release", "git push *"],           // docs' own family: verb+sub, refspec wildcarded
    ["git add src/a.js src/b.js", "git add *"],           // every path dropped (the report's words)
    ["git commit -m 'ship it'", "git commit -m *"],       // the house default's own shape; the old hard-refuse
    ["git checkout -b rescue", "git checkout -b *"],      // the -b pin: bare checkout stays outside
    ["rm -rf build/x", "rm -rf *"],                       // flag-as-subcommand slot, path wildcarded
    ["make clean", "make clean"],                          // fully concrete: exact IS the generalization
    ["terraform apply -auto-approve", "terraform apply -auto-approve"],  // flag run consumed whole: no tail, no wildcard
  ];
  for (const [command, pattern] of cases) {
    const hint = rulingHintFor({ tool: "Bash", input: { command }, cwd: "/proj", env: gateEnv(H) });
    assert.equal(patternOf(hintLines(hint)[0]), pattern, command);
    // the replay bar: the entry always re-covers the very call that asked (the wildcard only
    // appears when a tail exists to match it)
    assert.equal(matches({ effect: "allow", pattern, scope: "project:/proj" }, { tool: "Bash", preview: [command], cwd: "/proj" }),
      true, `pattern must match its own segment: ${pattern} vs ${command}`);
  }
  // generalized, not single-use: variants of the same shape lift too
  for (const [pattern, variant] of [
    ["git push *", "git push origin release-2"],
    ["git add *", "git add -- src/other.z"],
    ["git commit -m *", "git commit -m 'another message'"],
  ])
    assert.equal(matches({ effect: "allow", pattern, scope: "project:/proj" }, { tool: "Bash", preview: [variant], cwd: "/proj" }),
      true, `variant must match the generalized pattern: ${pattern} vs ${variant}`);
  // the space before the star is load-bearing: the entry never catches other subcommands
  for (const [pattern, nonmatch] of [
    ["git push *", "git status"],
    ["git push *", "git pushx origin main"],
    ["git checkout -b *", "git checkout main"],
  ])
    assert.equal(matches({ effect: "allow", pattern, scope: "project:/proj" }, { tool: "Bash", preview: [nonmatch], cwd: "/proj" }),
      false, `must not over-match: ${pattern} vs ${nonmatch}`);
});

test("one line per segment, each generalizing its own segment (the 7.4 discipline, kept)", () => {
  const H = home();
  const hint = rulingHintFor({ tool: "Bash", input: { command: "git push origin release; git checkout -b rescue" }, cwd: "/proj", env: gateEnv(H) });
  const lines = hintLines(hint);
  assert.equal(lines.length, 2);
  assert.equal(patternOf(lines[0]), "git push *");
  assert.equal(patternOf(lines[1]), "git checkout -b *");
  assert.ok(String(hint).endsWith(`\n# policy store: ${policyFile(gateEnv(H))}`), "one store comment, after every line");
});

// ── defect 2's pin: the scope is the resolved call workdir, never the harness home ────────────

test("the suggested scope is the call's workdir (entry 6's resolution), never the harness home", async () => {
  const H = home();
  // through assessAction — callWorkdir is applied at its entry (the 1.6 single site), and
  // the hint inherits the resolved folder; a raw rulingHintFor call receives it already resolved
  const r = await assessAction({ tool: "Bash", input: { command: "git push origin release", workdir: "/users/reporter/projects/repo" }, cwd: "/users/reporter/.hermes" }, opts(H));
  assert.equal(r.level, "ask");
  assert.ok(r.rulingHint.includes(`--scope 'project:/users/reporter/projects/repo'`), `hint names the resolved project: ${r.rulingHint}`);
  assert.ok(!r.rulingHint.includes("/users/reporter/.hermes"), "the harness home is never the suggested scope");
});

// ── the refusals: "" — never a suggestion that would fail or over-match ───────────────────────

test("refusals: too compound, kept-token quote or glob, non-bash, no cwd, empty, broken interpolation", () => {
  const H = home();
  const e = gateEnv(H);
  const refuse = (call) => assert.equal(rulingHintFor({ ...call, env: e }), "", JSON.stringify(call));
  refuse({ tool: "Bash", input: { command: "a && b && c && d" }, cwd: "/proj" });        // >3 segments
  refuse({ tool: "Bash", input: { command: "echo 'hi'" }, cwd: "/proj" });                // quote in a KEPT token
  refuse({ tool: "Bash", input: { command: "ls build?" }, cwd: "/proj" });                // glob in a KEPT token
  refuse({ tool: "Write", input: { file_path: "/proj/x", content: "y" }, cwd: "/proj" }); // not bash-shaped
  refuse({ tool: "Bash", input: { command: "git push origin release" } });                 // no cwd
  refuse({ tool: "Bash", input: { command: "" }, cwd: "/proj" });                          // empty command
  // a single-quote in an interpolated path would break the pasted shell form — refuse
  assert.equal(rulingHintFor({ tool: "Bash", input: { command: "git push origin release" }, cwd: "/it's/proj", env: e }), "");
  // quotes in the wildcarded TAIL no longer refuse — that is the generalization working
  assert.notEqual(rulingHintFor({ tool: "Bash", input: { command: "git commit -m 'ship it'" }, cwd: "/proj", env: e }), "");
});

// ── the ask surfaces carry the rebuilt hint ───────────────────────────────────────────────────

test("an ask carries the rebuilt hint in message and rulingHint; askBlockedDeny preserves it", async () => {
  const H = home();
  const r = await assessAction({ tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj" }, opts(H));
  assert.equal(r.level, "ask");
  assert.equal(r.rulingHint,
    `GUARD_HOME='${H}' node '${CLI_ENTRY}' policy add --effect allow --pattern 'git push *' --scope 'project:/proj' --reason 'operator unblock'` +
    `\n# policy store: ${policyFile(gateEnv(H))}`);
  assert.ok(r.message.includes(
    "Operator unblock (run in your own terminal, not here — the gate blocks agent-run ruling changes):\n" +
    `GUARD_HOME='${H}' node '${CLI_ENTRY}' policy add`), r.message);
  const blocked = askBlockedDeny(r);
  assert.equal(blocked.level, "deny");
  assert.ok(blocked.message.includes(`# policy store: ${policyFile(gateEnv(H))}`), "the conversion carries the store comment");
});

// ── CAP-7's own bar: paste the suggestion, it succeeds, the following matching call passes ────

test("paste-runnability: the suggested command runs as printed and the following matching call passes", async () => {
  const H = home();
  const ask = await assessAction({ tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj" }, opts(H));
  assert.equal(ask.level, "ask");
  const line = hintLines(ask.rulingHint)[0];
  // the operator terminal: GUARD_OPERATOR_CLI=1 stands in for the TTY; the line's own
  // GUARD_HOME prefix steers the paste into the gate's store; HOME hermetic so the CLI's
  // harness-registry read stays empty (no divergence noise, a real store landing)
  const out = execFileSync("/bin/sh", ["-c", line], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, HOME: H, GUARD_OPERATOR_CLI: "1" },
  });
  // the paste succeeded and the CLI's own store footer names the file the comment promised
  assert.ok(out.includes(`policy store: ${policyFile(gateEnv(H))}`), `the CLI footer names the store: ${out}`);
  // the entry landed in the RIGHT store, generalized, scoped to the call's folder
  const store = JSON.parse(readFileSync(policyFile(gateEnv(H)), "utf8"));
  assert.equal(store.entries.length, 1);
  assert.equal(store.entries[0].kind, "command");
  assert.equal(store.entries[0].effect, "allow");
  assert.equal(store.entries[0].pattern, "git push *");
  assert.equal(store.entries[0].scope, "project:/proj");
  // the following matching call passes: the IDENTICAL call lifts, citing the pasted entry
  const replay = await assessAction({ tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj" }, opts(H));
  assert.equal(replay.level, "allow");
  assert.equal(replay.ruling, store.entries[0].id);
  // and a VARIANT of the same shape lifts too — generalized, not single-use
  const variant = await assessAction({ tool: "Bash", input: { command: "git push origin release-2" }, cwd: "/proj" }, opts(H));
  assert.equal(variant.level, "allow");
  assert.equal(variant.ruling, store.entries[0].id);
});

test("paste-runnability, the whole multi-line block: every line runs, the comment is shell-safe", async () => {
  const H = home();
  const ask = await assessAction({ tool: "Bash", input: { command: "git push origin release; git checkout -b rescue" }, cwd: "/proj" }, opts(H));
  assert.equal(ask.level, "ask");
  // the ENTIRE hint text — commands and the trailing comment — pasted as one block
  execFileSync("/bin/sh", ["-c", ask.rulingHint], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, HOME: H, GUARD_OPERATOR_CLI: "1" },
  });
  const store = JSON.parse(readFileSync(policyFile(gateEnv(H)), "utf8"));
  assert.deepEqual(store.entries.map((e) => e.pattern).sort(), ["git checkout -b *", "git push *"]);
  // one segment's entry never lifts the whole compound (TR-4) — each stage is separately covered
  const stage2 = await assessAction({ tool: "Bash", input: { command: "git checkout -b rescue2" }, cwd: "/proj" }, opts(H));
  assert.equal(stage2.level, "allow", "the second stage's own entry covers its own segment");
});

// ── the deliberate divergence: the prompt-capture mint stays exact ────────────────────────────

test("the capture mint stays exact-segment while the hint generalizes — the divergence is pinned", () => {
  const H = home();
  const cap = capturePromptRuling(
    { choice: "session", harness: "pi", sessionId: "s-4", tool: "Bash", input: { command: "git push origin release" }, cwd: "/proj" },
    { env: captureEnv(H) });
  assert.equal(cap.captured, true);
  assert.equal(cap.ruling.pattern, "git push origin release", "the mint is the EXACT segment — never the hint's generalized shape");
  assert.notEqual(cap.ruling.pattern, "git push *");
});
