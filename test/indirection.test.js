// Context-body floor (epic-compound-recognition entry 5, CAP-3 reshaped by operator
// doctrine 2026-10-25): the bodies of executing command contexts run under the credential
// floor like any command — echo $(cat prod.env) keeps its doctrine deny. NOTHING here asks:
// the ask band is brain-only (the indirection escalator that previously lived in this file
// retired 2026-10-25, superseded-by-doctrine in docs/rules-retirement.md).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessAction } from "../src/guard.js";
import { commandContextBodies } from "../src/indirection.js";

test("a substitution-wrapped credential read takes the body-floor deny, never an ask", async () => {
  const r = await assessAction({ tool: "Bash", input: { command: "echo $(cat prod.env)" }, cwd: process.cwd() }, { env: {} });
  assert.equal(r.level, "deny");
  assert.notEqual(r.category, "Indirection Escalation", "the ask family is retired — no path produces it");
});

test("benign indirection goes to the brain and resolves there (no deterministic ask exists)", async () => {
  // this chain asked under the retired escalator; with an isolated store and no backend the
  // call degrades — allow or deny, never an ask, never the retired category
  const env = { GUARD_HOME: mkdtempSync(join(tmpdir(), "ind-")), SYSTEMONE_URL: "http://brain.test" };
  const r = await assessAction({ tool: "Bash", input: { command: "T=$(mktemp -d /tmp/x); echo $T" }, cwd: process.cwd() }, { env });
  assert.notEqual(r.category, "Indirection Escalation");
  assert.notEqual(r.level, "ask", "no deterministic path may produce an ask");
});

test("commandContextBodies extracts executing contexts, quote-aware", () => {
  assert.deepEqual(commandContextBodies('echo "$(cat a | b)"'), ["cat a | b"]);
  assert.deepEqual(commandContextBodies("echo `a; b`"), ["a; b"]);
  assert.deepEqual(commandContextBodies("x && (y; z)"), ["y; z"]);
  assert.deepEqual(commandContextBodies("grep -F '$(' f"), [], "single-quoted spans are literal text");
  assert.deepEqual(commandContextBodies('echo "it\'s $(date)"'), ["date"], "an apostrophe inside double quotes cannot hide a substitution");
});
