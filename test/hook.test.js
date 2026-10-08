// Entry 4 (TR-5, R3/M6): the red team's /tmp/opencode/dialect-tests.sh rebuilt as durable
// mock-brain tests — every hook dialect driven with a fake Jev, zero classifier calls.
// A risk-2.0 ask must return a blocking decision on every dialect without a prompt surface,
// keep prompting where a real prompt exists, and a leak-ask (Credential Exposure) must deny
// everywhere, Claude included.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleHook } from "../src/hook.js";
import { assessAction } from "../src/guard.js";
import { UnjangledGuardrails, UnjangledGuardrailsV2, getV2Context } from "../src/opencode.js";

const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-dialects-"));
const env = { JEV_API_KEY: "test", GUARD_HOME: dir };

const noul = (p) => ({ type: "noul", noul: p });
// One mock brain, two scenarios: the classic risk-2.0 ask (dialect-tests.sh A–E) and the
// leak-ask shape — low risk, high leaks_secrets — that used to ride the advisory ask path.
const mockBrain = ({ risk = 2.0, approval = 0.85, leak = 0.05 } = {}) => async () => ({ ok: true, json: async () => ({ answers: {
  risk: { type: "score", score: risk, probabilities: {}, confidence: 0.8 },
  approval: noul(approval), user_requested: noul(0.05), from_untrusted: noul(0.05),
  leaks_secrets: noul(leak), dumps_env_argv: noul(0.05), dumps_process_argv: noul(0.05), reads_credential_file: noul(0.05),
} }) });
const opts = (scenario = {}, extra = {}) => ({ env: { ...env }, fetchImpl: mockBrain(scenario), ...extra });

const PRE = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "make deploy" }, cwd: "/tmp/opencode/work", session_id: "dialects" };
const level = (out) => out?.hookSpecificOutput?.permissionDecision ?? out?.permissionDecision ?? out?.permission ?? out?.decision;

test("risk-2.0 ask: prompts where a prompt exists, blocks on every dialect without one", async () => {
  // Claude Code and pi enforce the ask band: still held for a real prompt
  assert.equal((await handleHook(PRE, opts())).hookSpecificOutput.permissionDecision, "ask");
  assert.equal(await handleHook({ ...PRE, hook_event_name: "PermissionRequest" }, opts()), null);
  // Cursor's shell/MCP permission hooks enforce ask too
  assert.equal((await handleHook({ hook_event_name: "beforeShellExecution", command: "make deploy", cwd: PRE.cwd, session_id: "dialects" }, opts())).permission, "ask");

  // Codex has no ask (0.154): deny with the ask-blocked message, routed to the user in conversation
  const codex = await handleHook({ ...PRE, turn_id: "t1", model: "gpt-5" }, opts());
  assert.equal(codex.hookSpecificOutput.permissionDecision, "deny");
  assert.match(codex.hookSpecificOutput.permissionDecisionReason, /denied by the Unjangled Guardrails classifier/);
  assert.match(codex.hookSpecificOutput.permissionDecisionReason, /no approval prompt/);
  assert.match(codex.hookSpecificOutput.permissionDecisionReason, /grant an operator ruling/);

  // Gemini BeforeTool has no ask and no prompt
  const gem = await handleHook({ hook_event_name: "BeforeTool", tool_name: "Bash", tool_input: PRE.tool_input, session_id: "dialects" }, opts());
  assert.equal(gem.decision, "deny");
  assert.match(gem.reason, /no approval prompt/);

  // Cursor preToolUse accepts ask but does not enforce it: deny instead
  const cursor = await handleHook({ hook_event_name: "preToolUse", tool_name: "Write", tool_input: { file_path: "/tmp/opencode/work/x", content: "hi" }, session_id: "dialects" }, opts());
  assert.equal(cursor.permission, "deny");
  assert.match(cursor.agent_message, /no approval prompt/);

  // Hermes: denies unless its plugin detected an approver (GUARD_HERMES_APPROVER)
  assert.equal(level(await handleHook(PRE, opts({}, { agent: "hermes" }))), "deny");
  assert.equal(level(await handleHook(PRE, opts({}, { agent: "hermes", env: { ...env, GUARD_HERMES_APPROVER: "1" } }))), "ask");
});

test("OpenCode: tool.execute.before throws on ask-band (the conversation loop is the prompt); permission.ask (inert on 1.18.31, kept for forward compat) still auto-allows safe calls", async () => {
  const savedFetch = globalThis.fetch, savedKey = process.env.JEV_API_KEY, savedHome = process.env.GUARD_HOME;
  globalThis.fetch = mockBrain(); process.env.JEV_API_KEY = "test"; process.env.GUARD_HOME = dir;
  try {
    const hooks = await UnjangledGuardrails({ client: {}, directory: "/tmp/opencode/work" });
    // ask-band throws with the ask message — the agent asks the user in conversation, the retry
    // passes on user_requested >= 0.85 (permission.ask is dead code on 1.18.31)
    await assert.rejects(hooks["tool.execute.before"]({ tool: "bash", sessionID: "oc" }, { args: { command: "make deploy" } }), /needs the user's approval/);
    // the forward-compat prompt surface still holds the call for a real prompt…
    const held = { status: "ask" };
    await hooks["permission.ask"]({ type: "bash", pattern: "make deploy", title: "make deploy", metadata: {}, sessionID: "oc" }, held);
    assert.equal(held.status, "ask");
    // …and still auto-approves the safe calls
    globalThis.fetch = mockBrain({ risk: 0.2, approval: 0.05 });
    const safe = { status: "ask" };
    await hooks["permission.ask"]({ type: "bash", pattern: "ls -la", title: "ls -la", metadata: {}, sessionID: "oc" }, safe);
    assert.equal(safe.status, "allow");
    // denies still throw from tool.execute.before
    globalThis.fetch = mockBrain({ risk: 2.9, approval: 0.99 });
    await assert.rejects(hooks["tool.execute.before"]({ tool: "bash", sessionID: "oc" }, { args: { command: "evil" } }), /denied/);
  } finally {
    globalThis.fetch = savedFetch;
    if (savedKey === undefined) delete process.env.JEV_API_KEY; else process.env.JEV_API_KEY = savedKey;
    if (savedHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedHome;
  }
});

test("UnjangledGuardrailsV2: default definition with id + setup (the form v2.0.24 loads, probe shape g); setup stores its context off the export shape and registers no hooks", async () => {
  // shape: an object with exactly id + setup — v2 rejects a default function ("Expected object")
  // and a default without id ("Missing key at [\"default\"][\"id\"]"); package-free, no imports.
  assert.equal(typeof UnjangledGuardrailsV2, "object");
  assert.ok(UnjangledGuardrailsV2 !== null && !Array.isArray(UnjangledGuardrailsV2));
  assert.deepEqual(Object.keys(UnjangledGuardrailsV2).sort(), ["id", "setup"]);
  assert.equal(typeof UnjangledGuardrailsV2.id, "string");
  assert.ok(UnjangledGuardrailsV2.id.length > 0);
  assert.equal(typeof UnjangledGuardrailsV2.setup, "function");
  // behavior: setup enters, stores the loader context OFF the exported shape (getV2Context), no-ops
  const ctx = { tool: { hook: () => assert.fail("skeleton must not register hooks") } };
  assert.equal(UnjangledGuardrailsV2.setup(ctx), undefined);
  assert.equal(getV2Context(), ctx);
  // shape invariant holds AFTER setup too: no third key ever appears on the export
  assert.deepEqual(Object.keys(UnjangledGuardrailsV2).sort(), ["id", "setup"]);
  // ponytail invariant holds at module level: no default export (the 1.x loader throws on object
  // exports; the v2 shim default-exports, never this module)
  const mod = await import("../src/opencode.js");
  assert.equal(mod.default, undefined);
});

test("leak-ask (Credential Exposure): denies on every dialect, Claude included", async () => {
  const leak = { risk: 0.5, approval: 0.05, leak: 0.9 };
  // pi rides the same assessAction path as Claude (extensions/unjangled-guardrails.ts)
  const claude = await assessAction({ tool: "Bash", input: { command: "printenv TOKEN" }, cwd: PRE.cwd, sessionId: "leak" }, { env, fetchImpl: mockBrain(leak) });
  assert.equal(claude.level, "deny");
  assert.equal(claude.category, "Credential Exposure");
  assert.match(claude.message, /\[Credential Exposure\]/);

  const cases = [
    ["codex", await handleHook({ ...PRE, tool_input: { command: "printenv TOKEN" }, turn_id: "t1", model: "gpt-5", session_id: "leak" }, opts(leak))],
    ["gemini", await handleHook({ hook_event_name: "BeforeTool", tool_name: "Bash", tool_input: { command: "printenv TOKEN" }, session_id: "leak" }, opts(leak))],
    ["cursor-shell", await handleHook({ hook_event_name: "beforeShellExecution", command: "printenv TOKEN", cwd: PRE.cwd, session_id: "leak" }, opts(leak))],
    ["cursor-preToolUse", await handleHook({ hook_event_name: "preToolUse", tool_name: "Bash", tool_input: { command: "cat /tmp/x" }, session_id: "leak" }, opts(leak))],
    ["hermes-no-approver", await handleHook(PRE, opts(leak, { agent: "hermes" }))],
  ];
  for (const [name, out] of cases) assert.equal(level(out), "deny", name);
});

// Back-compat (operator ruling 2026-10-07): the pre-rename JEV_GUARD_* spelling still works.

test("back-compat: JEV_GUARD_HERMES_APPROVER still defers Hermes asks to its approver", async () => {
  assert.equal(level(await handleHook(PRE, opts({}, { agent: "hermes", env: { ...env, JEV_GUARD_HERMES_APPROVER: "1" } }))), "ask");
});
