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
import { sessionRead } from "../src/contract.js";
import { UnjangledGuardrails, UnjangledGuardrailsV2, getV2Context } from "../src/opencode.js";

const dir = mkdtempSync(join(tmpdir(), "unjangled-guardrails-dialects-"));
const env = { JEV_API_KEY: "test", GUARD_HOME: dir };
// hermetic scan/store root for the V2 setup call sites that set no env of their own: the
// coexistence scan (epic-host-isolation ticket 2) bases the plugin dirs on
// GUARD_HOME ?? homedir(), so without this those setups would walk the operator's real
// plugin dirs; tests that point GUARD_HOME elsewhere overwrite and restore this value
process.env.GUARD_HOME = join(dir, "guard-home");

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
  assert.match(codex.hookSpecificOutput.permissionDecisionReason, /grant a policy rule from their own terminal/);

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
    // passes on user_requested >= 0.75 (permission.ask is dead code on 1.18.31)
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

test("UnjangledGuardrailsV2: default definition with id + setup (the form v2.0.24 loads, probe shape g); setup registers the execute.before gating hook, the permission.evaluate ask-band hook (ticket 4), and stores its context off the export shape", async () => {
  // shape: an object with exactly id + setup — v2 rejects a default function ("Expected object")
  // and a default without id ("Missing key at [\"default\"][\"id\"]"); package-free, no imports.
  assert.equal(typeof UnjangledGuardrailsV2, "object");
  assert.ok(UnjangledGuardrailsV2 !== null && !Array.isArray(UnjangledGuardrailsV2));
  assert.deepEqual(Object.keys(UnjangledGuardrailsV2).sort(), ["id", "setup"]);
  assert.equal(typeof UnjangledGuardrailsV2.id, "string");
  assert.ok(UnjangledGuardrailsV2.id.length > 0);
  assert.equal(typeof UnjangledGuardrailsV2.setup, "function");
  // behavior: setup enters, stores the loader context OFF the exported shape (getV2Context),
  // and registers the tool hooks: the registered hook list gains execute.before (ticket 2)
  // and execute.after (ticket 3); the permission domain gains evaluate (ticket 4)
  const registered = {};
  const permRegistered = {};
  const ctx = { tool: { hook: (name, fn) => { registered[name] = fn; } }, permission: { hook: (name, fn) => { permRegistered[name] = fn; } } };
  assert.equal(UnjangledGuardrailsV2.setup(ctx), undefined);
  assert.equal(getV2Context(), ctx);
  assert.deepEqual(Object.keys(registered).sort(), ["execute.after", "execute.before"]);
  assert.deepEqual(Object.keys(permRegistered), ["evaluate"]);
  assert.equal(typeof permRegistered["evaluate"], "function");
  // shape invariant holds AFTER setup too: no third key ever appears on the export
  assert.deepEqual(Object.keys(UnjangledGuardrailsV2).sort(), ["id", "setup"]);
  // ponytail invariant holds at module level: no default export (the 1.x loader throws on object
  // exports; the v2 adapter default-exports, never this module)
  const mod = await import("../src/opencode.js");
  assert.equal(mod.default, undefined);
});

test("UnjangledGuardrailsV2 execute.before: deny throws with the contract message, allow returns, ask returns undefined without throwing (defers to permission.evaluate, ticket 4)", async () => {
  const savedFetch = globalThis.fetch, savedKey = process.env.JEV_API_KEY, savedHome = process.env.GUARD_HOME;
  globalThis.fetch = mockBrain({ risk: 2.9, approval: 0.99 }); process.env.JEV_API_KEY = "test"; process.env.GUARD_HOME = dir;
  try {
    const registered = {};
    UnjangledGuardrailsV2.setup({ tool: { hook: (name, fn) => { registered[name] = fn; } }, permission: { hook: () => {} }, location: { directory: "/tmp/opencode/work" } });
    const before = registered["execute.before"];
    // deny vetoes by throwing — the r1 mechanism — and the contract message rides the throw
    await assert.rejects(before({ tool: "shell", sessionID: "oc-v2", input: { command: "evil" } }), /denied/);
    // the calls bucket records every verdict as v1 does, deny included
    assert.ok(sessionRead("oc-v2").calls.some((c) => c.level === "deny" && c.tool === "shell" && /evil/.test(c.preview)));
    // allow passes: undefined return, no throw, recorded
    globalThis.fetch = mockBrain({ risk: 0.2, approval: 0.05 });
    // `ls -la /etc` and not bare `ls -la`: the unconfined operand keeps it off the temp lane
    // (operator ruling 2026-10-11) so the allow verdict is actually produced and recorded
    assert.equal(await before({ tool: "shell", sessionID: "oc-v2", input: { command: "ls -la /etc" } }), undefined);
    assert.ok(sessionRead("oc-v2").calls.some((c) => c.level === "allow" && /ls -la/.test(c.preview)));
    // ask DEFERS: returns undefined WITHOUT throwing — unlike v1 (whose conversation loop was
    // the prompt), v2's untouched ask falls through to permission.evaluate (ticket 4's hook)
    globalThis.fetch = mockBrain();  // risk 2.0 rides the ask band
    assert.equal(await before({ tool: "shell", sessionID: "oc-v2", input: { command: "make deploy" } }), undefined);
    assert.ok(sessionRead("oc-v2").calls.some((c) => c.level === "ask" && /make deploy/.test(c.preview)));
  } finally {
    globalThis.fetch = savedFetch;
    if (savedKey === undefined) delete process.env.JEV_API_KEY; else process.env.JEV_API_KEY = savedKey;
    if (savedHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedHome;
  }
});

test("UnjangledGuardrailsV2 permission.evaluate (ticket 4): safe rewrites effect to allow (the r7 rewrite), ask and deny leave the effect untouched, brain-down answers through the degraded floor, and every verdict lands in the calls bucket", async () => {
  const savedFetch = globalThis.fetch, savedKey = process.env.JEV_API_KEY, savedHome = process.env.GUARD_HOME, savedSessions = process.env.GUARD_SESSIONS;
  process.env.JEV_API_KEY = "test"; process.env.GUARD_HOME = dir; process.env.GUARD_SESSIONS = join(dir, "sessions-perm");
  try {
    const permRegistered = {};
    UnjangledGuardrailsV2.setup({
      tool: { hook: () => {} },
      permission: { hook: (name, fn) => { permRegistered[name] = fn; } },
      location: { directory: "/tmp/opencode/work" },
    });
    const evaluate = permRegistered["evaluate"];
    assert.equal(typeof evaluate, "function");

    // safe under an ask rule: the callback rewrites effect to allow — the rewrite the probe
    // proved v2 honors end-to-end (r7: the ask-rule call ran)
    globalThis.fetch = mockBrain({ risk: 0.2, approval: 0.05 });
    const safe = { action: "shell", resources: ["sort /tmp/opencode/work/notes.txt"], effect: "ask", sessionID: "oc-v2-perm" };
    await evaluate(safe);
    assert.equal(safe.effect, "allow");
    assert.ok(sessionRead("oc-v2-perm").calls.some((c) => c.level === "allow" && /notes\.txt/.test(c.preview)));

    // an unconfigured safe call (the base policy's allow, spike r0) stays allow
    const plain = { action: "shell", resources: ["wc -l /tmp/opencode/work/notes.txt"], effect: "allow", sessionID: "oc-v2-perm" };
    await evaluate(plain);
    assert.equal(plain.effect, "allow");

    // ask: untouched — v2's native permission flow owns the prompt (a bare run auto-rejects
    // an untouched ask, r8; the real prompt surface is the ACP client), and the callback
    // mutates nothing else on the event
    globalThis.fetch = mockBrain();  // risk 2.0 rides the ask band
    const risky = { action: "shell", resources: ["make deploy"], effect: "ask", sessionID: "oc-v2-perm" };
    await evaluate(risky);
    assert.equal(risky.effect, "ask");
    assert.deepEqual(Object.keys(risky).sort(), ["action", "effect", "resources", "sessionID"]);
    assert.ok(sessionRead("oc-v2-perm").calls.some((c) => c.level === "ask" && /make deploy/.test(c.preview)));

    // wildcard/empty resources (the MCP shape, probe m1): nothing is judged — the incoming
    // effect is untouched (a configured ask on an MCP tool still prompts), no brain call,
    // no record. Closes the closure-check gap on the wildcard branch.
    globalThis.fetch = () => { throw new Error("wildcard must not reach the brain"); };
    const mcp = { action: "ogprobe_ogping", resources: ["*"], effect: "ask", sessionID: "oc-v2-perm" };
    await evaluate(mcp);
    assert.equal(mcp.effect, "ask");
    assert.ok(sessionRead("oc-v2-perm").calls.every((c) => !/ogping/.test(c.preview)), "wildcard call recorded nothing");

    // contract deny: untouched too — the before-hook owns the veto (r1), a configured deny
    // never reaches this callback at all (r6), so the callback's deny band is pure
    // pass-through: it never relaxes, rewrites, or annotates a deny
    globalThis.fetch = mockBrain({ risk: 2.9, approval: 0.99 });
    const denied = { action: "shell", resources: ["evil"], effect: "allow", sessionID: "oc-v2-perm" };
    await evaluate(denied);
    assert.equal(denied.effect, "allow");
    assert.ok(sessionRead("oc-v2-perm").calls.some((c) => c.level === "deny" && /evil/.test(c.preview)));

    // ordinary doc write: the standing-allow skip class died in the consolidation — the write
    // pays the brain, takes its real allow verdict, and IS recorded (no silent null class
    // remains but GUARD_SKIP_TOOLS)
    globalThis.fetch = mockBrain({ risk: 0.2, approval: 0.05 });
    const doc = { action: "write", resources: ["/tmp/opencode/work/NOTES.md"], effect: "ask", sessionID: "oc-v2-perm" };
    await evaluate(doc);
    assert.equal(doc.effect, "allow");
    assert.ok(sessionRead("oc-v2-perm").calls.some((c) => c.level === "allow" && /NOTES\.md/.test(c.preview)), "the brain judged the write and the verdict is on the record");

    // brain down: the degraded floor answers (it does not throw), so an ask-rule call the
    // offline rules pass rewrites to allow with the degraded verdict recorded — the same
    // posture the before-hook shows brain-down
    globalThis.fetch = async () => { throw new Error("brain down"); };
    const down = { action: "shell", resources: ["sort /tmp/opencode/work/other.txt"], effect: "ask", sessionID: "oc-v2-perm-down" };
    await evaluate(down);
    assert.equal(down.effect, "allow");
    const downCall = sessionRead("oc-v2-perm-down").calls.at(-1);
    assert.equal(downCall.level, "allow");
    assert.match(downCall.preview, /other\.txt/);
  } finally {
    globalThis.fetch = savedFetch;
    if (savedKey === undefined) delete process.env.JEV_API_KEY; else process.env.JEV_API_KEY = savedKey;
    if (savedHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedHome;
    if (savedSessions === undefined) delete process.env.GUARD_SESSIONS; else process.env.GUARD_SESSIONS = savedSessions;
  }
});

test("UnjangledGuardrailsV2 permission.evaluate lane pin, consolidated: a bash-plane call under the operator's bash:ask rule is rewritten allow by a CONFIG entry lifting the brain's ask — the entry, not a skip class, decides it", async () => {
  // The consolidation port of the old safe-lane pin: the deterministic lanes died, and the
  // standing allowance re-emerged as a policy entry (the CONFIG layer). The brain is always
  // consulted now (literal brain-through); the entry lifts the ask band afterwards, so the
  // operator's bash:ask rule (the installer note's `permission: { "bash": "ask" }`) still does
  // not prompt for the shapes the entry covers — and shapes it does not cover prompt again.
  const savedFetch = globalThis.fetch, savedKey = process.env.JEV_API_KEY, savedHome = process.env.GUARD_HOME, savedSessions = process.env.GUARD_SESSIONS;
  process.env.JEV_API_KEY = "test"; process.env.GUARD_HOME = dir; process.env.GUARD_SESSIONS = join(dir, "sessions-lane");
  try {
    const permRegistered = {};
    UnjangledGuardrailsV2.setup({
      tool: { hook: () => {} },
      permission: { hook: (name, fn) => { permRegistered[name] = fn; } },
      location: { directory: "/tmp/opencode/work" },
    });
    const evaluate = permRegistered["evaluate"];
    // the standing allowance: a seeded command entry (the operator's `policy add` product)
    const { addCommandEntry } = await import("../src/policy.js");
    addCommandEntry({ effect: "allow", pattern: "git add *", scope: "global" }, { GUARD_HOME: dir, GUARD_OPERATOR_CLI: "1" });
    // the brain scores the git add into the ASK band: without the entry the ask would stand
    globalThis.fetch = mockBrain({ risk: 2.0, approval: 0.85 });

    // everyday git (explicit relative pathspec — the AGENTS.md atomic-commit plane)
    const laneGit = { action: "bash", resources: ["git add src/notes.md"], effect: "ask", sessionID: "oc-v2-lane" };
    assert.equal(laneGit.effect, "ask");  // the operator's bash:ask config, before the callback
    await evaluate(laneGit);
    assert.equal(laneGit.effect, "allow");  // the entry lifted the brain's ask: no prompt surfaces
    const laneCall = sessionRead("oc-v2-lane").calls.at(-1);
    assert.equal(laneCall.level, "allow", "the brain judged, the entry lifted — the lifted verdict is on the record");
    assert.deepEqual(Object.keys(laneGit).sort(), ["action", "effect", "resources", "sessionID"]);  // only effect was touched

    // a shape NO entry covers: the ask stands and prompts (the honest literal-brain-through cost)
    const uncovered = { action: "bash", resources: ["echo build done > /tmp/work/out.txt"], effect: "ask", sessionID: "oc-v2-lane-echo" };
    await evaluate(uncovered);
    assert.equal(uncovered.effect, "ask", "an uncovered shape keeps the prompt the operator configured");
    assert.ok(sessionRead("oc-v2-lane-echo").calls.some((c) => c.level === "ask"));
    assert.deepEqual(Object.keys(uncovered).sort(), ["action", "effect", "resources", "sessionID"]);
  } finally {
    globalThis.fetch = savedFetch;
    if (savedKey === undefined) delete process.env.JEV_API_KEY; else process.env.JEV_API_KEY = savedKey;
    if (savedHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedHome;
    if (savedSessions === undefined) delete process.env.GUARD_SESSIONS; else process.env.GUARD_SESSIONS = savedSessions;
  }
});

test("UnjangledGuardrailsV2 deny-final (initiative check #3): a configured hard deny survives adapter evaluation — v2's pre-check settles it without ever invoking the evaluate callback and fails with the BlockedError the spike captured (r6); the same callback in the loop still rewrites safe calls", async () => {
  const savedFetch = globalThis.fetch, savedKey = process.env.JEV_API_KEY, savedHome = process.env.GUARD_HOME, savedSessions = process.env.GUARD_SESSIONS;
  process.env.JEV_API_KEY = "test"; process.env.GUARD_HOME = dir; process.env.GUARD_SESSIONS = join(dir, "sessions-denyfinal");
  try {
    // the real adapter's callback, captured through a fake ctx — the only piece this unit
    // test can reach; the v2 dispatcher itself is simulated below with the semantics the
    // spike observed (runs r0/r6/r7, evidence/opencode-v2-hook-semantics-probe-2026-10-09.md)
    const permRegistered = {};
    UnjangledGuardrailsV2.setup({
      tool: { hook: () => {} },
      permission: { hook: (name, fn) => { permRegistered[name] = fn; } },
      location: { directory: "/tmp/opencode/work" },
    });
    const evaluate = permRegistered["evaluate"];

    // Simulated v2.0.24 permission pre-check: configured rules are consulted FIRST; a
    // matching deny settles the call WITHOUT invoking any evaluate callback and fails with
    // Permission.BlockedError carrying the ruleset (r6: PERM-REGISTERED then NO PERM-FIRE
    // then the BlockedError); anything else reaches the callbacks, whose final effect decides.
    class PermissionBlockedError extends Error {
      constructor(rules, call) {
        super("blocked by permission rules");
        this.name = "Permission.BlockedError";
        this.rules = rules;
        this.permission = call.action;
        this.resources = call.resources;
      }
    }
    const rules = [
      { action: "*", resource: "*", effect: "allow" },                      // the built-in base policy (r6, verbatim)
      { action: "shell", resource: "echo OGPERM-DENY *", effect: "deny" },  // the configured deny, fixture shape (r6)
    ];
    const matchedDeny = (action, resource) => rules.find((r) => r.effect === "deny"
      && (r.action === "*" || r.action === action)
      // the r6 matcher shape: a trailing-space-star pattern matched the bare command too
      && (r.resource === "*" || resource === r.resource.replace(/ \*$/, "") || resource.startsWith(r.resource.replace(/ \*$/, "") + " ")));
    let callbackCalls = 0;
    const dispatch = async (action, resources, sessionID) => {
      const deny = matchedDeny(action, resources[0]);
      if (deny) throw new PermissionBlockedError(rules.slice(), { action, resources });  // callbacks skipped (r6)
      callbackCalls++;                                                                    // else the callbacks run (r0/r7)
      const ev = { action, resources, effect: "allow", sessionID };                       // base-policy allow (r0)
      await evaluate(ev);
      return { effect: ev.effect };
    };

    // the configured deny: blocked, ZERO callback invocations, BlockedError carrying the rule
    await assert.rejects(dispatch("shell", ["echo OGPERM-DENY"], "oc-v2-denyfinal"), (err) => {
      assert.ok(err instanceof PermissionBlockedError);
      assert.equal(err.name, "Permission.BlockedError");
      assert.ok(err.rules.some((r) => r.effect === "deny" && r.resource === "echo OGPERM-DENY *"));
      return true;
    });
    assert.equal(callbackCalls, 0);
    // the adapter's session store saw nothing for the denied call — the callback never ran
    assert.equal(sessionRead("oc-v2-denyfinal").calls.length, 0);

    // contrast, the same callback in the loop: a non-denied call reaches it and the safe
    // verdict rewrites to allow — the adapter can only ever relax toward allow, never a deny
    globalThis.fetch = mockBrain({ risk: 0.2, approval: 0.05 });
    // a RELATIVE operand: `wc -l /tmp/...` is temp-lane shaped (a /tmp/ path is confined) and
    // would lane-skip instead of producing the verdict this callback must record
    const ran = await dispatch("shell", ["wc -l ledger.txt"], "oc-v2-denyfinal");
    assert.equal(callbackCalls, 1);
    assert.equal(ran.effect, "allow");
    assert.ok(sessionRead("oc-v2-denyfinal").calls.some((c) => c.level === "allow" && /ledger\.txt/.test(c.preview)));
  } finally {
    globalThis.fetch = savedFetch;
    if (savedKey === undefined) delete process.env.JEV_API_KEY; else process.env.JEV_API_KEY = savedKey;
    if (savedHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedHome;
    if (savedSessions === undefined) delete process.env.GUARD_SESSIONS; else process.env.GUARD_SESSIONS = savedSessions;
  }
});

test("UnjangledGuardrailsV2 execute.after: flagged scan annotates BOTH model-visible fields (output.output + content[0].text), reassigns the result, records the flag, and attempts the synthetic notice", async () => {
  // one mock brain: the assess questions ride the safe band, the scan questions flag an injection
  const scanBrain = async () => ({ ok: true, json: async () => ({ answers: {
    risk: { type: "score", score: 0.2, probabilities: {}, confidence: 0.8 },
    approval: noul(0.05), user_requested: noul(0.05), from_untrusted: noul(0.05),
    leaks_secrets: noul(0.05), dumps_env_argv: noul(0.05), dumps_process_argv: noul(0.05), reads_credential_file: noul(0.05),
    directed: { noul: 0.99 }, kind: { choice: "injection" },
  } }) });
  const savedFetch = globalThis.fetch, savedKey = process.env.JEV_API_KEY, savedHome = process.env.GUARD_HOME, savedSessions = process.env.GUARD_SESSIONS;
  globalThis.fetch = scanBrain; process.env.JEV_API_KEY = "test"; process.env.GUARD_HOME = dir; process.env.GUARD_SESSIONS = join(dir, "sessions-after");
  try {
    const registered = {};
    const notices = [];
    UnjangledGuardrailsV2.setup({
      tool: { hook: (name, fn) => { registered[name] = fn; } },
      permission: { hook: () => {} },
      location: { directory: "/tmp/opencode/work" },
      session: { synthetic: ({ sessionID, text }) => { notices.push({ sessionID, text }); return Promise.resolve({ id: "msg_x", type: "synthetic", delivery: "steer" }); } },
    });
    const after = registered["execute.after"];
    // the result shape the probe observed (r0/r5b/r5c EVA payloads); text clears the 200-char scan floor
    const long = "ordinary shell filler text so the scan clears MIN_SCAN_CHARS ".repeat(6);
    const mk = () => ({ tool: "shell", sessionID: "oc-v2-after", agent: "build", messageID: "m1", id: "c1", input: { command: "cat README.md" }, status: "completed",
      result: { output: { exit: 0, truncated: false, output: long, status: "completed" }, content: [{ type: "text", text: long }], metadata: { status: "completed" } } });
    const ev = mk();
    await after(ev);
    // the rewrite rule (epic Decision 2026-10-09): BOTH fields carry the flagged prefix and
    // the event's result is reassigned with them mutated
    assert.match(ev.result.output.output, /^\[This tool result was flagged by the Unjangled Guardrails classifier/);
    assert.equal(ev.result.output.output, ev.result.content[0].text);
    assert.ok(ev.result.output.output.endsWith(long));
    assert.ok(ev.result.content[0].text.endsWith(long));
    // the flags bucket records the scan as v1 does
    const flag = sessionRead("oc-v2-after").flags.at(-1);
    assert.equal(flag.kind, "injection");
    assert.equal(flag.tool, "shell");
    assert.equal(flag.p, 0.99);
    assert.ok(flag.reported);
    // the v1 toast maps to the best-effort steer-delivered synthetic notice
    assert.equal(notices.length, 1);
    assert.equal(notices[0].sessionID, "oc-v2-after");
    assert.match(notices[0].text, /flagged by the Unjangled Guardrails classifier/);
  } finally {
    globalThis.fetch = savedFetch;
    if (savedKey === undefined) delete process.env.JEV_API_KEY; else process.env.JEV_API_KEY = savedKey;
    if (savedHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedHome;
    if (savedSessions === undefined) delete process.env.GUARD_SESSIONS; else process.env.GUARD_SESSIONS = savedSessions;
  }
});

test("UnjangledGuardrailsV2 execute.after nudges: secret-shape appends to both fields once per session, host-pollution fires on the v2 shell name, a throwing synthetic never breaks the hook, and errored calls (no result) are left alone", async () => {
  const savedHome = process.env.GUARD_HOME, savedSessions = process.env.GUARD_SESSIONS;
  process.env.GUARD_HOME = dir; process.env.GUARD_SESSIONS = join(dir, "sessions-after");
  try {
    const registered = {};
    UnjangledGuardrailsV2.setup({
      tool: { hook: (name, fn) => { registered[name] = fn; } },
      permission: { hook: () => {} },
      location: { directory: "/tmp/opencode/work" },
      // best-effort by contract: a notice failure must never break the hook
      session: { synthetic: () => { throw new Error("no notice surface here"); } },
    });
    const after = registered["execute.after"];
    const result = (text) => ({ output: { exit: 0, truncated: false, output: text, status: "completed" }, content: [{ type: "text", text }], metadata: {} });
    // secret-shaped write: the note appends to BOTH fields, and the throwing synthetic is swallowed
    const secret = 'TOKEN="sk-proj-' + "a".repeat(24) + '"';
    const w1 = { tool: "write", sessionID: "oc-v2-nudge", input: { filePath: "/tmp/opencode/work/x.txt", content: secret }, status: "completed", result: result(secret) };
    await after(w1);  // must not throw despite the synthetic throwing
    assert.ok(w1.result.output.output.endsWith("\n\n[Unjangled Guardrails] A write looked secret-shaped. Keep keys in env or Infisical, never in code or git."));
    assert.equal(w1.result.output.output, w1.result.content[0].text);
    // second secret-shaped write in the same session: nudge-once-per-session-per-rule
    const w2 = { tool: "write", sessionID: "oc-v2-nudge", input: { filePath: "/tmp/opencode/work/y.txt", content: "xoxb-short-secret-token" + "b".repeat(10) }, status: "completed", result: result("xoxb-short-secret-token" + "b".repeat(10)) };
    await after(w2);
    assert.ok(!w2.result.output.output.includes("[Unjangled Guardrails]"));
    // .env files are exempt from the secret-shape nudge — under both field spellings
    // (v1 `filePath`, the v2 `path` the probe s2 observed). Fresh sessions: the exemption
    // must suppress the nudge itself, not ride a once-per-session early return.
    const w3 = { tool: "write", sessionID: "oc-v2-nudge-env1", input: { filePath: "/tmp/opencode/work/.env", content: secret }, status: "completed", result: result(secret) };
    await after(w3);
    assert.ok(!w3.result.output.output.includes("[Unjangled Guardrails]"));
    const w4 = { tool: "write", sessionID: "oc-v2-nudge-env2", input: { path: "/tmp/opencode/work/.env", content: secret }, status: "completed", result: result(secret) };
    await after(w4);
    assert.ok(!w4.result.output.output.includes("[Unjangled Guardrails]"));
    // sanity that those fresh sessions were nudge-eligible at all: a non-.env write on the
    // same spelling DOES nudge (so the two green assertions above are load-bearing)
    const w5 = { tool: "write", sessionID: "oc-v2-nudge-env3", input: { path: "/tmp/opencode/work/x.txt", content: secret }, status: "completed", result: result(secret) };
    await after(w5);
    assert.ok(w5.result.output.output.includes("[Unjangled Guardrails]"));
    // host-pollution nudges on the v2 spelling of the shell tool (probe: tool "shell")
    const s1 = { tool: "shell", sessionID: "oc-v2-nudge2", input: { command: "npm install -g left-pad" }, status: "completed", result: result("added 1 package") };
    await after(s1);
    assert.ok(s1.result.output.output.endsWith("\n\n[Unjangled Guardrails] That install may land on the host. Prefer a container or a project-local environment."));
    assert.equal(s1.result.content[0].text, s1.result.output.output);
    // an errored call carries error and NO result (probe r6/r8): the hook returns clean
    const bad = { tool: "shell", sessionID: "oc-v2-nudge2", input: { command: "echo x" }, status: "error", error: { _tag: "Tool.Error", error: { _tag: "Permission.BlockedError" } } };
    await after(bad);
    assert.equal(bad.result, undefined);
  } finally {
    if (savedHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedHome;
    if (savedSessions === undefined) delete process.env.GUARD_SESSIONS; else process.env.GUARD_SESSIONS = savedSessions;
  }
});

test("UnjangledGuardrailsV2 setup: subscribes the session.deleted nudge-state cleanup (v1 parity via ctx.event, best-effort); firing it frees the session so the same rule can nudge again", async () => {
  let sub = null;
  const registered = {};
  UnjangledGuardrailsV2.setup({
    tool: { hook: (name, fn) => { registered[name] = fn; } },
    permission: { hook: () => {} },
    location: { directory: "/tmp/opencode/work" },
    // best-effort synthetic that works here, so the nudge path is fully exercised
    session: { synthetic: () => Promise.resolve({ id: "msg_x", delivery: "steer" }) },
    // the recorded r0 ctx surface: ctx.event {subscribe}; the v1-parity cleanup subscribes
    // the "session.deleted" topic defensively (call shape unprobed — captured here)
    event: { subscribe: (topic, fn) => { sub = { topic, fn }; } },
  });
  assert.ok(sub, "setup subscribed the cleanup");
  assert.equal(sub.topic, "session.deleted");
  assert.equal(typeof sub.fn, "function");
  // the hook still registered despite the extra ctx member, and the handler tolerates
  // every payload shape it defends against
  assert.equal(typeof registered["execute.after"], "function");
  for (const payload of [undefined, {}, { sessionID: "x" }, { properties: { info: { id: "y" } } }]) sub.fn(payload);

  const after = registered["execute.after"];
  const result = (text) => ({ output: { exit: 0, truncated: false, output: text, status: "completed" }, content: [{ type: "text", text }], metadata: {} });
  const secret = 'TOKEN="sk-proj-' + "c".repeat(24) + '"';
  const w1 = { tool: "write", sessionID: "oc-v2-cleanup", input: { path: "/tmp/opencode/work/a.txt", content: secret }, status: "completed", result: result(secret) };
  await after(w1);
  assert.ok(w1.result.output.output.includes("[Unjangled Guardrails]"));
  // same rule again, same session: suppressed by the once-per-session map…
  const w2 = { tool: "write", sessionID: "oc-v2-cleanup", input: { path: "/tmp/opencode/work/b.txt", content: secret }, status: "completed", result: result(secret) };
  await after(w2);
  assert.ok(!w2.result.output.output.includes("[Unjangled Guardrails]"));
  // …and freed again once the cleanup fires for that session (payload shape v1 used)
  sub.fn({ properties: { sessionID: "oc-v2-cleanup" } });
  const w3 = { tool: "write", sessionID: "oc-v2-cleanup", input: { path: "/tmp/opencode/work/c.txt", content: secret }, status: "completed", result: result(secret) };
  await after(w3);
  assert.ok(w3.result.output.output.includes("[Unjangled Guardrails]"));
});

test("UnjangledGuardrailsV2 runtime coexistence detection (epic-host-isolation ticket 2): setup signals its own entry, records a sibling v1-shaped adapter through the loader-WARN console channel, surfaces the synthetic guidance once on the first session event, and stays silent with no sibling", async () => {
  // Ground truth (evidence/opencode-v2-plugin-loading-probe-2026-10-07.md, Q1/run 4 + shape a):
  // v2 scans BOTH plugin dirs, dedupes by id, and rejects the v1 re-export shape with a WARN
  // that only reaches the v2 log — never stdout. The r0 ctx dump (hook-semantics probe §c)
  // exposes no setup-time notice surface (synthetic needs a sessionID), so the ladder is
  // console at setup + the synthetic on the first session event. The console lines are the
  // only ones this test asserts on: stubbed here, restored in finally.
  const { mkdirSync, writeFileSync } = await import("node:fs");
  const home = mkdtempSync(join(tmpdir(), "unjangled-guardrails-coexist-"));
  const configPlugins = join(home, ".config", "opencode", "plugins");
  mkdirSync(configPlugins, { recursive: true });
  const v1Adapter = join(configPlugins, "unjangled-guardrails.js");
  writeFileSync(v1Adapter, `export { UnjangledGuardrails } from "/tmp/opencode/src/opencode.js";\n`);  // the exact v1 adapter shape install.js writes
  const savedFetch = globalThis.fetch, savedKey = process.env.JEV_API_KEY, savedGuardHome = process.env.GUARD_HOME;
  const logs = [], warns = [], notices = [];
  const origLog = console.log, origWarn = console.warn;
  console.log = (...a) => logs.push(a.join(" "));
  console.warn = (...a) => warns.push(a.join(" "));
  // the scan base is GUARD_HOME ?? homedir(): point it at the fixture per leg
  process.env.JEV_API_KEY = "test"; process.env.GUARD_HOME = home;
  // the brain must not answer here: a throw rides failOpen to null, so execute.before passes
  // through untouched and the notice path is the only thing under test
  globalThis.fetch = async () => { throw new Error("no brain in the coexistence test"); };
  const registered = {};
  const mkCtx = () => ({
    tool: { hook: (name, fn) => { registered[name] = fn; } },
    permission: { hook: () => {} },
    location: { directory: home },
    session: { synthetic: ({ sessionID, text }) => { notices.push({ sessionID, text }); return Promise.resolve({ id: "msg_x", type: "synthetic", delivery: "steer" }); } },
    event: { subscribe: () => {} },
  });
  try {
    UnjangledGuardrailsV2.setup(mkCtx());
    // the positive entry signal — the load proof, present whether or not a sibling tripped
    assert.ok(logs.some((l) => /v2 adapter active/.test(l)), logs.join("\n"));
    // the coexistence fact recorded at setup through the loader-WARN channel, naming the adapter
    const warn = warns.find((l) => /coexistence/.test(l));
    assert.ok(warn, warns.join("\n"));
    assert.ok(warn.includes(v1Adapter));
    assert.match(warn, /Missing key at \["default"\]/);  // the loader's own rejection, quoted for the log grep
    assert.match(warn, /install opencode --v2 --force/);  // the only command that resolves either mismatch state
    // no session exists at setup — the synthetic guidance is pending, not sent
    assert.equal(notices.length, 0);
    // the first session event the adapter sees surfaces it, once, into that session
    await registered["execute.before"]({ tool: "shell", sessionID: "oc-coexist", input: { command: "echo hi" } });
    assert.equal(notices.length, 1);
    assert.equal(notices[0].sessionID, "oc-coexist");
    assert.match(notices[0].text, /v1 plugin adapter/);
    assert.match(notices[0].text, /v2 adapter is the active guard/);
    // once means once: a later event in another session does not repeat it
    await registered["execute.before"]({ tool: "shell", sessionID: "oc-coexist-2", input: { command: "echo hi" } });
    assert.equal(notices.length, 1);

    // no-sibling control: a clean scan root (both scanned dirs present, empty) — the entry
    // signal still there, no coexistence WARN, and the first session event sends no notice
    logs.length = 0; warns.length = 0;
    const clean = mkdtempSync(join(tmpdir(), "unjangled-guardrails-coexist-clean-"));
    mkdirSync(join(clean, ".config", "opencode", "plugins"), { recursive: true });
    mkdirSync(join(clean, ".opencode", "plugins"), { recursive: true });
    process.env.GUARD_HOME = clean;
    UnjangledGuardrailsV2.setup(mkCtx());
    assert.ok(logs.some((l) => /v2 adapter active/.test(l)), logs.join("\n"));
    assert.equal(warns.length, 0, warns.join("\n"));
    await registered["execute.before"]({ tool: "shell", sessionID: "oc-clean", input: { command: "echo hi" } });
    assert.equal(notices.length, 1);

    // false-positive pins in the clean tree: another plugin's named re-export, a v2-shaped
    // default adapter, and a BOTH-shapes file (the default wins — install.js adapterGeneration
    // precedence) are none of them a v1 adapter
    const plugDir = join(clean, ".config", "opencode", "plugins");
    writeFileSync(join(plugDir, "other.js"), `export { OtherPlugin } from "somewhere-else";\n`);
    writeFileSync(join(plugDir, "v2adapter.js"), `import { UnjangledGuardrailsV2 } from "/tmp/opencode/src/opencode.js";\nexport default UnjangledGuardrailsV2;\n`);
    writeFileSync(join(plugDir, "hybrid.js"), `export { UnjangledGuardrails } from "/tmp/x.js";\nexport default { id: "x", setup() {} };\n`);
    logs.length = 0; warns.length = 0;
    UnjangledGuardrailsV2.setup(mkCtx());
    assert.equal(warns.filter((l) => /coexistence/.test(l)).length, 0, warns.join("\n"));

    // the second scanned dir counts: with .config/opencode/plugins ABSENT, a v1 adapter in
    // ~/.opencode/plugins is still found (one unreadable dir must not hide the other)
    const dotHome = mkdtempSync(join(tmpdir(), "unjangled-guardrails-coexist-dot-"));
    const dotPlugins = join(dotHome, ".opencode", "plugins");
    mkdirSync(dotPlugins, { recursive: true });
    writeFileSync(join(dotPlugins, "unjangled-guardrails.js"), `export { UnjangledGuardrails } from "/tmp/opencode/src/opencode.js";\n`);
    process.env.GUARD_HOME = dotHome;
    logs.length = 0; warns.length = 0;
    UnjangledGuardrailsV2.setup(mkCtx());
    const dotWarn = warns.find((l) => /coexistence/.test(l));
    assert.ok(dotWarn && dotWarn.includes(join(dotPlugins, "unjangled-guardrails.js")), warns.join("\n"));
  } finally {
    console.log = origLog; console.warn = origWarn;
    globalThis.fetch = savedFetch;
    if (savedKey === undefined) delete process.env.JEV_API_KEY; else process.env.JEV_API_KEY = savedKey;
    if (savedGuardHome === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = savedGuardHome;
  }
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
    ["cursor-preToolUse", await handleHook({ hook_event_name: "preToolUse", tool_name: "Bash", tool_input: { command: "cat /etc/hosts" }, session_id: "leak" }, opts(leak))],  // /etc keeps cat off the temp lane
    ["hermes-no-approver", await handleHook(PRE, opts(leak, { agent: "hermes" }))],
  ];
  for (const [name, out] of cases) assert.equal(level(out), "deny", name);
});

// Back-compat (operator ruling 2026-10-07): the pre-rename JEV_GUARD_* spelling still works.

test("back-compat: JEV_GUARD_HERMES_APPROVER still defers Hermes asks to its approver", async () => {
  assert.equal(level(await handleHook(PRE, opts({}, { agent: "hermes", env: { ...env, JEV_GUARD_HERMES_APPROVER: "1" } }))), "ask");
});
