// The simulated harnesses (conformance entry 2, epic-adapter-seam): scripted stand-ins for the
// real hosts, one per dialect, each sending the exact payload shapes its harness sends and each
// interpreting the adapter's reply the way the real host does. The harnesses drive the REAL
// adapter modules — src/hook.js, src/opencode.js, src/acp.js, extensions/unjangled-guardrails.ts,
// the Hermes python bridge — through the contract case set. Zero classifier calls (the simulated
// brain answers), zero network (loopback only, for the python bridge that spawns the real CLI).
import { PassThrough } from "node:stream";
import { createInterface } from "node:readline";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { handleHook } from "../../src/hook.js";
import { UnjangledGuardrails } from "../../src/opencode.js";
import { runProxy } from "../../src/acp.js";
import { remember } from "../../src/session.js";
import { scriptedBrain } from "./brain.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// ── shared harness environment ───────────────────────────────────────────────────────────────

/** The harness root: per-run temp dirs every adapter shares, so no case touches operator state. */
export function makeHarnessEnv({ root }) {
  const projectDir = join(root, "project");
  const sessionsDir = join(root, "sessions");
  const guardHome = join(root, "guard-home");
  for (const d of [projectDir, sessionsDir, guardHome]) mkdirSync(d, { recursive: true });
  const optsEnv = (extra = {}) => ({
    JEV_API_KEY: "conformance-simulated",
    GUARD_SKIP_TOOLS: "",
    GUARD_SKIP_SCAN: "",
    GUARD_HOME: guardHome,
    GUARD_SESSIONS: sessionsDir,
    ...extra,
  });
  return {
    root, projectDir, sessionsDir, guardHome, optsEnv,
    sid: (tag) => `conf-${tag}`,
    seedPrompt: (sid, text) => remember(sid, "prompts", { text }),
    resetRulings: () => {
      writeFileSync(join(guardHome, "rulings.json"), "[]");
      // pair the store write with a mutation row so the tamper check stays quiet between cases
      appendFileSync(join(guardHome, "rulings-use.jsonl"), JSON.stringify({ at: new Date().toISOString(), ruling: null, effect: "reset", note: "conformance fixture reset" }) + "\n");
    },
    writeRuling: (ruling) => {
      // The store plus a mutation audit row, exactly as an operator write would leave them —
      // the tamper check compares store mtime against the last audit row.
      writeFileSync(join(guardHome, "rulings.json"), JSON.stringify([ruling]));
      appendFileSync(join(guardHome, "rulings-use.jsonl"), JSON.stringify({ at: new Date().toISOString(), ruling: ruling.id, effect: ruling.effect, note: "conformance fixture store write" }) + "\n");
    },
  };
}

// ── adapter 1: src/hook.js — the command hook, one simulated harness per host dialect ────────

const LONG_TEXT = "Ordinary report content. ".repeat(14);  // > MIN_SCAN_CHARS so the post-scan runs

/** Claude Code / Codex / Copilot CLI: Claude-shaped JSON, snake_case keys. */
const claudePre = (h, tag, extra = {}) => ({
  hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "make deploy" },
  session_id: h.sid(tag), cwd: h.projectDir, ...extra,
});
/** Claude-shaped host that spells the keys camelCase (some versions do). */
const claudeCamelPre = (h, tag) => ({
  eventName: "PreToolUse", toolName: "Bash", toolInput: { command: "make deploy" }, sessionId: h.sid(tag),
});
const postScan = (h, tag, snakeKeys) => ({
  ...(snakeKeys
    ? { hook_event_name: "PostToolUse", tool_name: "webfetch", tool_input: { url: "https://example.com/report" } }
    : { eventName: "PostToolUse", toolName: "webfetch", toolInput: { url: "https://example.com/report" } }),
  [snakeKeys ? "tool_response" : "toolResponse"]: { content: [{ type: "text", text: LONG_TEXT }] },
  [snakeKeys ? "session_id" : "sessionId"]: h.sid(tag),
});

/** Drive one hook.js event under one brain scenario. Returns the raw reply plus the brain record. */
export async function runHook(h, input, { scenario, agent, envExtra = {} } = {}) {
  const brain = scriptedBrain(scenario);
  const out = await handleHook(input, { agent, env: h.optsEnv(envExtra), fetchImpl: brain.fetchImpl });
  return { out, brain };
}

export const dialects = {
  claude: {
    pre: (h, tag) => claudePre(h, tag),
    post: (h, tag) => postScan(h, tag, true),
    /** PreToolUse reply → verdict: null = allow, hookSpecificOutput.permissionDecision otherwise. */
    verdict: (out) => out?.hookSpecificOutput?.permissionDecision ?? "allow",
    text: (out) => out?.hookSpecificOutput?.permissionDecisionReason ?? "",
  },
  claudeCamel: {
    pre: (h, tag) => claudeCamelPre(h, tag),
    verdict: (out) => out?.hookSpecificOutput?.permissionDecision ?? "allow",
    text: (out) => out?.hookSpecificOutput?.permissionDecisionReason ?? "",
  },
  codex: {
    pre: (h, tag) => claudePre(h, tag, { turn_id: "conf-turn", model: "conf-model" }),
    verdict: (out) => out?.hookSpecificOutput?.permissionDecision ?? "allow",
    text: (out) => out?.hookSpecificOutput?.permissionDecisionReason ?? "",
  },
  copilot: {
    pre: (h, tag) => claudePre(h, tag, { timestamp: "2026-10-06T00:00:00Z" }),
    verdict: (out) => out?.permissionDecision ?? out?.hookSpecificOutput?.permissionDecision ?? "allow",
    text: (out) => out?.permissionDecisionReason ?? out?.hookSpecificOutput?.permissionDecisionReason ?? "",
  },
  gemini: {
    pre: (h, tag) => ({ hook_event_name: "BeforeTool", tool_name: "Bash", tool_input: { command: "make deploy" }, session_id: h.sid(tag) }),
    verdict: (out) => (out === null || out === undefined ? "allow" : (out.decision ?? "allow")),
    text: (out) => out?.reason ?? "",
    post: (h, tag) => ({ hook_event_name: "AfterTool", tool_name: "webfetch", tool_response: { content: [{ type: "text", text: LONG_TEXT }] }, session_id: h.sid(tag) }),
    postFlag: (out) => !!(out?.systemMessage && out?.hookSpecificOutput?.additionalContext),
  },
  cursorShell: {
    pre: (h, tag) => ({ eventName: "beforeShellExecution", command: "make deploy", cwd: h.projectDir, sessionId: h.sid(tag) }),
    verdict: (out) => out?.permission ?? "allow",
    text: (out) => out?.user_message ?? "",
  },
  cursorTool: {
    pre: (h, tag) => ({ eventName: "preToolUse", tool_name: "Bash", tool_input: { command: "make deploy" }, sessionId: h.sid(tag) }),
    verdict: (out) => out?.permission ?? "allow",
    text: (out) => out?.user_message ?? "",
    post: (h, tag) => ({ eventName: "postToolUse", tool_name: "webfetch", tool_input: { url: "https://example.com/report" }, tool_output: LONG_TEXT, sessionId: h.sid(tag) }),
    postFlag: (out) => typeof out?.additional_context === "string" && out.additional_context.length > 0,
  },
  hermesJs: {
    pre: (h, tag) => claudePre(h, tag),
    verdict: (out) => out?.hookSpecificOutput?.permissionDecision ?? "allow",
    text: (out) => out?.hookSpecificOutput?.permissionDecisionReason ?? "",
    post: (h, tag) => postScan(h, tag, true),
    postFlag: (out) => !!(out?.decision === "block" && out?.systemMessage),
  },
};

export const claudePost = (h, tag) => postScan(h, tag, true);
export const claudePostVerdict = (out) => (out === null ? "clean" : out.decision === "block" ? "flagged" : "unknown");

// ── adapter 2: src/opencode.js — the OpenCode plugin ─────────────────────────────────────────

const ocMessages = (text) => [{ info: { role: "user" }, parts: [{ type: "text", text }] }];

/** Instantiate the real plugin against a fake OpenCode client. */
export async function runOpencode(h, tag, userWords) {
  const client = {
    tui: { showToast: async () => {} },
    app: { log: () => {} },
    session: { messages: async () => ({ data: ocMessages(userWords ?? "please deploy the staging box") }) },
  };
  const handlers = await UnjangledGuardrails({ client, directory: h.projectDir });
  const sid = h.sid(tag);
  return {
    sid,
    before: (args, scenario) => opencodeCall(scenario, () => handlers["tool.execute.before"]({ tool: "Bash", sessionID: sid }, { args })),
    ask: (pattern, scenario) => opencodeAsk(handlers, sid, pattern, scenario),
    after: async (scenario) => {
      const output = { output: LONG_TEXT };
      await opencodeCall(scenario, () => handlers["tool.execute.after"]({ tool: "webfetch", args: { url: "https://example.com/report" }, sessionID: sid }, output));
      return output.output;
    },
  };
}

async function opencodeCall(scenario, fn) {
  const brain = scriptedBrain(scenario);
  setGlobalBrain(brain);  // the plugin takes no opts — the core reads the global fetch (entry 3 migrates it)
  let err = null, out;
  try { out = await fn(); } catch (e) { err = e; }
  setGlobalBrain(null);
  return { brain, err, out };
}

async function opencodeAsk(handlers, sid, pattern, scenario) {
  const brain = scriptedBrain(scenario);
  setGlobalBrain(brain);
  const output = {};
  await handlers["permission.ask"]({ type: "bash", pattern, title: "make deploy", sessionID: sid, metadata: {} }, output);
  setGlobalBrain(null);
  return { brain, status: output.status };
}

// ── adapter 3: extensions/unjangled-guardrails.ts — the pi extension ─────────────────────────

export async function runPi(h, tag, userWords) {
  const { default: piExtension } = await import(new URL("../../extensions/unjangled-guardrails.ts", import.meta.url));
  const handlers = {};
  piExtension({ on: (name, fn) => { handlers[name] = fn; } });
  const sid = h.sid(tag);
  const branch = [{ type: "message", message: { role: "user", content: [{ type: "text", text: userWords ?? "please deploy the staging box" }] } }];
  let confirmAnswer = true;
  const notifications = [];
  const ctx = {
    sessionManager: { getSessionId: () => sid, getBranch: () => branch },
    cwd: h.projectDir, sessionID: sid, signal: undefined, hasUI: true,
    ui: { notify: (m) => notifications.push(m), confirm: async () => confirmAnswer },
  };
  const brainFor = (scenario) => { const b = scriptedBrain(scenario); currentGlobalBrain = b; return b; };
  return {
    sid,
    call: async (scenario) => { const brain = brainFor(scenario); const r = await handlers.tool_call({ toolName: "Bash", input: { command: "make deploy" } }, ctx); return { brain, r }; },
    setResult: (v) => { confirmAnswer = v; },
    result: async (scenario) => { const brain = brainFor(scenario); const r = await handlers.tool_result({ toolName: "webfetch", input: { url: "https://example.com/report" }, content: [{ type: "text", text: LONG_TEXT }] }, ctx); return { brain, r, notifications }; },
  };
}

// pi and the OpenCode plugin configure the core from process.env and the global fetch (they
// predate the contract and take no opts — entry 3 migrates them). While they run, the global
// fetch points at the simulated brain; run.mjs installs and restores the patch.
export let currentGlobalBrain = null;
export function setGlobalBrain(b) { currentGlobalBrain = b; }
export const globalFetchImpl = (url, init) => (currentGlobalBrain ? currentGlobalBrain.fetchImpl(url, init) : globalThis.__realFetch(url, init));

// ── adapter 4: src/acp.js — the ACP stdio proxy, driven by a scripted fake agent ─────────────

const ACP_AGENT = `
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
const sid = process.env.ACP_SID;
let started = false;
const start = () => {
  if (started) return;
  started = true;
  if (process.env.ACP_MODE === "terminal") {
    send({ jsonrpc: "2.0", method: "session/update", params: { sessionId: sid, update: { sessionUpdate: "agent_message_chunk", content: { type: "text", text: process.env.ACP_INTENT || "" } } } });
    send({ jsonrpc: "2.0", id: 1, method: "terminal/create", params: { sessionId: sid, command: "make", args: ["deploy"], cwd: process.env.ACP_CWD } });
  } else if (process.env.ACP_MODE === "read") {
    send({ jsonrpc: "2.0", id: 2, method: "fs/read_text_file", params: { sessionId: sid, path: process.env.ACP_PATH || "report.txt" } });
  }
};
if (process.env.ACP_MODE !== "terminal") start();  // terminal mode starts on the client's first message, so the operator prompt lands before the agent speaks
let buf = "";
process.stdin.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\\n")) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    let m; try { m = JSON.parse(line); } catch { continue; }
    start();
    if (m.id !== undefined && !m.method) send({ method: "agent/echo", params: m });
  }
});
setTimeout(() => process.exit(0), 20000);
`;

/** Drive one ACP exchange: the fake agent speaks ACP at the proxy, the harness plays the client. */
export async function runAcp(h, tag, { scenario, mode, permissionAnswer, resultContent, ruling } = {}) {
  if (ruling) h.writeRuling(ruling);
  const brain = scriptedBrain(scenario);
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const received = [];
  createInterface({ input: stdout }).on("line", (line) => {
    if (!line.trim()) return;
    try { received.push(JSON.parse(line)); } catch { /* non-JSON noise never arrives */ }
  });
  const env = {
    ...h.optsEnv(),
    ACP_MODE: mode, ACP_SID: h.sid(tag), ACP_CWD: h.projectDir, ACP_INTENT: "deploying the staging box as asked",
  };
  const child = runProxy(process.execPath, ["-e", ACP_AGENT], { stdin, stdout, env, fetchImpl: brain.fetchImpl, onExit: () => {} });
  const write = (m) => new Promise((res) => stdin.write(JSON.stringify(m) + "\n", res));
  const waitFor = async (pred, ms = 10000) => {
    const deadline = Date.now() + ms;
    for (;;) {
      const hit = received.find(pred);
      if (hit) return hit;
      if (Date.now() > deadline) throw new Error(`conformance ACP harness: timed out waiting; saw ${JSON.stringify(received).slice(0, 600)}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  };
  try {
    if (mode === "terminal") {
      await write({ jsonrpc: "2.0", method: "session/prompt", params: { sessionId: h.sid(tag), prompt: [{ type: "text", text: "operator asked for the staging deploy" }] } });
      const first = await waitFor((m) =>
        m.method === "session/request_permission"
        || (m.method === "terminal/create" && m.id === 1)
        || (m.method === "agent/echo" && m.params?.id === 1 && m.params?.error));
      if (first.method === "session/request_permission") {
        assert.equal(first.params?.options?.some((o) => o.kind === "allow_once"), true, "the ask prompt offers allow/reject");
        await write({ jsonrpc: "2.0", id: first.id, result: { outcome: { outcome: "selected", optionId: permissionAnswer } } });
        if (permissionAnswer === "allow") {
          const forwarded = await waitFor((m) => m.method === "terminal/create" && m.id === 1);
          await write({ jsonrpc: "2.0", id: 1, result: {} });
          return { brain, outcome: "forwarded", forwarded, echoed: await waitFor((m) => m.method === "agent/echo" && m.params?.id === 1) };
        }
        return { brain, outcome: "rejected", forwarded: await waitFor((m) => m.method === "agent/echo" && m.params?.id === 1) };
      }
      if (first.method === "terminal/create") {  // allowed straight through — the client still gets the request
        await write({ jsonrpc: "2.0", id: 1, result: {} });
        return { brain, outcome: "forwarded", forwarded: first, echoed: await waitFor((m) => m.method === "agent/echo" && m.params?.id === 1) };
      }
      return { brain, outcome: "decided-by-gate", echoed: first };  // the gate denied: the agent sees only the error
    }
    if (mode === "read") {
      await waitFor((m) => m.method === "fs/read_text_file" && m.id === 2);
      await write({ jsonrpc: "2.0", id: 2, result: { content: resultContent } });
      return { brain, scanned: await waitFor((m) => m.method === "agent/echo" && m.params?.id === 2) };
    }
    throw new Error(`unknown ACP harness mode ${mode}`);
  } finally {
    stdin.end();
    child.kill();
  }
}

// ── adapter 5: plugins/unjangled-guardrails — the Hermes python bridge ───────────────────────

/** Drive the real python adapter through one pre_tool_call / transform_tool_result event.
 *  The bridge spawns the repo's own CLI, so the brain is the loopback server and the guard
 *  home is the temp one (which carries the shim entry point the bridge validates against). */
export async function runHermesPython(h, http, { scenario, mode = "pre", tool = "bash", args, result, approver = false, ruling, tag } = {}) {
  http.setScenario(scenario);
  if (ruling) h.writeRuling(ruling);
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  // The approver is configured through the real detection path: a HERMES_CONFIG whose
  // approvals block says manual (an approval flow exists) or off (it does not).
  const hermesConfig = join(h.root, "hermes-config.yaml");
  writeFileSync(hermesConfig, approver ? "approvals:\n  mode: manual\n" : "approvals:\n  mode: off\n");
  const env = {
    GUARD_HOME: h.guardHome,
    SYSTEMONE_URL: http.url,
    GUARD_SESSIONS: h.sessionsDir,
    GUARD_SKIP_TOOLS: "",
    GUARD_SKIP_SCAN: "",
    HERMES_CONFIG: hermesConfig,
    GUARD_NO_INSTALL_HINT: "1",
    PATH: process.env.PATH, HOME: process.env.HOME,
    HC_PLUGIN: join(REPO, "plugins", "unjangled-guardrails", "__init__.py"),
    HERMES_CASE: mode,
    HC_TOOL: tool,
    HC_ARGS: JSON.stringify(args ?? { command: "make deploy" }),
    HC_SID: h.sid(tag ?? "hermes"),
    HC_RESULT: result ?? "",
  };
  const run = promisify(execFile);
  const { stdout } = await run("python3", [join(h.root, "hermes-driver.py")], { env, cwd: h.projectDir, timeout: 30000 });
  return JSON.parse(stdout.trim() || "null");
}

/** The python entry point the bridge executes; written into the harness root by run.mjs. */
export const HERMES_DRIVER = [
  "import json, os, importlib.util",
  'spec = importlib.util.spec_from_file_location("hermes_adapter", os.environ["HC_PLUGIN"])',
  "mod = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(mod)",
  'case = os.environ.get("HERMES_CASE", "pre")',
  'if case == "pre":',
  '    out = mod._pre_tool_call(tool_name=os.environ.get("HC_TOOL", "bash"), args=json.loads(os.environ.get("HC_ARGS", "{}")), session_id=os.environ.get("HC_SID", ""))',
  "else:",
  '    out = mod._transform_tool_result(tool_name=os.environ.get("HC_TOOL", "webfetch"), args=json.loads(os.environ.get("HC_ARGS", "{}")), result=os.environ.get("HC_RESULT", ""))',
  "print(json.dumps(out))",
  "",
].join("\n");
