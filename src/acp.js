// `unjangled-guardrails acp -- <agent command...>`: a stdio proxy between any ACP client (Zed, JetBrains, ...) and any ACP agent.
// Guards what flows through the client: terminal/create and fs/write_text_file are assessed before they are forwarded
// (ask → session/request_permission to the client), and fs/read_text_file / terminal/output results are scanned on the way
// back. Tools the agent runs on its own (its built-in web fetch, say) never pass through here and are not covered.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
// Contract-only (entry 3, epic-adapter-seam): every core call routes through src/contract.js.
import { assess, scan, scanInstructions, failClosed, preview, excerpt, INSTRUCTION_FILE, sessionRemember, sessionRememberCreated, expirePromptSession, recordHarnessStore, capturePromptRuling, promptCaptureTier, agentCreatedPaths } from "./contract.js";

// The closed optionId→capture-choice map (story 4): only an option the gate itself offered
// maps to a choice; hasOwn guards the lookup so a forged prototype-key optionId
// ("constructor") reads undefined and falls to the reject path, never a truthy inherited value.
const CAPTURE_CHOICES = { allow: "once", session: "session", always: "always" };

export function runProxy(cmd, args, { stdin = process.stdin, stdout = process.stdout, env = process.env, fetchImpl, onExit = (c) => process.exit(c) } = {}) {
  // Store visibility (CAP-5, entry 5): this process serves a harness — record where its
  // policy store lives so operator terminals can see a split. Entry-time, never per call;
  // the guards inside keep test fixtures silent; it never throws.
  recordHarnessStore("acp", env);
  const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "inherit"], env });
  const opts = { env, fetchImpl };
  const toClient = (m) => stdout.write(JSON.stringify(m) + "\n");
  const toAgent = (m) => child.stdin.write(JSON.stringify(m) + "\n");
  const warn = (err) => process.stderr.write(`unjangled-guardrails: ${err.message ?? err}\n`);

  let seq = 0;
  const ours = new Map();      // id of a request we sent to the client → { resolve, sessionId } — the session id answers session/cancel below
  const agentReqs = new Map(); // id of an agent→client request we forwarded → method
  const intents = new Map();   // sessionId → the agent's current message text, rebuilt from agent_message_chunk updates

  function askClient(method, params) {
    const id = `unjangled-guardrails:${++seq}`;
    return new Promise((resolve) => { ours.set(id, { resolve, sessionId: params?.sessionId }); toClient({ jsonrpc: "2.0", id, method, params }); });
  }

  async function fromAgent(msg) {
    if (msg.method === "session/update") {        // notification: keep the agent's latest words per session
      const u = msg.params?.update ?? {};
      const sid = msg.params?.sessionId;
      if (u.sessionUpdate === "agent_message_chunk" && u.content?.type === "text") intents.set(sid, (intents.get(sid) ?? "") + u.content.text);
      if (u.sessionUpdate === "tool_call") sessionRemember(sid, "calls", { tool: u.name ?? u.kind ?? "tool", preview: preview(u.rawInput ?? u.title ?? "", 100) });
    }
    if (msg.method && msg.id !== undefined) {   // request agent → client
      const rejection = await guardRequest(msg);
      if (rejection) return toAgent(rejection);
      agentReqs.set(msg.id, { method: msg.method, req: msg });
    }
    toClient(msg);
  }

  async function guardRequest(msg) {
    const p = msg.params ?? {};
    let tool, input, kind;
    if (msg.method === "terminal/create") { tool = "Bash"; input = { command: [p.command, ...(p.args ?? [])].join(" "), cwd: p.cwd }; kind = "execute"; }
    else if (msg.method === "fs/write_text_file") { tool = "Write"; input = { file_path: p.path, content: p.content }; kind = "edit"; }
    else return null;
    let d;
    const context = { sessionId: p.sessionId, intent: intents.get(p.sessionId)?.slice(-1500) };  // spec — the contract builds it
    try { d = await assess({ call: { tool, input, cwd: p.cwd, agent: "acp", sessionId: p.sessionId }, context }, opts); }
    catch (err) { warn(err); if (!failClosed(env)) return null; d = { verdict: "deny", message: `unjangled-guardrails unavailable: ${err.message}` }; }
    if (d) sessionRemember(p.sessionId, "calls", { tool, preview: preview(input, 100), level: d.verdict });
    if (d?.verdict === "allow") for (const created of agentCreatedPaths(tool, input, p.cwd)) sessionRememberCreated(p.sessionId, created);  // CAP-11: allowed creator calls record their paths
    if (!d || d.verdict === "allow") return null;
    if (d.verdict === "ask") {
      // The capture tier grows the gate-owned options array (story 4, CAP-1/R-4): a tier on
      // inserts the session option, tier project also the always option — both ACP v1 kind
      // allow_always, the remembered-decision scope named IN the option name (the spec's
      // rule; duplicate kinds are legal and optionId is an opaque string this proxy maps
      // back). Tier off keeps the byte-identical two-option shape. No client-side
      // persistence: memory ownership is the agent side, i.e. the gate store the mint writes.
      const tier = promptCaptureTier(env);
      const res = await askClient("session/request_permission", {
        sessionId: p.sessionId,
        toolCall: { toolCallId: `unjangled-guardrails-${seq + 1}`, title: `unjangled-guardrails: ${tool} ${preview(input)}`, kind, status: "pending", rawInput: input },
        options: [
          { optionId: "allow", name: "Allow once", kind: "allow_once" },
          ...(tier === "off" ? [] : [{ optionId: "session", name: "Allow for this session", kind: "allow_always" }]),
          ...(tier === "project" ? [{ optionId: "always", name: "Allow always", kind: "allow_always" }] : []),
          { optionId: "reject", name: "Reject", kind: "reject_once" },
        ],
      });
      const o = res?.result?.outcome;
      // A closed optionId→choice map: only an option the gate itself offered can proceed —
      // reject, cancelled, and every forged unknown optionId stay reject-once.
      const choice = o?.outcome === "selected" && Object.hasOwn(CAPTURE_CHOICES, o.optionId) ? CAPTURE_CHOICES[o.optionId] : undefined;
      if (choice) {
        try {
          // The core is the ceiling (a forged "always" under tier session still mints session
          // scope 24h; the per-session cap bounds the flood); a decline or a throw never
          // changes the ask outcome — the allow stands (adapter-guide §7).
          capturePromptRuling({ choice, harness: "acp", sessionId: p.sessionId, tool, input, cwd: p.cwd }, { env });
        } catch { /* a capture failure never changes the ask outcome: catch, proceed, surface nothing */ }
        return null;
      }
      d.message = `User rejected: ${d.message}`;
    }
    return { jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: d.message } };
  }

  async function fromClient(msg) {
    if (msg.method === "session/prompt") {       // the user's words, one entry per prompt; also resets the agent's running message
      const sid = msg.params?.sessionId;
      const text = (msg.params?.prompt ?? []).filter((b) => b?.type === "text").map((b) => b.text).join("\n");
      if (text.trim()) sessionRemember(sid, "prompts", { text: text.slice(0, 2000) });
      intents.set(sid, "");
    }
    if (msg.method === "session/cancel") {
      // The v1 session-end-ish signal the proxy sees (epic-prompt-rulings-session story 2):
      // the client abandoned the session. Two duties — every pending session/request_permission
      // for that session resolves cancelled (the ACP spec's answer-pending duty; the ask path
      // already treats a non-allow outcome as reject-once), and the session's prompt-captured
      // grants die in the store (expirePromptSession's scope discipline). The cancel itself
      // still forwards to the agent untouched below. A client that cancels mid-session loses
      // that session's prompt grants — extra asks later, never extra allows (accepted ACP v1
      // coarseness).
      const sid = msg.params?.sessionId;
      for (const [id, pending] of [...ours])
        if (pending.sessionId === sid) { ours.delete(id); pending.resolve({ result: { outcome: { outcome: "cancelled" } } }); }
      if (sid) {
        try { expirePromptSession(sid, env, { harness: "acp" }); }
        catch (err) { warn(err); }  // never block the forwarded cancel on a cleanup failure — the 24h cap holds
      }
    }
    if (msg.id !== undefined && !msg.method) {   // response client → agent
      const mine = ours.get(msg.id);
      if (mine) { ours.delete(msg.id); return mine.resolve(msg); }
      const hit = agentReqs.get(msg.id);
      agentReqs.delete(msg.id);
      if (hit?.method === "fs/read_text_file" || hit?.method === "terminal/output") await flagContent(msg, hit.method, hit.req);
    }
    toAgent(msg);
  }

  async function flagContent(msg, method, req) {
    const key = method === "fs/read_text_file" ? "content" : "output";
    const text = msg.result?.[key];
    if (typeof text !== "string") return;  // 5.7: no length floor — short results are scanned too
    const source = req?.params?.path ?? method;
    try {
      const r = source !== method && INSTRUCTION_FILE.test(source)
        ? await scanInstructions({ text, source }, opts)
        : await scan({ text, tool: method, source }, opts);
      if (r?.flagged) {
        sessionRemember(req?.params?.sessionId, "flags", { kind: r.kind, source, tool: method, p: +r.probability.toFixed(2), excerpt: excerpt(text), reported: true });
        msg.result[key] = `[${r.message}]\n\n${text}`;
      }
    } catch (err) { warn(err); }
  }

  pipe(child.stdout, fromAgent, warn);
  pipe(stdin, fromClient, warn);
  stdin.on("end", () => child.stdin.end());
  child.on("exit", (code) => onExit(code ?? 0));
  return child;
}

// Sequential per direction so message order survives the async checks.
function pipe(stream, handler, warn) {
  let chain = Promise.resolve();
  createInterface({ input: stream }).on("line", (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch { return warn(`non-JSON line dropped: ${line.slice(0, 80)}`); }
    chain = chain.then(() => handler(msg)).catch(warn);
  });
}
