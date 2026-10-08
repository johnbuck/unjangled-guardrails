// OpenCode plugin. `unjangled-guardrails install opencode` drops a one-line shim into ~/.config/opencode/plugins/ that re-exports this.
// tool.execute.before throws to block; permission.ask (only fires for tools you set to "ask" in opencode.json)
// lets unjangled-guardrails auto-approve the safe calls and keep the prompt for the risky ones; tool.execute.after flags results.
// Contract-only (entry 3, epic-adapter-seam): every core call routes through src/contract.js.
// vendor/guardrails-core is upstream-vendored engine code, not fork core — outside the lint's scope.
import {
  assess, scan, scanInstructions, failClosed, askBlocked,
  preview, excerpt, INSTRUCTION_FILE, messagesFrom, sessionRead, sessionRemember,
} from "./contract.js";
import { SECRET_SHAPE } from "../vendor/guardrails-core/rules.mjs";

export const UnjangledGuardrails = async ({ client, directory }) => {
  // vendored guardrails nudge state: once per session per rule
  const nudged = new Map();
  const nudge = async (sessionID, rule, humanMsg, modelNote, output) => {
    const s = nudged.get(sessionID) || new Set();
    if (s.has(rule)) return;
    s.add(rule); nudged.set(sessionID, s);
    if (output) output.output = `${output.output || ""}\n\n[Unjangled Guardrails] ${modelNote}`;
    toast(humanMsg);
  };
  const toast = (message, variant = "warning") =>
    client?.tui?.showToast?.({ body: { title: "Unjangled Guardrails", message, variant, duration: 8000 } }).catch(() => {});
  const audit = (outcome, rule) => {
    try { client?.app?.log?.({ body: { service: "unjangled-guardrails", level: "warn", message: `${outcome} ${rule}` } }) } catch {}
  };
  const failOpen = (err) => {
    toast(err.message, "error");
    if ((process.env.GUARD_FALLBACK ?? process.env.JEV_GUARD_FALLBACK) === "closed" || failClosed(process.env)) throw new Error(`Unjangled Guardrails unavailable: ${err.message}`);
    return null;
  };

  // The session's messages, via the SDK; empty when the server can't be reached. Returned as a
  // contract ConversationContextSpec — the contract builds it (assessment-time, like before).
  const context = async (sessionID) => {
    const res = await client?.session?.messages?.({ path: { id: sessionID } }).catch(() => null);
    return { sessionId: sessionID, messages: messagesFrom(res?.data ?? []) };
  };

  return {
    "tool.execute.before": async (input, output) => {
      const d = await assess({ call: { tool: input.tool, input: output.args, cwd: directory, agent: "opencode", sessionId: input.sessionID }, context: await context(input.sessionID) }).catch(failOpen);
      if (d) sessionRemember(input.sessionID, "calls", { tool: input.tool, preview: preview(output.args, 100), level: d.verdict });
      if (!d || d.verdict === "allow") return;
      if (d.verdict === "deny") throw new Error(d.message);
      // Ask-band: the conversation loop is the prompt on OpenCode (the permission.ask hook
      // is dead code in 1.18.31 — never triggered). Block with the ask message; the agent
      // tells the user what it wants; the user approves in conversation; the retry passes
      // because user_requested >= 0.85 (the question-wording fix makes this work).
      toast(d.message);
      throw new Error(d.message);
    },

    "permission.ask": async (input, output) => {
      // NOTE: the permission.ask hook is dead code on OpenCode 1.18.31 — the trigger is never
      // dispatched (confirmed by binary analysis; upstream issues #7006 and #9229). This handler
      // is kept for forward compatibility: when upstream wires it, it will auto-allow safe calls,
      // keep the prompt for ask-band, and deny dangerous ones. On the current version it is inert.
      // pattern carries the command text: preview it as `command` so ruling globs and the brain judge the call, not the wrapper object
      const args = { ...(input.metadata ?? {}), command: input.pattern, title: input.title };
      const d = await assess({ call: { tool: input.type, input: args, cwd: directory, agent: "opencode", sessionId: input.sessionID }, context: await context(input.sessionID) }).catch(failOpen);
      if (!d) { output.status = "allow"; return; }
      output.status = d.verdict;  // allow → no prompt, ask → prompt, deny → refused
      if (d.verdict !== "allow") toast(d.message);
    },

    "tool.execute.after": async (input, output) => {
      const source = input.args?.url ?? input.args?.filePath ?? input.args?.path;
      const instructions = /^skill$/i.test(input.tool ?? "") || (source && INSTRUCTION_FILE.test(source));  // skill passes {name}, no path
      const r = await (instructions
        ? scanInstructions({ text: output.output, source: source ?? input.args?.name ?? input.tool })
        : scan({ text: output.output, tool: input.tool, source: preview(input.args, 120), task: sessionRead(input.sessionID).prompts.at(-1)?.text })
      ).catch(() => null);
      if (r?.flagged) sessionRemember(input.sessionID, "flags", { kind: r.kind, source, tool: input.tool, p: +r.probability.toFixed(2), excerpt: excerpt(output.output), reported: true });
      if (r?.flagged) { toast(r.message); output.output = `[${r.message}]\n\n${output.output}`; }

      // ── vendored guardrails nudges (host pollution, secret-shaped writes) ──
      const args = input.args ?? {};
      if (input.tool === "bash") {
        const cmd = args.command || "";
        const npmGlobal = /\bnpm\s+(?:i|install)\b[^\n]*(?:\s-g\b|--global)/.test(cmd);
        const pipBare = /\bpip[\d.]*\s+install\b/.test(cmd) && !/-r\s|\bvenv\b|\.venv/.test(cmd) && !process.env.VIRTUAL_ENV;
        if (npmGlobal || pipBare) {
          audit("nudge", "host-pollution");
          await nudge(input.sessionID, "host-pollution",
            "That install may change the whole computer. Ask me to set it up inside the project instead.",
            "That install may land on the host. Prefer a container or a project-local environment.",
            output);
        }
      } else if (["write", "edit", "apply_patch"].includes(input.tool)) {
        const content = args.content || args.newString || args.patchText || "";
        const target = args.filePath || (args.patchText || "").match(/^\*\*\* (?:Add|Update|Delete|Move to) File:\s*(.+)$/m)?.[1]?.trim() || "";
        const isEnvFile = /(^|\/)\.env(\.[^/]*)?$/.test(target);
        if (!isEnvFile && SECRET_SHAPE.some((rx) => rx.test(content))) {
          audit("nudge", "secret-shape");
          await nudge(input.sessionID, "secret-shape",
            "A file looked like it holds a password or key. Keys should live in the secret store, not in code.",
            "A write looked secret-shaped. Keep keys in env or Infisical, never in code or git.",
            output);
        }
      }
    },

    // ── vendored guardrails: commit hygiene on idle, state cleanup ──
    event: async ({ event }) => {
      if (event.type === "session.deleted") { nudged.delete(event.properties?.sessionID); return }
      if (event.type !== "session.idle") return;
      const sessionID = event.properties?.sessionID;
      if (!sessionID || nudged.get(sessionID)?.has("commit")) return;
      if (!client?.$ || !directory) return;
      let dirty = "";
      try { dirty = (await Promise.race([client.$`git -C ${directory} status --porcelain`.quiet().text(), new Promise((_, rej) => setTimeout(() => rej(new Error("git status timeout")), 2000))])).trim() } catch { return }
      if (!dirty) return;
      const s = nudged.get(sessionID) || new Set(); s.add("commit"); nudged.set(sessionID, s);
      toast("Uncommitted changes: commit each change on its own with a clear message, or type /undo to roll back.", "info");
      try { await client.session.prompt({ path: { id: sessionID }, body: { parts: [{ type: "text", text: "Guardrails note: there are uncommitted changes. Commit each logical change atomically with a short clear message before moving on." }], noReply: true } }) } catch {}
    },
  };
};

// ── v2 surface (skeleton, dual-entry ticket 3): the v2.0.24 loader accepts a default definition
// with an id and an effect or setup function; this module uses the setup form, package-free
// (@opencode/plugin does not resolve from the scanned plugins dir — probe shapes d/g,
// evidence/opencode-v2-plugin-loading-probe-2026-10-07.md). The skeleton registers NO hooks —
// setup stores the loader context for epic-v2-adapter's wiring and does nothing else. The band
// contract the v2 mapping will cite is VERDICTS in src/contract.js.
//
// The context is parked OFF the exported shape: a module-level slot captured by setup and read
// back through the getV2Context named accessor (an accessor, not a surface — epic-v2-adapter
// consumes it when wiring hooks), so Object.keys of the export stays exactly ["id", "setup"]
// after setup runs.
let v2Context = null;
export const UnjangledGuardrailsV2 = {
  id: "unjangled-guardrails",
  setup(ctx) { v2Context = ctx; },
};
export const getV2Context = () => v2Context;

// ponytail: no default export at module level on purpose. OpenCode 1.x's older loader treats every
// export as a plugin function and throws on an object, so the v1 shim re-exports ONLY the named
// function (extra named exports here never reach that loader — it judges the shim's exports, not
// the module's). Loader note corrected by the v2.0.24 probe: the earlier "a single named function
// loads in both" is REFUTED for v2, which requires a default definition with an id and an effect
// or setup function and rejects a named re-export (SchemaError(Missing key at ["default"])).
// One module, two surfaces;
// the per-host shim content is chosen at install time (entry 4): the v1 shim keeps the named
// re-export of UnjangledGuardrails, the v2 shim default-exports UnjangledGuardrailsV2.
