// pi extension: block/confirm dangerous tool calls, flag AI-directed text in tool results (Unjangled Guardrails).
// Load via the settings extensions path, or `unjangled-guardrails install pi`.
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
// Contract-only (entry 3, epic-adapter-seam): every core call routes through src/contract.js.
import { assess, scan, scanInstructions, failClosed, collectText, excerpt, INSTRUCTION_FILE, messagesFrom, sessionRead, sessionRemember } from "../src/contract.js";

export default function (pi: ExtensionAPI) {
  const sessionId = (ctx: any) => ctx.sessionManager?.getSessionId?.();
  const context = (ctx: any) =>
    ({ sessionId: sessionId(ctx), messages: messagesFrom(ctx.sessionManager?.getBranch?.() ?? []) });  // spec — the contract builds it

  pi.on("tool_call", async (event, ctx) => {
    let r;
    try {
      r = await assess({ call: { tool: event.toolName, input: event.input, cwd: ctx.cwd, agent: "pi", sessionId: ctx.sessionID }, context: context(ctx) }, { signal: ctx.signal });
      if (r) sessionRemember(sessionId(ctx), "calls", { tool: event.toolName, preview: JSON.stringify(event.input).slice(0, 100), level: r.verdict });
    } catch (err) {
      ctx.ui.notify(`Unjangled Guardrails: ${(err as Error).message}`, "warning");
      return failClosed() ? { block: true, reason: `jev-guard unavailable: ${(err as Error).message}` } : undefined;
    }
    if (!r || r.verdict === "allow") return;
    if (r.verdict === "deny") return { block: true, reason: r.message };
    if (!ctx.hasUI) return { block: true, reason: `${r.message} (no UI to ask for approval, so blocked)` };
    const ok = await ctx.ui.confirm("Unjangled Guardrails: approve this tool call?", r.message);
    if (!ok) return { block: true, reason: `User rejected: ${r.message}` };
  });

  pi.on("tool_result", async (event, ctx) => {
    let r;
    try {
      const source = (event.input as any)?.url ?? (event.input as any)?.path;
      const text = collectText(event.content);
      r = source && INSTRUCTION_FILE.test(source)
        ? await scanInstructions({ text, source }, { signal: ctx.signal })
        : await scan({ text, tool: event.toolName, source, task: sessionRead(sessionId(ctx)).prompts.at(-1)?.text }, { signal: ctx.signal });
      if (r?.flagged) sessionRemember(sessionId(ctx), "flags", { kind: r.kind, source, tool: event.toolName, p: +r.probability.toFixed(2), excerpt: excerpt(text), reported: true });
    } catch (err) {
      ctx.ui.notify(`Unjangled Guardrails: ${(err as Error).message}`, "warning");
      return;
    }
    if (!r?.flagged) return;
    ctx.ui.notify(r.message, "warning");
    return { content: [{ type: "text", text: `[${r.message}]` }, ...event.content] };
  });
}
