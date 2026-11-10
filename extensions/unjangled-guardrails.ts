// pi extension: block/confirm dangerous tool calls, flag AI-directed text in tool results (Unjangled Guardrails).
// Load via the settings extensions path, or `unjangled-guardrails install pi`.
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
// Contract-only (entry 3, epic-adapter-seam): every core call routes through src/contract.js.
import { assess, scan, scanInstructions, failClosed, collectText, excerpt, INSTRUCTION_FILE, messagesFrom, sessionRead, sessionRemember, expirePromptSession, capturePromptRuling, promptCaptureTier, sessionRememberUserAnswer } from "../src/contract.js";

export default function (pi: ExtensionAPI) {
  const sessionId = (ctx: any) => ctx.sessionManager?.getSessionId?.();
  // CAP-4 (epic-github-field-reports entry 3): a sub-agent child carries its orchestrator's
  // session id in the process env (pi-subagents sets PI_SUBAGENT_ORCHESTRATOR_SESSION_ID on
  // every spawned child) — the harness-native parent link. Passing it as parentSessionId
  // relays the operator's own words from that session (its prompts bucket: directive, goal,
  // ask-user answers) into this session's user-words lane — live, read-only, informing the
  // brain's verdicts and minting nothing. Ephemeral children (no session of their own) get
  // their operator words only through this join; a plain top-level session has no env link
  // and is untouched.
  const relayParent = (own: string | undefined) => {
    const parent = process.env.PI_SUBAGENT_ORCHESTRATOR_SESSION_ID;
    return parent && parent !== own ? { parentSessionId: parent } : {};
  };
  const context = (ctx: any) =>
    ({ sessionId: sessionId(ctx), ...relayParent(sessionId(ctx)), messages: messagesFrom(ctx.sessionManager?.getBranch?.() ?? []) });  // spec — the contract builds it

  pi.on("session_shutdown", async (event: any, ctx: any) => {
    // The session runtime ends (reasons quit|new|resume|fork) — the session's prompt-captured
    // grants die with it (story 2, R-2). Reason "reload" is the one reason the SAME session
    // continues with fresh extension instances: firing there would kill grants mid-session,
    // so it is skipped. Ephemeral sessions (no id) have nothing attributed — the 24h cap holds.
    if (event?.reason === "reload") return;
    const sid = sessionId(ctx);
    if (!sid) return;
    try {
      expirePromptSession(sid, process.env, { harness: "pi" });
    } catch (err) {
      ctx.ui.notify(`Unjangled Guardrails: ${(err as Error).message}`, "warning");  // never throw on the session-end path
    }
  });

  pi.on("tool_call", async (event, ctx) => {
    let r;
    try {
      r = await assess({ call: { tool: event.toolName, input: event.input, cwd: ctx.cwd, agent: "pi", sessionId: sessionId(ctx) }, context: context(ctx) }, { signal: ctx.signal });
      if (r) sessionRemember(sessionId(ctx), "calls", { tool: event.toolName, preview: JSON.stringify(event.input).slice(0, 100), level: r.verdict });
    } catch (err) {
      ctx.ui.notify(`Unjangled Guardrails: ${(err as Error).message}`, "warning");
      return failClosed() ? { block: true, reason: `jev-guard unavailable: ${(err as Error).message}` } : undefined;
    }
    if (!r || r.verdict === "allow") return;
    if (r.verdict === "deny") return { block: true, reason: r.message };
    if (!ctx.hasUI) return { block: true, reason: `${r.message} (no UI to ask for approval, so blocked)` };
    if (promptCaptureTier(process.env) === "off") {
      const ok = await ctx.ui.confirm("Unjangled Guardrails: approve this tool call?", r.message);
      if (!ok) return { block: true, reason: `User rejected: ${r.message}` };
      return;
    }
    // The capture surface (story 3, CAP-1): the ask grows the four options when a tier is on.
    // select has no body param, so the ask message rides the title (the upstream
    // permission-gate pattern); the chosen label maps to the capture export — the core is
    // the ceiling (tier session keeps always session-scoped; tier project maps always to
    // project:<cwd>). Reject, cancel, and any unknown label keep today's outcome.
    const label = await ctx.ui.select(`Unjangled Guardrails: approve this tool call?\n\n${r.message}`,
      ["Allow once", "Allow for this session", "Allow always", "Reject"]);
    if (label !== "Allow once" && label !== "Allow for this session" && label !== "Allow always")
      return { block: true, reason: `User rejected: ${r.message}` };
    try {
      capturePromptRuling({
        choice: label === "Allow once" ? "once" : label === "Allow for this session" ? "session" : "always",
        harness: "pi", sessionId: sessionId(ctx), tool: event.toolName, input: event.input, cwd: ctx.cwd,
      }, { env: process.env });
    } catch { /* a capture failure never changes the ask outcome: the allow-once stands (adapter-guide §7) */ }
  });

  pi.on("tool_result", async (event, ctx) => {
    let r;
    try {
      const source = (event.input as any)?.url ?? (event.input as any)?.path;
      const text = collectText(event.content);
      // CAP-2 (entry 2): an ask-user tool's result is the operator's own typed answer —
      // user-words lane first (the scan below returns null for the ask-user family).
      sessionRememberUserAnswer(sessionId(ctx), event.toolName, text);
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
