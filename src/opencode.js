// OpenCode plugin. `unjangled-guardrails install opencode` drops a one-line adapter into ~/.config/opencode/plugins/ that re-exports this.
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
      // because user_requested >= 0.75 (the question-wording fix + 2026-10-16 bar cut make this work).
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

// ── v2 surface (epic-v2-adapter): the v2.0.24 loader accepts a default definition with an id
// and an effect or setup function; this module uses the setup form, package-free
// (@opencode/plugin does not resolve from the scanned plugins dir — probe shapes d/g,
// evidence/opencode-v2-plugin-loading-probe-2026-10-07.md). Setup stores the loader context
// off the exported shape and registers the tool hooks — execute.before, the gating hook
// (ticket 2), and execute.after, the output scans + nudges (ticket 3) — and the permission
// hook, permission.evaluate, the ask-band routing (ticket 4, the registration below).
//
// Gating (ticket 2): `ctx.tool.hook("execute.before")` maps the hook event onto the same
// assess call shape as the v1 tool.execute.before dispatch, then splits on the VERDICTS bands
// (src/contract.js):
//   deny  → veto by THROWING new Error(d.message). Throw is the only veto mechanism on
//           v2.0.24 (epic Decision 2026-10-09, probe runs r1–r4b2 in
//           evidence/opencode-v2-hook-semantics-probe-2026-10-09.md): the thrown message
//           reaches the model verbatim and the veto preempts permission.evaluate and
//           execute.after; mutating the event is a rewrite (not a veto) and veto-shaped
//           keys or return values are inert.
//   allow → return; the call runs.
//   ask   → DEFER: return WITHOUT vetoing. Unlike v1 — whose conversation loop was the
//           prompt — v2 owns a permission flow: the untouched ask effect falls through to
//           permission.evaluate, which the evaluate hook below routes (safe→allow,
//           risky→the host's real permission prompt). The band map cites VERDICTS; the ask
//           band is a held verdict here, not the v1 ask-blocked deny.
// Context: v1 fetched the session transcript via client.session.messages. The hook event
// carries no transcript (event fields: tool, sessionID, agent, messageID, id, input), so the
// payload omits context — the contract treats an absent context as valid (AD-1). The ctx
// session dump (probe r0) names no `messages` method, but ctx.session.get and
// ctx.session.context were never invoked by the probe — "no transcript reachable" is
// unconfirmed, not established. Ticket 4 (permission.evaluate) left those two surfaces
// unprobed as well; the context-free payload stands, still unconfirmed-not-established.
//
// Scans + nudges (ticket 3): `ctx.tool.hook("execute.after")` ports the v1
// tool.execute.after dispatch onto the probe-observed v2 event shape. The event carries
// {tool, sessionID, agent, messageID, id, input, status, result} (spike r5 EVA marker line,
// evidence/opencode-v2-hook-semantics-probe-2026-10-09.md), and the result is
// {output:{exit,truncated,output,status}, content:[{type:"text",text}], metadata:{…}}.
// Errored calls carry `error` and NO `result` — a permission-denied call still arrives here
// with status:"error" (spike runs r6/r8) — so the hook bails when the result is absent.
// Two probe-proven facts shape the port (epic Decisions 2026-10-09; runs r0/r5/r5b/r5c):
//   rewrite — the annotation reaches the model ONLY by reassigning the event's result with
//             BOTH result.output.output AND result.content[0].text mutated (the persisted
//             tool part and the model reply both carried the probe marker); metadata-only
//             or top-level rewrites do not surface.
//   notice  — the v2 setup ctx has NO toast surface (r0 deep scan: zero hits), so the v1
//             toast() degrades to ctx.session.synthetic({sessionID, text}) — steer-delivered
//             and model-visible (r0/r8) — wrapped in try/catch: a notice failure never
//             breaks the hook.
// Ported v1 logic (tool "shell" is the v2 spelling of v1's "bash" — probe-observed): the
// skill tool or an INSTRUCTION_FILE source → scanInstructions, else scan({text, tool,
// source, task}); flagged → flags-bucket record + the annotation prefix on both text
// fields; secret-shape (SECRET_SHAPE on write/edit/apply_patch content, .env files exempt)
// and host-pollution (npm -g / bare pip) nudges, once per session per rule. v1's
// `event`-hook behaviors, each with its disposition here so nothing is silently dropped:
// the session.deleted nudge-state cleanup IS ported (ctx.event.subscribe, best-effort —
// see the registration below), while v1's audit() (client.app.log; no v2 surface) and the
// commit-hygiene session.idle nudge (v2 event wiring is a separate concern) are NOT
// ported — both remain epic-v2-adapter follow-ups.
//
// The loader context is parked OFF the exported shape: a module-level slot captured by setup
// and read back through the getV2Context named accessor (an accessor, not a surface), so
// Object.keys of the export stays exactly ["id", "setup"] after setup runs.
//
// Runtime coexistence detection (epic-host-isolation ticket 2): setup positively signals its
// own entry — one console line, the load proof (setup entered, ctx stored) — and scans the two
// plugin dirs the v2 loader reads (probe Q1/run 4: BOTH are scanned, dedupe by plugin id) for
// a sibling v1-shaped adapter. v2 REJECTS that shape at load with a WARN that only reaches the
// v2 log, never stdout (probe shape a: SchemaError(Missing key at ["default"])), so in-band
// the gate "looks missing" with no pointer to the fix. Detection is read-only and shallow —
// the first 2048 bytes of each *.js, matched against the install.js generation fingerprint
// (adapterGeneration: v1 = the named UnjangledGuardrails re-export with NO default export) —
// never a reimplementation of the loader. Channels (the r0 ctx dump exposes no setup-time
// notice surface — synthetic needs a sessionID): console.warn at setup is a ZERO-COST HEDGE
// only — the same-day bwrap probe (2026-10-12) caught plugin console swallowed on 2.0.24 run
// mode — while the synthetic guidance is the channel that DELIVERS, ONCE, on the first
// session event the adapter sees — execute.before, the earliest hook proven to fire for
// every call with a sessionID (probe r6: it fires even when permission settles the call; a
// ctx.event.subscribe topic for session start is unprobed, so no notice rides a guessed
// topic string).
import { readdirSync, openSync, readSync, closeSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
let v2Context = null;
export const UnjangledGuardrailsV2 = {
  id: "unjangled-guardrails",
  setup(ctx) {
    v2Context = ctx;

    // ── runtime coexistence detection (epic-host-isolation ticket 2, design in the block
    // comment above) ── the positive entry signal, then the sibling-adapter scan.
    console.log("[Unjangled Guardrails] v2 adapter active: setup entered, ctx stored (id unjangled-guardrails).");
    let coexistence = null;  // truthy = the pending synthetic guidance, first sessionID only
    try {
      const found = [];
      for (const dir of [
        join(process.env.GUARD_HOME ?? homedir(), ".config", "opencode", "plugins"),
        join(process.env.GUARD_HOME ?? homedir(), ".opencode", "plugins"),
      ]) {
        let names;
        try { names = readdirSync(dir); } catch { continue; }  // a missing/unreadable dir must not hide the other one
        for (const name of names) {
          if (!name.endsWith(".js")) continue;
          // plain read semantics, like the installer's detectOwnership: symlinks are
          // followed, and a missing/unreadable target (a directory named *.js, a dead
          // link) just skips the file; only the FIRST 2048 BYTES are read
          let head;
          try {
            const buf = Buffer.alloc(2048);
            const fd = openSync(join(dir, name), "r");
            try { head = buf.toString("utf8", 0, readSync(fd, buf, 0, 2048, 0)); } finally { closeSync(fd); }
          } catch { continue; }
          // the install.js generation fingerprint: v1 = the named UnjangledGuardrails
          // re-export, no default (a default present ⇒ v2-shaped, not flagged)
          if (!/^\s*export\s+default\b/m.test(head) && /export\s*\{\s*UnjangledGuardrails\s*\}/.test(head)) found.push(join(dir, name));
        }
      }
      if (found.length) {
        coexistence = `[Unjangled Guardrails] An old v1 plugin adapter for this guard is still installed (${found.join(", ")}). OpenCode v2 rejects it at load, so it guards nothing here; this v2 adapter is the active guard. Remove the v1 adapter, or resolve the install with \`unjangled-guardrails install opencode --v2 --force\`.`;
        console.warn(`[Unjangled Guardrails] coexistence: v1-shaped plugin adapter at ${found.join(", ")} — v2 rejected it at load ("Missing key at [\"default\"]", WARN in this log only, silent in-band); this v2 adapter IS the active guard. Remove the v1 adapter, or resolve the install with \`unjangled-guardrails install opencode --v2 --force\`.`);
      }
    } catch { /* best-effort: an unreadable plugin tree must never break setup */ }
    // vendored guardrails nudge state: once per session per rule (v1 parity)
    const nudged = new Map();
    // The v1 toast's v2 mapping (probe r0/r8): steer-delivered into the live session,
    // best-effort — sync throws and rejections are both swallowed so a notice failure
    // never breaks the hook.
    const notify = (sessionID, text) => {
      try { ctx.session?.synthetic?.({ sessionID, text })?.catch?.(() => {}); } catch {}
    };
    // Annotate the model-visible result and REASSIGN the event's result — the only rewrite
    // the probe proved reaches the model (epic Decision 2026-10-09, runs r5/r5b/r5c): BOTH
    // result.output.output AND result.content[0].text must carry it; metadata-only or
    // top-level rewrites do not surface. `prefix` puts the note before the text (the v1
    // flagged-scan shape); otherwise it appends (the v1 nudge shape). A missing field is
    // skipped; non-string fields are left alone.
    const annotate = (ev, note, prefix = false) => {
      const result = ev.result;
      if (!result) return;
      const wrap = (text) => (prefix ? note + text : text + note);
      if (typeof result.output?.output === "string") result.output.output = wrap(result.output.output);
      if (typeof result.content?.[0]?.text === "string") result.content[0].text = wrap(result.content[0].text);
      ev.result = result;
    };
    const nudge = (ev, rule, humanMsg, modelNote) => {
      const s = nudged.get(ev.sessionID) || new Set();
      if (s.has(rule)) return;
      s.add(rule); nudged.set(ev.sessionID, s);
      annotate(ev, `\n\n[Unjangled Guardrails] ${modelNote}`);
      notify(ev.sessionID, humanMsg);
    };
    // v1 parity: nudge state is per-session and is freed on session.deleted (v1's `event`
    // hook did this; dropping it would grow the map for the process lifetime). The surface
    // exists on v2 — ctx.event.subscribe is in the recorded r0 ctx dump
    // (evidence/opencode-v2-hook-semantics-probe-2026-10-09.md §c) and the "session.deleted"
    // topic string is in the 2.0.24 binary — but the subscribe call shape and the event
    // payload are unprobed, so the registration and the handler are both best-effort: the
    // try/catch keeps a subscribe failure from breaking setup, and the handler clears under
    // every plausible payload shape (v1's {event:{properties:{sessionID}}}, a flat
    // {sessionID}, or a properties.info.id) instead of guessing one.
    try {
      ctx.event?.subscribe?.("session.deleted", (ev) => {
        nudged.delete(ev?.properties?.sessionID ?? ev?.sessionID ?? ev?.properties?.info?.id);
      })?.catch?.(() => {});
    } catch {}

    // v1 failOpen parity, minus the toast (the v2 ctx has no toast surface — the notice
    // decision is ticket 3's): fail open by default, fail closed on GUARD_FALLBACK=closed.
    // Shared by both assess call sites — the execute.before gating hook and the
    // permission.evaluate callback — so the closed-posture switch cannot drift apart.
    const failOpen = (err) => {
      if ((process.env.GUARD_FALLBACK ?? process.env.JEV_GUARD_FALLBACK) === "closed" || failClosed(process.env))
        throw new Error(`Unjangled Guardrails unavailable: ${err.message}`);
      return null;
    };

    ctx.tool.hook("execute.before", async (ev) => {
      // coexistence guidance (ticket 2): the pending synthetic fires once — the first event
      // carrying a sessionID — and only after a real attempt is notify-swallowed failures
      // a lost notice (the flag clears with the attempt, per the once-per-boot design).
      if (coexistence && ev.sessionID) { const guidance = coexistence; coexistence = null; notify(ev.sessionID, guidance); }
      const d = await assess({
        call: { tool: ev.tool, input: ev.input, cwd: ctx.location?.directory, agent: "opencode", sessionId: ev.sessionID },
      }).catch(failOpen);
      if (d) sessionRemember(ev.sessionID, "calls", { tool: ev.tool, preview: preview(ev.input, 100), level: d.verdict });
      if (!d || d.verdict === "allow") return;
      if (d.verdict === "deny") throw new Error(d.message);
      return;  // ask: defer to v2's permission flow (ticket 4's evaluate hook) — never a veto
    });

    // Output scans + nudges (ticket 3): the v1 tool.execute.after dispatch mapped onto the
    // v2 event (event and result shapes, the rewrite rule, and the notice mapping are cited
    // in the block comment above).
    ctx.tool.hook("execute.after", async (ev) => {
      const result = ev.result;
      if (!result) return;  // errored calls carry `error`, no result (probe r6/r8) — nothing to scan
      const text = typeof result.output?.output === "string" ? result.output.output
        : typeof result.content?.[0]?.text === "string" ? result.content[0].text : "";
      const source = ev.input?.url ?? ev.input?.filePath ?? ev.input?.path;
      const instructions = /^skill$/i.test(ev.tool ?? "") || (source && INSTRUCTION_FILE.test(source));  // skill passes {name}, no path
      const r = await (instructions
        ? scanInstructions({ text, source: source ?? ev.input?.name ?? ev.tool })
        : scan({ text, tool: ev.tool, source: preview(ev.input, 120), task: sessionRead(ev.sessionID).prompts.at(-1)?.text })
      ).catch(() => null);  // v1 parity: a scan failure never blocks the tool output
      if (r?.flagged) {
        sessionRemember(ev.sessionID, "flags", { kind: r.kind, source, tool: ev.tool, p: +r.probability.toFixed(2), excerpt: excerpt(text), reported: true });
        annotate(ev, `[${r.message}]\n\n`, true);
        notify(ev.sessionID, r.message);
      }

      // ── vendored guardrails nudges (host pollution, secret-shaped writes) ──
      const args = ev.input ?? {};
      if (ev.tool === "bash" || ev.tool === "shell") {  // "shell" is the v2 spelling (probe-observed)
        const cmd = args.command || "";
        const npmGlobal = /\bnpm\s+(?:i|install)\b[^\n]*(?:\s-g\b|--global)/.test(cmd);
        const pipBare = /\bpip[\d.]*\s+install\b/.test(cmd) && !/-r\s|\bvenv\b|\.venv/.test(cmd) && !process.env.VIRTUAL_ENV;
        if (npmGlobal || pipBare) {
          nudge(ev, "host-pollution",
            "That install may change the whole computer. Ask me to set it up inside the project instead.",
            "That install may land on the host. Prefer a container or a project-local environment.");
        }
      } else if (["write", "edit", "apply_patch"].includes(ev.tool)) {
        const content = args.content || args.newString || args.patchText || "";
        const target = args.filePath || args.path || (args.patchText || "").match(/^\*\*\* (?:Add|Update|Delete|Move to) File:\s*(.+)$/m)?.[1]?.trim() || "";  // v2 spells the write target `path` (probe s2)
        const isEnvFile = /(^|\/)\.env(\.[^/]*)?$/.test(target);
        if (!isEnvFile && SECRET_SHAPE.some((rx) => rx.test(content))) {
          nudge(ev, "secret-shape",
            "A file looked like it holds a password or key. Keys should live in the secret store, not in code.",
            "A write looked secret-shaped. Keep keys in env or Infisical, never in code or git.");
        }
      }
    });

    // Permission evaluate (ticket 4): routes the ask band the before-hook defers. The v2
    // dispatcher calls this for every call its configured rules do not SETTLE: an
    // unconfigured call arrives with the built-in base policy's effect:"allow" (spike r0 —
    // there is no true "no rule" state), a configured ask with effect:"ask" (r7/r8), while
    // a CONFIGURED DENY never reaches the callback at all — v2's own pre-check blocks the
    // call and fails with Permission.BlockedError carrying the ruleset (r6). Deny-final is
    // v2's guarantee, not ours to enforce: this callback can only ever rewrite TOWARD
    // allow; ask and deny effects pass through untouched.
    // Mapping (AssertInput → contract): call.tool = action; the resources carry the
    // command/paths the call acts on, so they ride input.command (joined — one command per
    // call in the probed shape) next to the raw array, mirroring how the before-hook maps
    // ev.input so the brain judges the real call.
    // Bands (VERDICTS, src/contract.js): allow → ev.effect = "allow", the r7-proven
    // rewrite (honored end-to-end: the ask-rule call ran); ask → untouched, v2's native
    // permission flow owns the prompt (a bare `run` auto-rejects an untouched ask with
    // Permission.CorrectedError instead of stalling — r8; the real prompt surface is the
    // ACP client); deny → untouched (defense in depth — the before-hook already vetoed a
    // contract deny, and a configured deny never arrives here, r6). Fail-open parity with
    // the before-hook: no verdict → the effect stays untouched (the harness default
    // applies); GUARD_FALLBACK=closed rethrows (the closed posture's real veto is the
    // before-hook throw — r1 — which preempts permission entirely; a throw from inside
    // this callback is an unprobed v2 surface).
    ctx.permission.hook("evaluate", async (ev) => {
      const resources = Array.isArray(ev.resources) ? ev.resources : [];
      // MCP calls arrive with the wildcard resource ["*"] (probe m1) — no real command to
      // judge, so no assess: no verdict → the harness default applies (the call arrived
      // with an effect already).
      const judgeable = resources.length > 0 && !(resources.length === 1 && resources[0] === "*");
      // Write-shaped actions carry the target as resources[0]; feeding it back as input.path
      // lets the write-content floors see the target path (the credential-shaped-target check
      // and the .env-file exemption in the secret-shape leg key on it).
      const input = { command: resources.join("\n"), resources };
      if (/^(write|edit|apply_patch|notebook)$/i.test(ev.action ?? "")) input.path = resources[0];
      const d = judgeable
        ? await assess({
        call: { tool: ev.action, input, cwd: ctx.location?.directory, agent: "opencode", sessionId: ev.sessionID },
      }).catch(failOpen)
        : null;
      if (d) sessionRemember(ev.sessionID, "calls", { tool: ev.action, preview: preview(ev.resources, 100), level: d.verdict });
      // Null from a JUDGED call = the GUARD_SKIP_TOOLS escape (the consolidated gate judges
      // everything else — no skip classes remain; brain failures never produce null in open
      // mode, the degraded floor returns a real verdict). Honor the standing allow: rewrite
      // to allow so an operator's bash:ask rule does not prompt for skip-listed calls (the
      // cross-story reconciliation with epic-ask-band-posture, epic Notes 2026-10-10).
      // Fail-safe caveat: if a future skip class is added that is NOT a deliberate standing
      // allow, this rewrite would auto-allow it — the enumeration in guard.js assessAction
      // is the control point. Null from an UNJUDGED call (wildcard/empty resources — MCP
      // shape, probe m1) is different: nothing decided anything, so the incoming effect is
      // left untouched — the harness default applies, and a configured ask on an MCP tool
      // still prompts.
      if (!d) { if (judgeable) ev.effect = "allow"; return; }
      if (d.verdict !== "allow") return;  // ask → v2's flow; deny → untouched (deny-final, r6)
      ev.effect = "allow";  // the r7-proven rewrite: honored end-to-end, the call runs
    });
  },
};
export const getV2Context = () => v2Context;

// ponytail: no default export at module level on purpose. OpenCode 1.x's older loader treats every
// export as a plugin function and throws on an object, so the v1 adapter re-exports ONLY the named
// function (extra named exports here never reach that loader — it judges the adapter's exports, not
// the module's). Loader note corrected by the v2.0.24 probe: the earlier "a single named function
// loads in both" is REFUTED for v2, which requires a default definition with an id and an effect
// or setup function and rejects a named re-export (SchemaError(Missing key at ["default"])).
// One module, two surfaces;
// the per-host adapter content is chosen at install time (entry 4): the v1 adapter keeps the named
// re-export of UnjangledGuardrails, the v2 adapter default-exports UnjangledGuardrailsV2.
