// The Adapter Contract — the ONLY surface the core exposes to adapter code (AD-1, spec CAP-2).
// Adapters translate their harness's native surface into these payloads and consume these
// decisions; they never call deeper core modules (enforced by test/contract.test.js —
// the import lint starts as a documented allowlist and entry 3 shrinks it to contract-only).
//
// Versioning — CONTRACT_VERSION is SemVer over this module's contract surface:
//   PATCH: wording/docs only, no shape change.
//   MINOR: additive change — a new optional payload field, a new decision or scan-result
//          field, or a new exported helper. Consumers must ignore fields they don't know;
//          producers must never require a field they didn't declare at their own version.
//   MAJOR: removing or renaming a field, changing a field's type, changing the verdict
//          enum, or changing fail-safe semantics (AD-2).
// Adapters record the version they were written against and refuse to run against a
// different MAJOR; MINOR mismatches are logged, not fatal.
//
// AD-2 (verdict taxonomy as data): exactly three verdicts — deny, ask, allow. An ask maps
// to deny where the host has no prompt surface (askBlocked); context-leak verdicts are
// denies everywhere; unknown shapes resolve toward the safe side. No adapter reinvents
// verdict semantics per dialect.
import { assessAction, scanContent, askBlockedDeny, INSTRUCTION_FILE, MIN_SCAN_CHARS, excerpt, collectText, preview } from "./guard.js";
import { buildContext, messagesFrom } from "./context.js";
import { readSession, remember, update, markReported } from "./session.js";
import { findInstructionFiles, projectRoots, scanFiles, scanInstructionsCached } from "./skills.js";
import { failClosed } from "./orchestrate.js";

/**
 * Contract version. See the compat rules in the module header. Bump MINOR on any
 * additive change; MAJOR on any removal/renaming/type change/enum change.
 * 1.1.0 (entry 3, epic-adapter-seam): additive adapter-support surface — the helper
 * exports below let every adapter import through the contract alone (the import lint
 * is now contract-only). No existing field or shape changed.
 * @type {"1.1.0"}
 */
export const CONTRACT_VERSION = "1.1.0";

/**
 * The complete verdict enum (AD-2). Frozen: adapters must not extend or reinterpret it.
 *
 * The verdict-band contract: `VERDICTS` is the shared vocabulary every host surface maps
 * onto — a v2 builder must not invent a second one. The 1.x dispatch already maps onto
 * exactly these three bands (src/opencode.js tool.execute.before: deny → throw, ask →
 * ask-band fallback — throw with the ask message and let the conversation loop be the
 * prompt, allow → return); citing `VERDICTS` is the requirement for the future v2
 * mappings (epic-v2-adapter), which must translate host-native outcomes onto these bands.
 * `askBlocked` is the one defined translation between bands: an ask where the host has no
 * prompt surface becomes a deny (AD-2).
 * @type {readonly ["deny", "ask", "allow"]}
 */
export const VERDICTS = Object.freeze(["deny", "ask", "allow"]);

/**
 * A tool call the harness is about to run, normalized by the adapter.
 *
 * @typedef {object} ToolCall
 * @property {string} tool                Tool name as the harness spells it (lowercased core-side).
 * @property {object} input               Harness-native input shape (command, path, args…). Passed through opaquely.
 * @property {string} [cwd]               Working directory the call runs in, if the harness exposes one.
 * @property {string} [agent]             Agent/runner identity, if the harness exposes one.
 * @property {string} [sessionId]         Harness session id, used for rulings and session-scoped context.
 */

/**
 * Conversation context: what Jev gets to see besides the tool call itself. Built by
 * {@link buildConversationContext} from the session store, a transcript, or adapter-supplied
 * messages. `flagged_untrusted_content` is the provenance of flagged content refs (the core
 * derives it from session flags recorded by earlier scans).
 *
 * @typedef {object} ConversationContext
 * @property {string[]} [user_recent_messages]        Recent operator messages (the operator's own words, deduped, tail-clipped).
 * @property {string} [assistant_intent]              The agent's stated intent for the current turn.
 * @property {string[]} [recent_tool_calls]           The last few calls and their verdicts.
 * @property {string[]} [flagged_untrusted_content]   Provenance refs: kind, source, probability and excerpt of content flagged untrusted earlier in the session.
 */

/**
 * Spec for building a {@link ConversationContext}. The adapter supplies whatever its harness
 * hands it; `messages` entries are `{role: "user"|"assistant", text: string}`.
 *
 * @typedef {object} ConversationContextSpec
 * @property {string} [sessionId]       Session-store key.
 * @property {string} [transcriptPath]  Claude-style JSONL transcript path, if the harness provides one.
 * @property {string} [intent]          Adapter-known agent intent text.
 * @property {{role: "user"|"assistant", text: string}[]} [messages]  Adapter-extracted recent messages (pi, OpenCode, ACP).
 */

/**
 * Provenance of flagged untrusted content supplied by the adapter at assessment time.
 * RESERVED in 1.0: the core derives provenance itself from session flags (see
 * {@link ConversationContext.flagged_untrusted_content}); a populated field here is accepted
 * and carried in `detail`, not yet consulted by the core. Additive evolution lands as MINOR.
 *
 * @typedef {object} Provenance
 * @property {boolean} [fromUntrustedContent]  Adapter's own belief that the call follows untrusted content.
 * @property {string[]} [refs]                 Identifiers of the flagged content items the call responds to.
 */

/**
 * Payload in (AD-1): tool call + conversation context + provenance.
 *
 * @typedef {object} AssessPayload
 * @property {ToolCall} call                                                The tool call being judged.
 * @property {ConversationContext | ConversationContextSpec} [context]      Either a spec for {@link buildConversationContext} or an already-built context.
 * @property {Provenance} [provenance]                                      Adapter-supplied provenance (reserved — see the typedef).
 */

/**
 * Decision out (AD-1): the core's answer, in contract terms. `message` is the full
 * human-readable ruling (header + guidance) for whatever the harness surfaces to the model;
 * `guidance` is the agent-guidance sentence(s) alone, for hosts that render them separately.
 *
 * @typedef {object} Decision
 * @property {"deny"|"ask"|"allow"} verdict     One of {@link VERDICTS} — never anything else (AD-2).
 * @property {string} category                  Reason category (e.g. "Dangerous Action", "Injected Instruction", "Credential Exposure", "Gate Self-Protection", "Approval Needed") or the governing reason text.
 * @property {string} stats                     Human-readable classifier stats line (scores/probabilities, or floor/degraded provenance).
 * @property {string | null} ruling             Operator ruling citation that produced or shaped this decision, null when none applied.
 * @property {string} guidance                  Agent guidance string — what to do (and not do) next; "" when none.
 * @property {string} message                   The full rendered message (header + guidance).
 * @property {object} detail                    The full underlying assessment (risk, approval, degraded flag, floor family…). Additive; ignore unknown fields.
 */

/**
 * Scan result out (AD-1): post-tool content scan of text the model is about to read.
 *
 * @typedef {object} ScanResult
 * @property {boolean} flagged       True when the content was flagged as AI-directed (injection/canary/unknown at threshold).
 * @property {string} kind           Classifier kind ("injection", "canary", "unknown", "clean", …).
 * @property {number} probability    Directness probability of the judgment.
 * @property {number} [confidence]   Classifier confidence, when provided.
 * @property {string} message        Rendered guidance for the flagged/clean content.
 * @property {object} detail         The full underlying scan answer. Additive; ignore unknown fields.
 */

// assessAction composes `message` as header + " " + guidance; on deny/ask the header always
// ends with `${raw.what}.`, so the guidance is everything after that boundary. Reconstructing
// here keeps the contract self-contained without re-deriving core internals; the marker
// cannot appear earlier than the header (what precedes guidance by construction).
function decisionFrom(raw) {
  if (!raw) return null;
  let guidance = "";
  if (raw.level !== "allow" && raw.what) {
    const marker = `${raw.what}.`;
    const i = String(raw.message ?? "").indexOf(marker);
    if (i !== -1) guidance = raw.message.slice(i + marker.length).trim();
  }
  return {
    verdict: raw.level,
    category: raw.category ?? "",
    stats: raw.stats ?? "",
    ruling: raw.ruling ?? null,
    guidance,
    message: raw.message ?? "",
    detail: raw,
  };
}

/**
 * Judge a tool call. Returns null when the core skips the call (read-shaped tools below the
 * gate, skip-listed tools) — null means "no verdict; the harness default applies", never
 * "allow": the fail-safe direction is always toward deny (AD-2).
 *
 * @param {AssessPayload} payload
 * @param {object} [opts]  Core options (env, fetchImpl, warnStream) — pass a fake brain in tests.
 * @returns {Promise<Decision | null>}
 */
export async function assess({ call, context, provenance }, opts = {}) {
  const ctx = context
    ? ("user_recent_messages" in context || "assistant_intent" in context || "recent_tool_calls" in context || "flagged_untrusted_content" in context
        ? context
        : buildContext(context) ?? undefined)
    : undefined;
  return decisionFrom(await assessAction({ ...call, context: ctx }, opts));
}

/**
 * Build the conversation context half of the payload from whatever the harness exposes.
 * Returns undefined when nothing is known — the payload then carries the call alone.
 *
 * @param {ConversationContextSpec} spec
 * @returns {ConversationContext | undefined}
 */
export function buildConversationContext(spec) {
  return buildContext(spec);
}

/**
 * Scan tool output text before the model reads it. Returns null when the core skips the
 * scan (never-scanned tools, skip list, below the minimum length) — null is "no scan ran",
 * not "clean".
 *
 * @param {{text: string, tool?: string, source?: string, task?: string}} payload
 * @param {object} [opts]  Core options (env, fetchImpl, warnStream).
 * @returns {Promise<ScanResult | null>}
 */
export async function scan({ text, tool, source, task }, opts = {}) {
  const raw = await scanContent({ text, tool, source, task }, opts);
  if (!raw) return null;
  return { flagged: raw.flagged, kind: raw.kind, probability: raw.p, confidence: raw.confidence, message: raw.message, detail: raw };
}

/**
 * AD-2 fail-safe: on a host with no prompt surface an ask cannot be held, so it becomes a
 * deny carrying the ask-blocked guidance — the decision routes through the user in
 * conversation instead. Takes a contract {@link Decision}; returns a new one.
 *
 * @param {Decision} decision
 * @returns {Decision}
 */
export function askBlocked(decision) {
  return decisionFrom(askBlockedDeny(decision.detail));
}

/** Shape-guard for tests and the conformance suite: every field the contract promises is present and typed. */
export function isDecision(d) {
  return !!d && VERDICTS.includes(d.verdict)
    && typeof d.category === "string" && typeof d.stats === "string"
    && (d.ruling === null || typeof d.ruling === "string")
    && typeof d.guidance === "string" && typeof d.message === "string"
    && d.detail && typeof d.detail === "object";
}

/** Shape-guard for scan results, same role. */
export function isScanResult(r) {
  return !!r && typeof r.flagged === "boolean" && typeof r.kind === "string"
    && typeof r.probability === "number" && typeof r.message === "string";
}

// ── adapter-support surface (added 1.1.0, entry 3) ─────────────────────────────────────────
// Everything an adapter needs besides assess/scan/buildConversationContext/askBlocked, so
// the import lint can be contract-only. These are pass-throughs over the core modules the
// contract itself already rests on; they expose no new policy and accept no new state.

/** Instruction-file name/shape matcher (SKILL.md, CLAUDE.md, AGENTS.md, …) — the source
 *  strings a scan should treat as instructions. */
export { INSTRUCTION_FILE };

/** Shortest text that still gets scanned (below it the core skips the scan). */
export { MIN_SCAN_CHARS };

/** First N chars of a value, normalized — the preview shape adapters record in session memory. */
export { preview };

/** Clip text to an excerpt for flag records. */
export { excerpt };

/** Flatten a harness tool response (string, {content}, nested arrays) into one text blob. */
export { collectText };

/** Translate a harness message list (OpenCode SDK parts, pi branch entries) into the
 *  `{role: "user"|"assistant", text}` entries a {@link ConversationContextSpec.messages} takes. */
export { messagesFrom };

/** Session memory: read a session's store (prompts, calls, flags, swept). */
export const sessionRead = readSession;

/** Record one item in a session store bucket ("prompts", "calls", "flags"). */
export const sessionRemember = remember;

/** Patch a session store record (e.g. `{swept: true}`). */
export const sessionUpdate = update;

/** Mark every flag in a session as reported (the prompt/summary hooks fire once per flag). */
export const sessionMarkReported = markReported;

/** Fallback posture: true when GUARD_FALLBACK=closed (a dead brain must block, not pass). */
export { failClosed };

/** The project instruction sweep: find + scan every instruction file under the session's
 *  project roots. Returns the raw scan results (`flagged`, `kind`, `p`, `file`). */
export async function sweepInstructionFiles(cwd, opts = {}) {
  return scanFiles(findInstructionFiles(projectRoots(cwd)), opts);
}

/** Scan one named instruction file (the InstructionsLoaded event). Returns its scan result
 *  or undefined when the file holds nothing scannable. */
export async function scanInstructionFile(path, opts = {}) {
  const [r] = await scanFiles([path], opts);
  return r;
}

/** Scan instruction-shaped text through the cached instruction classifier. */
export async function scanInstructions({ text, source }, opts = {}) {
  return scanInstructionsCached({ text, source }, opts);
}
