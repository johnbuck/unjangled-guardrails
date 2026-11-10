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
import { assessAction, scanContent, askBlockedDeny, INSTRUCTION_FILE, excerpt, collectText, preview, agentCreatedPaths, isAskUserTool, isSubagentSpawnTool } from "./guard.js";
import { buildContext, messagesFrom } from "./context.js";
import { readSession, remember, rememberCreated, update, markReported } from "./session.js";
import { findInstructionFiles, projectRoots, scanFiles, scanInstructionsCached } from "./skills.js";
import { failClosed } from "./orchestrate.js";
import { capturePromptRuling, expirePromptSession, recordHarnessStore, promptCaptureTier } from "./rulings.js";

/**
 * Contract version. See the compat rules in the module header. Bump MINOR on any
 * additive change; MAJOR on any removal/renaming/type change/enum change.
 * 1.1.0 (entry 3, epic-adapter-seam): additive adapter-support surface — the helper
 * exports below let every adapter import through the contract alone (the import lint
 * is now contract-only). No existing field or shape changed.
 * 1.2.0 (story 1, epic-prompt-rulings-session): additive prompt-authority capture — the
 * `capturePromptRuling` export mints a gate ruling from a human-answered ask choice (the
 * only constructor of prompt:<harness> provenance; GUARD_PROMPT_RULINGS tier, default off).
 * No existing field or shape changed.
 * 1.3.0 (story 2, epic-prompt-rulings-session): additive session lifetime — the
 * `expirePromptSession` export removes one session's prompt-captured session-scope allow
 * rulings when its harness announces session end (never-mints, so it runs un-gated on
 * operator authority; the 24h mint-time cap stays the backstop). No existing field or
 * shape changed.
 * 1.4.0 (story 3, epic-prompt-rulings-session): additive capture-surface support — the
 * `promptCaptureTier` helper reads GUARD_PROMPT_RULINGS (off|session|project, default
 * off, unknown fail-safe) so an ask surface can choose its dialog shape against the SAME
 * parse the capture mint honors (the failClosed() precedent for config reads). No
 * existing field or shape changed.
 * 1.5.0 (entry 5, epic-github-field-reports): additive store visibility — the
 * `recordHarnessStore` export lets a gate process serving a harness record where that
 * harness's policy store lives (the harness store registry), so policy commands can name
 * their store and warn on divergence. No existing field or shape changed.
 * 1.6.0 (entry 2, epic-github-field-reports): additive ask-user user-words lane — the
 * `isAskUserTool` re-export (the core's ask-user tool family) and the
 * `sessionRememberUserAnswer` helper (record an ask-user tool's RESULT — the operator's
 * own typed answer — into the session's user-words lane). scan behavior for the family
 * changes from never-scanned-by-list to never-scanned-by-lane (null either way); no
 * existing field or shape changed.
 * 1.7.0 (entry 3, epic-github-field-reports): additive sub-agent context relay — the
 * `ConversationContextSpec.parentSessionId` field (a sub-agent child's harness-native
 * parent link; the parent's operator words join the child's user-words lane as scoring
 * context, informing verdicts and minting no allow) and the `isSubagentSpawnTool`
 * re-export (the spawn-tool family vocabulary). No existing field or shape changed.
 * @type {"1.7.0"}
 */
export const CONTRACT_VERSION = "1.7.0";

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
 *                                        The adapter supplies the harness-exposed cwd as the fallback; the core
 *                                        derives the call's own working folder from a bash/terminal-shaped input's
 *                                        workdir-style field when it carries one (CAP-6) — do not strip those fields.
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
 * @property {string[]} [flagged_untrusted_evidence]  Story-2 candidate E: same entries with the size-capped excerpt labeled as untrusted evidence — stripped from the main ask, fed only to the isolated from_untrusted request.
 */

/**
 * Spec for building a {@link ConversationContext}. The adapter supplies whatever its harness
 * hands it; `messages` entries are `{role: "user"|"assistant", text: string}`.
 *
 * @typedef {object} ConversationContextSpec
 * @property {string} [sessionId]       Session-store key.
 * @property {string} [parentSessionId] The harness-native parent link of a sub-agent child
 *                                       (1.7.0, CAP-4): the parent session's operator words
 *                                       (its prompts bucket only — prompt events and ask-user
 *                                       answers) join the child's `user_recent_messages` as
 *                                       scoring context, live and read-only. The relay mints
 *                                       nothing: the brain's user_requested judgment stays the
 *                                       only lifter, and no deny floor sees it. Supply it from
 *                                       what the harness itself exposes (pi subagent children
 *                                       carry `PI_SUBAGENT_ORCHESTRATOR_SESSION_ID` in env) —
 *                                       never guessed.
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

// ── prompt-authority capture (added 1.2.0, epic-prompt-rulings-session story 1) ─────────────
// The ask-prompt capture path (CAP-2): when the host's own prompt resolved an ask with a
// session/always choice, the adapter mints the matching gate ruling through this export —
// the ONLY constructor of prompt:<harness> provenance (no env var or CLI argv can mint it;
// GUARD_PROMPT_RULINGS off|session|project, DEFAULT OFF). Full semantics in
// src/rulings.js (capturePromptRuling) and docs/adapter-guide.md §7. The short adapter
// contract:
//   - call it only with a choice a HUMAN made on your prompt — a forged answer mints
//     standing allows; the per-session cap, the OFF default tier, dedupe, and the audit
//     row are the survivability story, not permission;
//   - a declined capture ({ captured: false }) means allow-once: proceed with this call;
//   - a thrown capture (store failure) also means allow-once: catch it, proceed, surface
//     nothing — a capture failure never changes the ask outcome;
//   - the next covered call lifts through the ordinary ruling consult; nothing else to do.
export { capturePromptRuling };

// ── session lifetime (added 1.3.0, epic-prompt-rulings-session story 2) ───────────────────
// The death-at-session-end half of the lifetime pair (operator ruling 2026-11-06): when the
// harness announces a session ended, the adapter calls this with that session's id and its
// own harness name — the session's prompt-captured session-scope grants die now instead of
// at the 24h mint-time cap. The short adapter contract (full semantics in src/policy.js
// expirePromptSession and docs/adapter-guide.md §7):
//   - it removes ONLY prompt-captured (via prompt:*) session-scope allow rulings for that
//     one session — operator-minted 7d session rulings, project captures, denies, and other
//     sessions are never touched;
//   - a cleanup that removes nothing writes nothing: repeated session-end signals are safe
//     to forward blindly (idempotent);
//   - it never mints anything, so no operator authority is involved — the audit row's
//     `session-end:<harness>` names the announcing channel;
//   - a corrupt/locked store THROWS: catch it, warn on your own surface, keep going — the
//     grants then die by the 24h cap, fail-safe; never crash the session-end path;
//   - an ephemeral session (no id) is the caller's skip: there is nothing attributed to it.
export { expirePromptSession };

// ── capture-surface support (added 1.4.0, epic-prompt-rulings-session story 3) ───────────
// The ask surfaces must know the capture tier BEFORE choosing their dialog shape, and the
// parse they consult must be the one the mint honors — a four-option ask on a tier the
// core reads as off would promise what the capture would decline. Route the read through
// the contract like every other config read (failClosed() precedent). Ask surfaces: with
// the tier on, offer the persistence choices; with it off (the default), keep the binary
// ask byte-identical.
export { promptCaptureTier };

// ── store visibility (added 1.5.0, epic-github-field-reports entry 5: CAP-5) ─────────────
// The two-terminal split: a harness that sets GUARD_HOME (the Hermes adapter must — it is
// the fork root the plugin spawns `node $GUARD_HOME/src/cli.js hook` from) reads a different
// policy store than an operator terminal without it, and no side could see the other. The
// adapter contract (full semantics in src/policy.js and docs/adapter-guide.md §9):
//   - call `recordHarnessStore(yourHarnessName, env)` ONCE from your process entry — never
//     per call, never from library code; the registry lives at the DEFAULT guard home so
//     every terminal finds it regardless of its own GUARD_HOME;
//   - it never throws and returns false when it did not record (synthetic env, scratch
//     root under the OS tmpdir, unwritable home) — call it bare, ignore the result;
//   - the reward: `policy where` shows your harness's store, and every policy command in a
//     terminal that resolves a different store warns about the divergence by name.
export { recordHarnessStore };

// ── adapter-support surface (added 1.1.0, entry 3) ─────────────────────────────────────────
// Everything an adapter needs besides assess/scan/buildConversationContext/askBlocked, so
// the import lint can be contract-only. These are pass-throughs over the core modules the
// contract itself already rests on; they expose no new policy and accept no new state.

/** Instruction-file name/shape matcher (SKILL.md, CLAUDE.md, AGENTS.md, …) — the source
 *  strings a scan should treat as instructions. */
export { INSTRUCTION_FILE };

// ── the ask-user user-words lane (added 1.6.0, epic-github-field-reports entry 2: CAP-2) ────
// An ask-user tool's RESULT is the operator's own typed answer (Hermes `clarify`, Claude
// Code AskUserQuestion, pi ask_user_question — `ASK_USER_RESULT_TOOLS` in src/guard.js).
// The scan side never flags it (`scan` resolves null for the family); this helper is the
// other half — the answer ARRIVES in the user-words lane: it records into the session's
// `prompts` bucket, the same bucket prompt events write and the one buildContext mines
// into user_recent_messages (the strict operator-words lift pipe the brain's
// user_requested question consults; never trimmed). Call it from your post-tool surface
// with the RESULT text (the operator's words — never the tool input, which is the
// agent's question); it no-ops for every other tool, for blank text, and without a
// session id.
export { isAskUserTool };

// ── the sub-agent context relay (added 1.7.0, epic-github-field-reports entry 3: CAP-4) ─────
// A sub-agent's tool calls are judged with the operator's overall directive and goal present:
// pass `parentSessionId` in the {@link ConversationContextSpec} (from the harness's own parent
// link — pi subagent children carry PI_SUBAGENT_ORCHESTRATOR_SESSION_ID in env) and the parent
// session's operator words join the child's user-words lane — live, read-only, prompts bucket
// only (never the parent's flags/calls/intents), informing the brain's verdicts and minting
// nothing (operator ruling 2026-11-09 + refinement: no second grant channel; harness-native ask
// routing is the route where the harness has it). The spawn-tool family below is the shared
// vocabulary for the shapes that spawn children — membership keys no verdict path.
export { isSubagentSpawnTool };

/** Record an ask-user tool's result — the operator's own typed answer — into the
 *  session's user-words lane (the `prompts` bucket). No-op for any other tool. */
export function sessionRememberUserAnswer(sessionId, tool, text) {
  if (!isAskUserTool(tool) || typeof text !== "string" || !text.trim()) return;
  remember(sessionId, "prompts", { text: text.slice(0, 2000) });
}

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

/** Record one path this session's own ALLOWED calls created (CAP-11 cleanup coverage). */
export const sessionRememberCreated = rememberCreated;

/** The paths a tool call creates (write-family tools; bash mkdir/touch/redirect targets) —
 *  what adapters feed into sessionRememberCreated on allowed creator calls. */
export { agentCreatedPaths };

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
