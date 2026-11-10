// Rulings machinery (consolidation 2026-10-20): the shared machinery the whole gate runs on,
// plus the back-compat surface over the rulings' new home. The rulings STORE, CLI and audit
// merged into the config surface (src/policy.js) — ruling entries live on there as
// command-pattern policy entries with scope + expiry; this module keeps the machinery
// (operatorContext, globToRegExp, subCommands, tamperCheck, the store lock, the atomic
// writer) and thin wrappers so every existing caller keeps working: an allow ruling lifts
// asks and denies, a deny ruling hard-blocks an allow — the exact consult semantics, over
// the folded store. Rulings enhance the brain, never bypass it: a brain deny is a safety
// floor only a deliberate operator entry can lift, and a corrupt store silently degrades to
// brain-only.
import { readFileSync, writeFileSync, mkdirSync, appendFileSync, existsSync, statSync, renameSync, rmdirSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join, sep, resolve } from "node:path";
import {
  policyFile, loadPolicyStore, commandConsult, addCommandEntry, removeEntry, listEntries,
} from "./policy.js";

const home = (env = process.env) => env.GUARD_HOME ?? env.JEV_GUARD_HOME ?? join(homedir(), ".unjangled-guardrails");
export const guardHome = home;  // exported for the path-based self-modification guard (always-deny.js)
export const rulingsFile = (env = process.env) => join(home(env), "rulings.json");  // LEGACY: the migration source; the live store is user-policy.json
export const auditFile = (env = process.env) => join(home(env), "rulings-use.jsonl");

// Expiry defaults when the operator gives none: session 7d, project 30d. Global rulings never
// defaulted — the `ruling add` surface still refuses a global without --expires (a
// forever-allow in every context is the context-blind allowlist this mechanism exists to
// replace); the policy surface allows a standing global entry, adopted deliberately.
export const DEFAULT_EXPIRY = { session: 7 * 864e5, project: 30 * 864e5 };

export function warn(msg, stream = process.stderr) {
  stream.write(`unjangled-guardrails: ${msg}\n`);
}

// Operator authority for every store mutation (plan 1.1, red-team R1). The check lives
// here in the library — not the CLI — so no entry point (CLI, script, import) can mutate the
// store without it. Agents run non-interactive (no TTY) and don't carry the escape. This is
// NOT cryptographic: a same-uid process can set the escape env (the documented residual risk).
// Those grants still append a mutation audit row marked via "env-escape", so the operator sees
// them after the fact; direct file writes are denied by the path guard (always-deny.js) and
// caught by the tamper warning below.
// The prompt-authority channel (epic-prompt-rulings-session, story 1): a fourth way to prove
// operator presence — the harness ask prompt answered by a human IS the proof (the red-team
// R1 framing "agents run non-interactive and don't carry the escape" gains its one recorded
// exception, with its audit vocabulary). The channel is keyed on a module-private Symbol so
// ONLY capturePromptRuling (below) can construct it: no env var maps to it, no CLI argv
// reaches it, and a caller passing { via: "prompt:…" } as a plain string key never gets past
// the tty/env-escape check. Non-cryptographic like the rest of this authority (a same-uid
// process can already mint anything via GUARD_OPERATOR_CLI — the documented residual); the
// invariant it does hold: every prompt:* audit row was minted by the capture path.
const PROMPT_AUTHORITY = Symbol("promptAuthority");

export function operatorContext(env = process.env, { isTTY = process.stdout.isTTY, [PROMPT_AUTHORITY]: harness, session } = {}) {
  if (typeof harness === "string" && harness) {
    // `session` rides along for entry attribution (the per-session write cap); it is inert on
    // every non-prompt path, where this return is only ever read for .via.
    return { via: `prompt:${harness}`, ...(session ? { session } : {}) };
  }
  if (!isTTY && (env.GUARD_OPERATOR_CLI ?? env.JEV_GUARD_OPERATOR_CLI) !== "1")
    throw new Error("ruling changes are operator-only: run from your own terminal");
  return { via: isTTY ? "tty" : "env-escape" };
}

// Tamper evidence: every legitimate store change is immediately followed by an operator
// mutation row (save()), and every entry-fired decision appends a usage row. A store whose
// mtime outpaces every audit row was changed by some other hand. Warn loudly; the gate keeps
// functioning (fail-safe direction), but the operator must re-check the store's contents.
// Both stores check: the live user-policy.json and the legacy rulings.json (a hand-edited
// legacy store after migration is still a tamper signal).
const TAMPER_GRACE_MS = 5_000;  // mtime vs wall-clock skew allowance
function lastAuditAt(env) {
  try {
    const rows = readFileSync(auditFile(env), "utf8").trim().split("\n").filter(Boolean);
    return Date.parse(JSON.parse(rows[rows.length - 1]).at) || 0;
  } catch { return 0; }
}
export function tamperCheck(env = process.env, warnStream) {
  const audit = lastAuditAt(env);
  for (const file of [rulingsFile(env), policyFile(env)]) {
    try {
      if (statSync(file).mtimeMs > audit + TAMPER_GRACE_MS)
        warn(`store changed without an operator action (${file}) — possible tampering`, warnStream);
    } catch { /* no store yet — nothing to tamper with */ }
  }
}

export function unexpired(r, now = Date.now()) {
  if (!r.expiresAt) return true;
  const t = Date.parse(r.expiresAt);
  return Number.isNaN(t) ? false : t > now;
}

// Command-style glob: `*` matches anything, `?` one char; everything else is literal.
export function globToRegExp(pattern) {
  const re = String(pattern).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${re}$`, "i");
}

// TR-4 (red R2): the terminators that split a compound bash command, honored only OUTSIDE
// quotes, backtick spans, and unquoted subshell/command-substitution parens. A ruling like
// `git push *` must never lift "git push origin main; rm -rf ~" — every sub-command has to
// match the ruling on its own — but a `;` inside a quoted commit message or a `|` inside a
// quoted grep pattern is argument text, not a terminator: the old quote-blind regex split
// inside it and manufactured junk segments no entry could match (CAP-1, corpus rows c1/c2).
// scanSpan: the body of one command context — $( ) / ( ) up to the matching close paren
// (paren counting is the whole job; degenerate quotes inside only affect bash-invalid
// input), or ` ` up to the first close backtick. Returns the body text, the index of the
// close character, and whether it closed at all (unbalanced input runs to end of string).
function scanSpan(raw, i, close) {
  let d = close === ")" ? 1 : 0;
  let text = "";
  i++;
  while (i < raw.length) {
    const c = raw[i];
    if (close === "`") { if (c === "`") return { text, end: i, closed: true }; text += c; i++; continue; }
    if (c === "(") d++;
    else if (c === ")") { d--; if (d === 0) return { text, end: i, closed: true }; }
    text += c;
    i++;
  }
  return { text, end: i, closed: false };
}

export function splitTopLevel(raw) {
  const parts = [];
  let cur = "";
  let quote = ""; // "" | "'" | '"' — the open quote, if any
  const stop = () => { parts.push(cur); cur = ""; };
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (quote) {
      // Inside double quotes `$( )` and backticks STILL EXECUTE (the quotes only silence
      // word-splitting of the result) — so their bodies segment on their own, exactly like
      // the unquoted case below. Inside single quotes nothing executes and everything is
      // argument text.
      if (quote === '"' && ((c === "$" && raw[i + 1] === "(") || c === "`")) {
        const open = c === "$" ? "$(" : "`";
        const close = c === "$" ? ")" : "`";
        cur += open;
        stop();
        i += open.length - 1;
        const body = scanSpan(raw, i, close);
        parts.push(...splitTopLevel(body.text));
        cur = body.closed ? close : "";
        i = body.end;
        continue;
      }
      cur += c;
      if (c === "\\" && quote === '"') cur += raw[++i] ?? ""; // double quotes honor \"
      else if (c === quote) quote = "";
      continue;
    }
    if (c === "\\") { cur += c + (raw[++i] ?? ""); continue; } // escaped char is literal
    if (c === "'" || c === '"') { quote = c; cur += c; continue; }
    // A command context opens: the prefix stands alone and the body segments on its own.
    // Substitution and subshell bodies EXECUTE as commands — merging them into the parent
    // segment would let a parent-matching entry lift smuggled commands (TR-4), which the
    // first cut of this scanner did and the quick lens caught.
    if (c === "`" || c === "(") {
      cur += c; // keep the open marker so segments reassemble the original text
      stop();
      const body = scanSpan(raw, i, c === "(" ? ")" : "`");
      parts.push(...splitTopLevel(body.text));
      cur = body.closed ? raw[body.end] : "";
      i = body.end;
      continue;
    }
    if ((c === "&" && raw[i + 1] === "&") || (c === "|" && raw[i + 1] === "|")) { stop(); i++; continue; }
    if (c === ";" || c === "|" || c === "\n") stop();
    else cur += c;
  }
  parts.push(cur);
  return parts;
}

// Bash-shaped input: an explicit .command field, or a shell tool. Everything else (file paths,
// urls) has no command grammar to split and keeps whole-input matching.
export function isBashShaped(tool, input) {
  return typeof input?.command === "string" || /bash|shell/i.test(String(tool ?? ""));
}

// Workdir-resolved project scope (CAP-6, epic-github-field-reports entry 6): the folder a tool
// call RUNS in, not the folder its harness process lives in. The Hermes plugin used to stamp
// every payload with the harness home (~/.hermes), so a project-scoped entry never matched a
// subagent terminal call running in a repo — the gate attributed every call to where Hermes
// was installed. This pure derivation feeds the matcher's cwd: for a bash/terminal-shaped call
// carrying its own working-directory field, that field is where the shell will execute, so it
// IS the scope truth (the workdir is execution reality, not an agent claim about it); every
// other call keeps the adapter-supplied cwd exactly as before. The field spellings are the
// harness family's own (Cursor cwd, ACP cwd, Hermes workdir, OpenCode directory), precedence
// fixed so both sides of an adapter pair cannot disagree; relative values resolve against the
// fallback — never process.cwd(), which would differ between a hook spawn and its harness.
// Non-bash inputs are excluded on purpose: a `directory` field on an MCP/filesystem tool is a
// target the agent chose, not a folder a shell executes in, and must not steer scope matching.
const WORKDIR_FIELDS = ["cwd", "workdir", "working_dir", "directory"];

/** The cwd a scope consult should match: the call's own working directory when a
 *  bash/terminal-shaped input carries one, else the adapter-supplied fallback unchanged. */
export function callWorkdir(tool, input, fallback) {
  const shellish = typeof input?.command === "string" || /bash|shell|terminal/i.test(String(tool ?? ""));
  if (!shellish || !input || typeof input !== "object") return fallback;
  for (const key of WORKDIR_FIELDS) {
    const v = input[key];
    if (typeof v === "string" && v.trim()) {
      if (v.startsWith("/")) return v;
      return typeof fallback === "string" ? resolve(fallback, v) : v;
    }
  }
  return fallback;
}

// The strings an entry's glob is tested against — the FULL input string, never a truncated
// preview (blue H2: the old 160-char slice made matching die silently past char 160, hiding
// whatever the tail carried). Bash-shaped input splits on the terminators ABOVE first —
// splitting the collapsed preview would be too late (inputPreview flattens newlines into
// spaces, erasing one of the separators). Non-bash tools get the whole input as one part,
// whitespace-collapsed like the old preview but untruncated.
export function subCommands(input, tool) {
  const raw = typeof input === "string" ? input
    : typeof input?.command === "string" ? input.command
    : String(input?.file_path ?? input?.path ?? input?.url ?? JSON.stringify(input ?? ""));
  const parts = isBashShaped(tool, input) ? splitTopLevel(raw) : [String(raw).replace(/\s+/g, " ")];
  return parts.map((s) => s.trim()).filter(Boolean);
}

// `preview` may be one string or the sub-command list from subCommands(); an array lifts only
// when EVERY sub-command matches its own match (empty list never matches).
export function matches(r, { tool, preview, cwd, sessionId }) {
  const parts = Array.isArray(preview) ? preview : [String(preview ?? "")];
  // Staged rulings (epic-ask-band-posture, operator request 2026-10-12): a compound allow —
  // one pattern per segment, and the segment COUNT must match exactly. A three-stage ruling
  // lifts a three-segment `git add … && git commit … && git push` chain while a two-segment
  // or four-segment variant still asks; each stage is separately constrained, so a force
  // flag in any stage breaks its stage's glob and the chain asks. No stages array → the
  // single-pattern rule (TR-4: every sub-command must match the one pattern).
  if (Array.isArray(r.stages)) {
    if (parts.length === 0 || parts.length !== r.stages.length) return false;
    if (!parts.every((p, i) => globToRegExp(r.stages[i]).test(p))) return false;
  } else {
    const re = globToRegExp(r.pattern);
    if (parts.length === 0 || !parts.every((p) => re.test(p))) return false;
  }
  if (r.tool && String(r.tool).toLowerCase() !== String(tool ?? "").toLowerCase()) return false;
  const scope = String(r.scope ?? "global");
  if (scope === "global") return true;
  if (scope.startsWith("session:")) return sessionId !== undefined && sessionId === scope.slice("session:".length);
  if (scope.startsWith("project:")) {
    if (cwd === undefined) return false;
    const root = scope.slice("project:".length).replace(/\/+$/, "");
    return cwd === root || cwd.startsWith(root + sep);
  }
  return false;
}

export function appendAudit(ruling, level, { tool, input, cwd, sessionId, env = process.env } = {}) {
  try {
    mkdirSync(home(env), { recursive: true, mode: 0o700 });
    const row = { at: new Date().toISOString(), ruling: ruling.id, effect: ruling.effect, onLevel: level,
      tool: tool ?? null, preview: String(inputPreview(input, 100)), cwd: cwd ?? null, sessionId: sessionId ?? null, scope: ruling.scope };
    appendFileSync(auditFile(env), JSON.stringify(row) + "\n", { mode: 0o600 });
  } catch (err) { warn(`could not write the rulings audit row (${err.message})`); }
}

export function inputPreview(input, max) {
  const s = typeof input === "string" ? input : input?.command ?? input?.file_path ?? input?.path ?? input?.url ?? JSON.stringify(input ?? "");
  return String(s).replace(/\s+/g, " ").slice(0, max);
}

function msSinceImpl(s) {
  const m = typeof s === "string" && s.match(/^(\d+)([dhm])$/);
  if (!m) return null;
  return +m[1] * { d: 864e5, h: 36e5, m: 6e4 }[m[2]];
}
export { msSinceImpl as msSince };

// ── the back-compat ruling surface (the store lives in policy.js) ─────────────────────────────

// Load the folded store as rulings: the command-pattern entries. Returns { rulings } — an
// empty array when the store is absent/corrupt (the consults then match nothing and the
// brain alone gates), never a null the caller must special-case.
export function loadRulings(env = process.env, { warnStream } = {}) {
  tamperCheck(env, warnStream);
  const { entries } = loadPolicyStore(env, { warnStream });
  return { rulings: (entries ?? []).filter((r) => (r.kind ?? "tool") === "command") };
}

// The resolution order (spec addendum, Story 10):
//   brain deny  → deny, no ruling applies (safety floor — handled by the caller never calling here)
//   brain ask   → first matching unexpired allow ruling wins
//   brain allow → first matching unexpired deny ruling wins
//   otherwise   → the brain verdict stands
// The returned override carries the ruling so the caller can cite its id and audit the decision.
export function resolveRuling(level, { tool, input, cwd, sessionId, env = process.env, warnStream } = {}) {
  // Operator ruling 2026-10-04: an explicit operator ruling may lift asks AND denies.
  // The grant itself is the deliberate, audited act — the floor moved from "nothing lifts a
  // deny" to "only a deliberate operator action or genuine user words lift a deny".
  return commandConsult(level, { tool, input, cwd, sessionId, env, warnStream });
}

export function addRuling({ effect, pattern, stages, tool, scope = "project", expiresAt, reason }, env = process.env, { warnStream, ...authority } = {}) {
  // The one refusal the ruling surface keeps that the policy surface drops (see
  // addCommandEntry): a global ruling requires an explicit --expires.
  if (scope === "global" && !expiresAt) throw new Error("a global ruling requires an explicit --expires (ISO date, 7d/12h/30m, or never — never = permanent)");
  return addCommandEntry({ effect, pattern, stages, tool, scope, expiresAt, reason }, env, { warnStream, ...authority });
}

export function revokeRuling(id, env = process.env, { warnStream, ...authority } = {}) {
  const op = operatorContext(env, authority);  // same library gate: revoking is also a mutation
  // id-only, as before: a pattern passed here is a mistake, not a bulk revoke.
  if (!listEntries(env, { warnStream }).some((r) => r.id === id)) throw new Error(`no ruling ${id}`);
  return removeEntry(id, env, { warnStream, ...authority });
}

export function listRulings(env = process.env, { warnStream } = {}) {
  return listEntries(env, { warnStream }).filter((r) => (r.kind ?? "tool") === "command");
}

// Session-end cleanup (story 2, R-2): the store mutation lives in policy.js beside its
// machinery (saveStore / withStoreLock / assertWritable are module-private there); this
// re-export keeps the rulings surface complete for the contract to pass through.
export { expirePromptSession } from "./policy.js";

// Store visibility (CAP-5, epic-github-field-reports entry 5): the harness store registry
// machinery lives in policy.js beside the store it describes; re-exported here the same way
// so the contract (the only adapter import surface) passes it through.
export { recordHarnessStore, readHarnessStores, divergentHarnessStores, harnessStoreRegistryFile } from "./policy.js";

// First-session bootstrap (the `setup` tracer): create the stranger-owned EMPTY policy store.
// No operator authority is needed or checked — an empty store grants nothing, so an agent can
// run this end to end (unlike add/revoke, which stay operator-gated). Mirrors save()'s write
// pattern: the pairing audit row is appended BEFORE the store write, so the store is
// tamper-clean from birth. Idempotent, and careful never to SHADOW a legacy store: when a
// legacy rulings.json or user-lane.json exists, no empty store is created — the first assess
// migrates them (loadPolicyStore's first-run migration). Returns true when the store was
// created, false when one already exists (or a legacy store is waiting to migrate).
export function initStore(env = process.env, via = "setup") {
  if (existsSync(policyFile(env))) return false;
  if (existsSync(rulingsFile(env)) || existsSync(join(home(env), "user-lane.json"))) return false;
  mkdirSync(home(env), { recursive: true, mode: 0o700 });
  appendFileSync(auditFile(env), JSON.stringify({ at: new Date().toISOString(), action: "init", op: "init", via }) + "\n", { mode: 0o600 });
  atomicWrite(policyFile(env), JSON.stringify({ version: 1, entries: [] }, null, 2) + "\n");
  return true;
}

// ── store integrity (posture-triage 5.2) ──────────────────────────────────────────────────────

// A mkdir-based mutation lock (mkdir is atomic on POSIX). Mutations hold it across
// load → modify → save so two processes can never interleave their read-modify-writes. A
// holder that died mid-mutation leaves the directory behind; it is broken as stale after
// LOCK_STALE_MS. A live waiter gives up after LOCK_WAIT_MS with a clear error — never a hang.
const LOCK_STALE_MS = 10_000;
const LOCK_WAIT_MS = 10_000;
const LOCK_RETRY_MS = 50;
export const storeLockFile = (env = process.env) => join(home(env), "user-policy.json.lock");

// Run fn() holding the store's mutation lock; released in a finally even when fn() throws.
export function withStoreLock(env = process.env, fn, { staleMs = LOCK_STALE_MS, waitMs = LOCK_WAIT_MS, retryMs = LOCK_RETRY_MS } = {}) {
  mkdirSync(home(env), { recursive: true, mode: 0o700 });
  const lock = storeLockFile(env);
  const deadline = Date.now() + waitMs;
  for (;;) {
    try { mkdirSync(lock); break; }  // the acquire: mkdir succeeds exactly once
    catch (err) {
      if (err.code !== "EEXIST") throw err;
      try {
        if (Date.now() - statSync(lock).mtimeMs > staleMs) { rmdirSync(lock); continue; }  // stale holder: break it
      } catch { continue; }  // the lock vanished under us — re-attempt the acquire
      if (Date.now() > deadline) throw new Error(`store is locked by another process (${lock}) — retry in a moment`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, retryMs);  // synchronous sleep
    }
  }
  try { return fn(); } finally { try { rmdirSync(lock); } catch { /* a stale-breaker took it */ } }
}

// R10: never write the store in place — a crash mid-writeFileSync truncates the store and the
// gate silently loses every entry. Write a temp file in the SAME directory (rename is only
// atomic within one filesystem) and rename over the final path: a concurrent reader sees
// either the old store or the new one, never a partial. The temp name is unique per call so a
// leftover from a crashed writer is never clobbered mid-write; 0600 rides the temp into the
// rename. The renamer cleans up its temp when the write itself fails.
export function atomicWrite(file, data) {
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomUUID().slice(0, 8)}`;
  try {
    writeFileSync(tmp, data, { mode: 0o600 });
    renameSync(tmp, file);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* nothing to clean up */ }
    throw err;
  }
}

// ── prompt-authority capture (epic-prompt-rulings-session, story 1: CAP-2) ──────────────────
// A chosen ask-prompt option becomes the matching gate ruling: what the copy-paste hint
// (guard.js rulingHintFor) mints from the operator's terminal, minted in-process instead,
// minus the copy-paste. Everything hard is inherited: the mint runs through addRuling
// (validation, store lock, dedupe, audit pairing, atomic write), the replay lift is the
// ordinary consult (guard.js resolveRuling), expiry/unexpiry is the ordinary machinery. New
// here and nowhere else:
//
//   GUARD_PROMPT_RULINGS      off | session | project — the capture tier, DEFAULT OFF
//                             (operator ruling 2026-11-06: nothing persists without an
//                             explicit on-prompt choice made while a tier is enabled;
//                             unknown values fail safe to off)
//   GUARD_PROMPT_RULINGS_CAP  per-session write cap (default 20) — the forged-response
//                             bounder: an agent child that forges prompt responses can
//                             mint at most this many distinct unexpired prompt captures
//                             per session id; dedupe repeats never write and never count
//
// Semantics (the tier is the ceiling): tier off → every choice consumes as allow-once;
// tier session → session and always choices mint session:<id> with an explicit now+24h
// expiry (the R-2 fallback cap — operator-minted rulings keep the 7d DEFAULT_EXPIRY);
// tier project → a session choice still mints session:<id> 24h, an always choice mints
// project:<cwd> (the operator opt-in) riding the 30d project default. Allow-effect only;
// the scope is constructed here from the payload's sessionId/cwd — never global, never
// caller-supplied. Patterns are DERIVED from the asked call under the capture surface's own
// constraints — the adapter hands in the call, not a pattern, so a forged choice cannot
// widen what gets minted. Capture failure never changes the ask outcome: declines return
// a result and write nothing; store failures throw with the store untouched.

export const PROMPT_CAPTURE_SESSION_MS = 24 * 36e5;  // 24h fallback cap (R-2); ticket 2 pins the contract
const PROMPT_CAPTURE_CAP = 20;

// The tier parse, exported for the contract (1.4.0): the ask surfaces must know the tier
// BEFORE choosing their dialog shape, and the parse they use must be THIS one — an
// adapter-side copy could drift from what capturePromptRuling honors (a four-option ask
// promising what the core would decline). failClosed() is the precedent: config reads
// route through the contract. Unknown values fail safe to off.
export function promptCaptureTier(env = process.env) {
  const t = String(env.GUARD_PROMPT_RULINGS ?? "").trim().toLowerCase();
  return t === "session" || t === "project" ? t : "off";
}
const promptCap = (env = process.env) => {
  const n = Number(env.GUARD_PROMPT_RULINGS_CAP);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : PROMPT_CAPTURE_CAP;
};

// The capture surface's own pattern predicate, over the matcher's own split: an explicit
// bash command that splits into 1..3 segments, none carrying a quote or glob metacharacter.
// Returns the exact segments (the minted pattern/stages), or null when the call is not
// capturable. Historically shared with the copy-paste hint (guard.js rulingHintFor); the two
// deliberately diverged at CAP-7 (2026-11-10) — the OPERATOR hint generalizes its patterns
// (verb + subcommand + wildcard, the docs' shape) while the prompt-captured mint stays exact:
// the human approved THIS call, and exactness is the mint's safety property. cwd is
// deliberately NOT required here — project-scope mints need it; a session-scope capture
// does not.
function captureSegments({ tool, input }) {
  if (!isBashShaped(tool, input) || typeof input?.command !== "string") return null;
  const segments = subCommands(input, tool);
  if (segments.length === 0 || segments.length > 3) return null;
  if (segments.some((seg) => /['*?]/.test(seg))) return null;
  return segments;
}

/**
 * Turn a human-answered ask choice into the matching gate ruling. Adapters call this AFTER
 * their prompt resolved with a session/always choice — the answered prompt is the operator
 * presence; this export is the only constructor of prompt:<harness> provenance.
 *
 * @param {{choice: "once"|"session"|"always", harness: string, sessionId?: string, tool?: string, input?: object, cwd?: string}} capture
 * @param {{env?: object, warnStream?: object}} [opts]
 * @returns {{captured: true, existed: boolean, ruling: object} | {captured: false, outcome: "once", reason: string}}
 *   decline reasons: "choice-once" | "bad-choice" | "tier-off" | "pattern-constraints" |
 *   "missing-session" | "missing-cwd" | "session-cap" — declines write nothing and the
 *   choice consumes as allow-once. Store failures (corrupt/locked) THROW with the store
 *   untouched — catch and treat the choice as allow-once; the ask outcome never changes.
 */
export function capturePromptRuling({ choice, harness, sessionId, tool, input, cwd } = {}, { env = process.env, warnStream } = {}) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(String(harness ?? "")))
    throw new Error("capture needs a harness name (letters/digits/._- — e.g. 'pi', 'acp')");
  const once = (reason) => ({ captured: false, outcome: "once", reason });
  if (choice === "once") return once("choice-once");
  if (choice !== "session" && choice !== "always") return once("bad-choice");
  const tier = promptCaptureTier(env);
  if (tier === "off") return once("tier-off");
  const segments = captureSegments({ tool, input });
  if (!segments) return once("pattern-constraints");
  if (typeof sessionId !== "string" || !sessionId) return once("missing-session");
  const sessionScoped = choice === "session" || tier === "session";
  if (!sessionScoped && !cwd) return once("missing-cwd");
  const scope = sessionScoped ? `session:${sessionId}` : `project:${cwd}`;
  const stages = segments.length > 1 ? segments : undefined;
  const pattern = stages ? stages.join(" && ") : segments[0];
  // The per-session write cap (forge bounder): unexpired prompt-captured entries attributed
  // to this session, ANY scope — a forged 'always' under the project tier counts too. A
  // repeat grant of a LIVE entry (addRuling's pattern+tool+scope dedupe) writes nothing and
  // bypasses the cap.
  //
  // Story 2 (the story-1 handoff, triaged FIX): a repeat capture whose matching entry has
  // EXPIRED now supersedes — the dead entry is removed under this path's own symbol
  // authority (its row reads prompt:<harness>) and the fresh capture mints with a new 24h
  // clock. Reachable in one >24h session (and on project scope across sessions after 30d):
  // a human re-answering the ask expects relief; leaving it deduped made prompt capture
  // silently no-op for the rest of that session. A supersede WRITES, so the cap applies to
  // it (the dead entry never counted — the cap counts unexpired entries only). The count
  // still runs outside the store lock (addRuling owns the lock; withStoreLock is not
  // reentrant) — the story-1 TOCTOU residual carries over unchanged. Recorded
  // residual: an EXPIRED OPERATOR-minted match keeps the inherited dedupe (existed:true, no
  // lift) — removing operator entries from the capture path would breach the operator-entry
  // boundary, and the inherited semantics are identical on the operator surface.
  const existing = listRulings(env, { warnStream });
  const match = existing.find((r) => r.pattern === pattern && (r.tool ?? "") === (tool ?? "") && (r.scope ?? "global") === scope);
  const supersede = match && !unexpired(match) && String(match.via ?? "").startsWith("prompt:") ? match : undefined;
  const writes = !match || !!supersede;  // a live or operator-dead dedupe writes nothing
  if (writes && existing.filter((r) => String(r.via ?? "").startsWith("prompt:") && r.session === sessionId && unexpired(r)).length >= promptCap(env))
    return once("session-cap");
  if (supersede) removeEntry(supersede.id, env, { warnStream, [PROMPT_AUTHORITY]: harness, session: sessionId });
  const ruling = addRuling({
    effect: "allow",  // allow-effect only — the capture surface has no deny vocabulary
    ...(stages ? { stages } : { pattern: segments[0] }),
    ...(tool ? { tool } : {}),
    scope,
    ...(sessionScoped ? { expiresAt: "24h" } : {}),  // explicit now+24h — never the 7d session default
    reason: `prompt capture (${harness}: allow ${sessionScoped ? "for this session" : "always"})`,
  }, env, { warnStream, [PROMPT_AUTHORITY]: harness, session: sessionId });
  return { captured: true, existed: !!ruling.existed, ruling };
}
