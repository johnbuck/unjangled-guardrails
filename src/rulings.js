// Operator rulings: scoped, expiring allow/deny overrides that represent "the operator already
// answered this question, in this scope". Stored in one 0600 JSON file; every ruling-fired
// decision appends an audit row. Rulings enhance the brain, never bypass it: a brain deny is a
// safety floor no ruling can lift, and a corrupt store silently degrades to brain-only.
// Every mutation is operator-authority-gated HERE (operatorContext) and paired with a mutation
// audit row, so no entry point can self-grant and every change is tamper-checkable.
import { readFileSync, writeFileSync, mkdirSync, appendFileSync, existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, sep, resolve } from "node:path";

const home = (env = process.env) => env.GUARD_HOME ?? env.JEV_GUARD_HOME ?? join(homedir(), ".unjangled-guardrails");
export const guardHome = home;  // exported for the path-based self-modification guard (orchestrate.js)
export const rulingsFile = (env = process.env) => join(home(env), "rulings.json");
export const auditFile = (env = process.env) => join(home(env), "rulings-use.jsonl");

// Expiry defaults when the operator gives none: session 7d, project 30d. Global rulings never
// default — `ruling add --scope global` without --expires is refused (a forever-allow in every
// context is the context-blind allowlist this mechanism exists to replace).
const DEFAULT_EXPIRY = { session: 7 * 864e5, project: 30 * 864e5 };

export function warn(msg, stream = process.stderr) {
  stream.write(`unjangled-guardrails: ${msg}\n`);
}

// Operator authority for every ruling-store mutation (plan 1.1, red-team R1). The check lives
// here in the library — not the CLI — so no entry point (CLI, script, import) can mutate the
// store without it. Agents run non-interactive (no TTY) and don't carry the escape. This is
// NOT cryptographic: a same-uid process can set the escape env (the documented residual risk).
// Those grants still append a mutation audit row marked via "env-escape", so the operator sees
// them after the fact; direct file writes are denied by the path guard (orchestrate.js) and
// caught by the tamper warning below.
export function operatorContext(env = process.env, { isTTY = process.stdout.isTTY } = {}) {
  if (!isTTY && (env.GUARD_OPERATOR_CLI ?? env.JEV_GUARD_OPERATOR_CLI) !== "1")
    throw new Error("ruling changes are operator-only: run from your own terminal");
  return { via: isTTY ? "tty" : "env-escape" };
}

// Tamper evidence: every legitimate store change is immediately followed by an operator
// mutation row (save()), and every ruling-fired decision appends a usage row. A store whose
// mtime outpaces every audit row was changed by some other hand. Warn loudly; the gate keeps
// functioning (fail-safe direction), but the operator must re-check the store's contents.
const TAMPER_GRACE_MS = 5_000;  // mtime vs wall-clock skew allowance
function lastAuditAt(env) {
  try {
    const rows = readFileSync(auditFile(env), "utf8").trim().split("\n").filter(Boolean);
    return Date.parse(JSON.parse(rows[rows.length - 1]).at) || 0;
  } catch { return 0; }
}
export function tamperCheck(env = process.env, warnStream) {
  try {
    if (statSync(rulingsFile(env)).mtimeMs > lastAuditAt(env) + TAMPER_GRACE_MS)
      warn("rulings store changed without an operator action — possible tampering", warnStream);
  } catch { /* no store yet — nothing to tamper with */ }
}

// Load + parse the store. Returns { rulings, warning } — rulings is null when the store is
// unreadable or malformed, and the caller keeps gating with the brain alone.
export function loadRulings(env = process.env, { warnStream } = {}) {
  tamperCheck(env, warnStream);
  const file = rulingsFile(env);
  let raw;
  try { raw = readFileSync(file, "utf8"); }
  catch (err) {
    if (err.code === "ENOENT") return { rulings: [] };
    warn(`rulings store unreadable (${err.message}) — ignoring rulings, the brain still gates`, warnStream);
    return { rulings: null };
  }
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error("rulings.json is not an array");
    return { rulings: parsed.filter((r) => r && typeof r === "object") };
  } catch (err) {
    warn(`rulings store corrupt (${err.message}) — ignoring rulings, the brain still gates`, warnStream);
    return { rulings: null };
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

// TR-4 (red R2): the terminators that split a compound bash command. A ruling like
// `git push *` must never lift "git push origin main; rm -rf ~" — every sub-command has to
// match the ruling on its own.
const COMMAND_SPLIT = /\s*(?:&&|\|\||;|\|)\s*|\n+/;

// Bash-shaped input: an explicit .command field, or a shell tool. Everything else (file paths,
// urls) has no command grammar to split and keeps whole-input matching.
export function isBashShaped(tool, input) {
  return typeof input?.command === "string" || /bash|shell/i.test(String(tool ?? ""));
}

// The strings a ruling's glob is tested against — the FULL input string, never a truncated
// preview (blue H2: the old 160-char slice made matching die silently past char 160, hiding
// whatever the tail carried). Bash-shaped input splits on the terminators ABOVE first —
// splitting the collapsed preview would be too late (inputPreview flattens newlines into
// spaces, erasing one of the separators). Non-bash tools get the whole input as one part,
// whitespace-collapsed like the old preview but untruncated.
export function subCommands(input, tool) {
  const raw = typeof input === "string" ? input
    : typeof input?.command === "string" ? input.command
    : String(input?.file_path ?? input?.path ?? input?.url ?? JSON.stringify(input ?? ""));
  const parts = isBashShaped(tool, input) ? raw.split(COMMAND_SPLIT) : [String(raw).replace(/\s+/g, " ")];
  return parts.map((s) => s.trim()).filter(Boolean);
}

// `preview` may be one string or the sub-command list from subCommands(); an array lifts only
// when EVERY sub-command matches its own match (empty list never matches).
export function matches(r, { tool, preview, cwd, sessionId }) {
  const parts = Array.isArray(preview) ? preview : [String(preview ?? "")];
  const re = globToRegExp(r.pattern);
  if (parts.length === 0 || !parts.every((p) => re.test(p))) return false;
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
  const { rulings } = loadRulings(env, { warnStream });
  if (!rulings) return null;
  const want = level === "allow" ? "deny" : "allow";  // seek a lifter for ask AND deny; a deny-ruling only hard-blocks allows
  const ruling = rulings.find((r) => r.effect === want && unexpired(r) &&
    matches(r, { tool, preview: subCommands(input, tool), cwd, sessionId }));
  if (ruling) appendAudit(ruling, level, { tool, input, cwd, sessionId, env });
  return ruling ?? null;
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

// ── store management for the CLI ──────────────────────────────────────────────────────────────
export function addRuling({ effect, pattern, tool, scope = "project", expiresAt, reason }, env = process.env, { warnStream, ...authority } = {}) {
  const op = operatorContext(env, authority);  // plan 1.1: the authority gate lives in the library, before any validation or I/O
  if (effect !== "allow" && effect !== "deny") throw new Error("effect must be allow or deny");
  if (!pattern) throw new Error("pattern is required (a command glob, e.g. 'git push *')");
  if (scope === "global" && !expiresAt) throw new Error("a global ruling requires an explicit --expires (ISO date or 7d/12h/30m)");
  const resolved = scope === "global" ? "global"
    : scope.startsWith("session:") || scope.startsWith("project:") ? scope
    : scope === "session" ? throwMissing("session scope needs an id: --scope session:<id>")
    : scope === "project" ? `project:${resolve(".")}` : throwMissing(`unknown scope ${scope} (use global | project | project:<path> | session:<id>)`);
  const span = msSince(expiresAt);
  const defaultSpan = DEFAULT_EXPIRY[resolved.split(":")[0]];
  const at = expiresAt ? (span === null ? new Date(Date.parse(expiresAt)) : new Date(Date.now() + span)) : new Date(Date.now() + (defaultSpan ?? 0));
  const { rulings } = loadRulings(env, { warnStream });
  if (!rulings) throw new Error("rulings store is unreadable — fix or remove it before adding rulings");
  const ruling = {
    id: `r-${crypto.randomUUID().slice(0, 8)}`,
    effect, pattern, ...(tool ? { tool } : {}),
    scope: resolved,
    expiresAt: Number.isNaN(Date.parse(at)) ? throwMissing(`bad --expires ${expiresAt}`) : at.toISOString(),
    reason: reason ?? "",
    createdAt: new Date().toISOString(),
  };
  save(rulings.concat(ruling), env, { action: "add", ruling: ruling.id, effect, pattern, scope: resolved, via: op.via });
  return ruling;
}

function throwMissing(msg) { throw new Error(msg); }
function msSince(s) {
  const m = typeof s === "string" && s.match(/^(\d+)([dhm])$/);
  if (!m) return null;
  return +m[1] * { d: 864e5, h: 36e5, m: 6e4 }[m[2]];
}

export function revokeRuling(id, env = process.env, { warnStream, ...authority } = {}) {
  const op = operatorContext(env, authority);  // same library gate: revoking a ruling is also a mutation
  const { rulings } = loadRulings(env, { warnStream });
  if (!rulings) throw new Error("rulings store is unreadable");
  const kept = rulings.filter((r) => r.id !== id);
  if (kept.length === rulings.length) throw new Error(`no ruling ${id}`);
  const revoked = rulings.find((r) => r.id === id);
  save(kept, env, { action: "revoke", ruling: id, effect: revoked.effect, pattern: revoked.pattern, scope: revoked.scope, via: op.via });
  return true;
}

export function listRulings(env = process.env, { warnStream } = {}) {
  return loadRulings(env, { warnStream }).rulings ?? [];
}

// First-session bootstrap (the `setup` tracer): create the stranger-owned EMPTY store. No
// operator authority is needed or checked — an empty store grants nothing, so an agent can
// run this end to end (unlike add/revoke, which stay operator-gated). Mirrors save()'s write
// pattern: the pairing audit row is appended BEFORE the store write, so the store is
// tamper-clean from birth (a crash in between leaves an orphan row, never a moved mtime
// without one). Idempotent: an existing store is left untouched and no second init row lands.
// Returns true when the store was created, false when it already existed.
export function initStore(env = process.env) {
  if (existsSync(rulingsFile(env))) return false;
  mkdirSync(home(env), { recursive: true, mode: 0o700 });
  appendFileSync(auditFile(env), JSON.stringify({ at: new Date().toISOString(), action: "init", op: "init", via: "setup" }) + "\n", { mode: 0o600 });
  writeFileSync(rulingsFile(env), "[]\n", { mode: 0o600 });
  return true;
}

function save(rulings, env = process.env, mutation) {
  mkdirSync(home(env), { recursive: true, mode: 0o700 });
  // Append the pairing audit row BEFORE the store write: a crash in between leaves an orphan row
  // (audit newer than mtime → tamper check stays silent — harmless), whereas the reverse order
  // leaves a moved mtime with no row → a false tamper warning on the next consult.
  try {
    appendFileSync(auditFile(env), JSON.stringify({ at: new Date().toISOString(), action: "mutation", op: mutation.action, ruling: mutation.ruling,
      effect: mutation.effect, pattern: mutation.pattern, scope: mutation.scope, via: mutation.via }) + "\n", { mode: 0o600 });
  } catch (err) { warn(`could not write the rulings mutation row (${err.message})`); }
  writeFileSync(rulingsFile(env), JSON.stringify(rulings, null, 2) + "\n", { mode: 0o600 });
}
