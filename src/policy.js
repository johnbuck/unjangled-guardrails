// CONFIG (consolidation 2026-10-20, plan-consolidation-two-layers): layer 3 of the two-layer
// gate — the per-install, operator-owned policy that applies effects to the brain's verdict,
// and the ONLY standing-posture surface. One store, two match dimensions:
//
//   tool entries    { kind: "tool", pattern, effect, at, reason } — the shipped user-lane
//                   semantics: effects allow | deny | ask on tool-name patterns (exact /
//                   server-wide boundary-prefix / trailing-star prefix / verb-class), the
//                   most-specific pattern wins, equal-specificity ties resolve deny > ask >
//                   allow. Deterministic — they hold in every posture, brain down included.
//   command entries { kind: "command", pattern, effect, scope, expiresAt, reason, tool? }
//                   — the rulings folded in: glob-matched command entries with the rulings'
//                   scope + expiry features. Semantics per today's rulings: an allow entry
//                   lifts asks AND denies (the deliberate, audited operator act), a deny entry
//                   hard-blocks a brain allow.
//   dir entries     { kind: "dir", path, effect, expiresAt?, id, at, reason } — the confined-work
//                   surface (2026-10-20; optional expiry 2026-11-10, operator ruling 5):
//                   "calls whose argument paths ALL resolve under this directory
//                   take this effect". POST-brain verdict modifiers only — every call still
//                   goes through the brain (operator correction, verbatim force: "ALL THESE
//                   CALLS SHOULD STILL GO THROUGH THE BRAIN. THE ONLY THING THIS SHOULD DO IS
//                   PUSH AN ASK INTO AN ALLOW IF IT IS NOT DANGEROUS"): allow turns a brain
//                   ask into an allow for in-dir work, deny hard-blocks and ask forces a
//                   prompt over any non-denied verdict, and the brain's deny line plus
//                   Always-Deny outrank every dir effect.
//
// The store lives at GUARD_HOME/user-policy.json (0600); every mutation appends to the one
// audit file (rulings-use.jsonl) and is operator-gated HERE (operatorContext, the rulings
// gate) — no entry point can self-grant. A legacy rulings.json and/or user-lane.json migrates
// into the store on first run. The suggested defaults (examples/user-policy.default.json) are
// NEVER auto-applied: `policy adopt-defaults` merges them on explicit operator command.
import { readFileSync, writeFileSync, mkdirSync, appendFileSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, dirname, join, resolve, sep } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  guardHome, operatorContext, warn, matches as entryMatches, unexpired, subCommands, isBashShaped,
  appendAudit, auditFile, rulingsFile, msSince, withStoreLock, atomicWrite, tamperCheck,
} from "./rulings.js";

export function policyFile(env = process.env) {
  return join(guardHome(env), "user-policy.json");
}

// The legacy stores the consolidation folded in. They are migration SOURCES only — once the
// policy store exists they are dead weight (guarded paths, never consulted).
const legacyLaneFile = (env = process.env) => join(guardHome(env), "user-lane.json");

const EFFECTS = ["allow", "deny", "ask"];
const COMMAND_EFFECTS = ["allow", "deny"];  // ask is a tool-pattern effect: a command ask has no flip semantics
const EFFECT_RANK = { deny: 3, ask: 2, allow: 1 };

// ── load + first-run migration ────────────────────────────────────────────────────────────────
// Unreadable/absent store = an empty policy; the gate runs unchanged (fail-safe direction).
// On the FIRST run after the consolidation, a legacy rulings.json and/or user-lane.json is
// migrated in (operator-approved migration, plan T5): the audit row lands BEFORE the store
// write (save()'s pairing discipline), so the store is tamper-clean from birth. A fresh
// install (neither legacy store, nothing to migrate) writes nothing — the store is created
// by the first mutation, and the gate behaves as: Always-Deny judges, the brain judges, no
// config effects.
export function loadPolicyStore(env = process.env, { warnStream } = {}) {
  let raw;
  try {
    raw = readFileSync(policyFile(env), "utf8");
  } catch (err) {
    if (err.code !== "ENOENT") warn(`user-policy store unreadable (${err.message}) — running with an empty policy`, warnStream);
    if (err.code === "ENOENT") return migrateOnFirstRun(env, { warnStream });
    return { version: 1, entries: [] };
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || !Array.isArray(parsed.entries)) throw new Error("user-policy.json has no entries array");
    return parsed;
  } catch (err) {
    warn(`user-policy store corrupt (${err.message}) — running with an empty policy`, warnStream);
    return { version: 1, entries: [], corrupt: true };
  }
}

function migrateOnFirstRun(env, { warnStream } = {}) {
  let rulings = [];
  let ruledFrom = false;
  try {
    const parsed = JSON.parse(readFileSync(rulingsFile(env), "utf8"));
    if (Array.isArray(parsed)) { rulings = parsed; ruledFrom = true; }
    else throw new Error("rulings.json is not an array");
  } catch (err) {
    if (err && err.code === "ENOENT") { /* no legacy rulings store — nothing to migrate from it */ }
    else {
      // A corrupt legacy store is a LOUD event, not a silent skip: the operator must re-check
      // it (the old loadRulings contract, carried through the migration path). The store is
      // marked corrupt so mutations refuse until it is fixed — never add onto unknown state.
      warn(`rulings store corrupt (${err.message}) — ignoring rulings, the brain still gates`, warnStream);
      return { version: 1, entries: [], corrupt: true };
    }
  }
  let lanes = [];
  let lanedFrom = false;
  try {
    const parsed = JSON.parse(readFileSync(legacyLaneFile(env), "utf8"));
    if (parsed && Array.isArray(parsed.tools)) { lanes = parsed.tools; lanedFrom = true; }
  } catch (err) {
    if (err && err.code !== "ENOENT") warn(`user-lane store unreadable (${err.message}) — running with an empty lane`, warnStream);
  }
  if (!ruledFrom && !lanedFrom) return { version: 1, entries: [] };  // fresh install: no store file, nothing adopted
  const entries = [
    ...rulings.filter((r) => r && typeof r === "object").map((r) => ({ ...r, kind: "command" })),
    ...lanes.map((t) => (typeof t === "string" ? { kind: "tool", pattern: t, effect: "allow" } : { effect: "allow", ...t, kind: "tool" })),
  ].filter((e) => e.pattern);
  try {
    mkdirSync(guardHome(env), { recursive: true, mode: 0o700 });
    // Pairing row BEFORE the store write (the save() discipline): a crash in between leaves an
    // orphan row, never a moved mtime without one.
    appendFileSync(auditFile(env), JSON.stringify({ at: new Date().toISOString(), action: "migration", op: "migrate",
      rulings: rulings.length, lane: lanes.length, via: "first-run" }) + "\n", { mode: 0o600 });
    atomicWrite(policyFile(env), JSON.stringify({ version: 1, entries }, null, 2) + "\n");
    warn(`migrated ${rulings.length} ruling(s) and ${lanes.length} lane entr(ies) into ${policyFile(env)}`, warnStream);
  } catch (err) {
    warn(`could not write the migrated policy store (${err.message}) — running with the migrated entries in memory`, warnStream);
  }
  return { version: 1, entries };
}

// ── tool entries (the user-lane surface) ──────────────────────────────────────────────────────
// verb-class form: "<server-prefix>*@<class>" — the class is matched as a PREFIX of the
// tool's final segment, so "@read" covers read/read_file/read_many_files but not "recall"
// ("recall" starts with "rec", not "rea").
export function toolPatternMatches(pattern, name) {
  const p = String(pattern ?? "").trim();
  const n = String(name ?? "");
  if (!p || !n) return false;
  if (p.endsWith("*")) return n.toLowerCase().startsWith(p.slice(0, -1).toLowerCase());
  const vc = p.match(/^(.*)\*@([a-zA-Z-]+)$/);
  if (vc) {
    const base = vc[1].replace(/\*$/, "").toLowerCase();
    if (!n.toLowerCase().startsWith(base)) return false;
    const verb = n.slice(n.lastIndexOf("__") + 2);
    return verb.toLowerCase().startsWith(vc[2].toLowerCase());
  }
  // Exact, or server-wide: the pattern is a name-prefix ending at a segment boundary
  // ("mcp__server__tool" vs "mcp__server" — the boundary must be the segment separator, so
  // partial segments never creep in). Case-insensitive like the coordination hardcode it
  // replaced: harnesses deliver capitalized names (ListAgents, TaskStop, CronCreate) and
  // operators write patterns in the documented spelling.
  const ln = n.toLowerCase();
  const lp = p.toLowerCase();
  return ln === lp || (ln.startsWith(lp) && ln.charAt(lp.length) === "_");
}

// The most-specific matching entry wins: exact name match beats everything; otherwise the
// longest matching pattern (server prefixes, verb classes); equal-length ties resolve
// deny > ask > allow (safety-first among equally specific operator statements).
// Deterministic — no brain consulted — so effects hold in every posture, degraded included.
export function toolEffect(tool, env = process.env, opts = {}) {
  const n = String(tool ?? "");
  let best = null;
  for (const entry of loadPolicyStore(env, opts).entries ?? []) {
    if ((entry.kind ?? "tool") !== "tool") continue;
    const pattern = String(entry.pattern ?? "");
    const effect = entry.effect || "allow";
    if (!toolPatternMatches(pattern, n)) continue;
    const exact = n.toLowerCase() === pattern.toLowerCase() ? 1 : 0;
    const score = exact * 10000 + pattern.length * 10 + (EFFECT_RANK[effect] ?? 1);
    if (!best || score > best.score) best = { effect, pattern, id: entry.id, score };
  }
  return best ? { effect: best.effect, pattern: best.pattern, id: best.id } : null;
}

// ── command entries (the rulings surface) ─────────────────────────────────────────────────────
// The resolution order (spec addendum, Story 10, carried verbatim):
//   brain deny  → deny — no ALLOW seek unless an entry lifts it (below); a deny entry never applies to a deny
//   brain ask   → first matching unexpired allow entry wins
//   brain allow → first matching unexpired deny entry wins (the operator's hard block)
// The returned entry carries its id so the caller can cite it; every fired decision appends
// an audit row.
export function commandConsult(level, { tool, input, cwd, sessionId, env = process.env, warnStream } = {}) {
  tamperCheck(env, warnStream);  // the consult is the read that notices an unpaired store write
  const { entries } = loadPolicyStore(env, { warnStream });
  const want = level === "allow" ? "deny" : "allow";  // seek a lifter for ask AND deny; a deny entry only hard-blocks allows
  const entry = (entries ?? []).find((r) => (r.kind ?? "tool") === "command" && r.effect === want && unexpired(r) &&
    entryMatches(r, { tool, preview: subCommands(input, tool), cwd, sessionId }));
  if (entry) appendAudit(entry, level, { tool, input, cwd, sessionId, env });
  return entry ?? null;
}

// ── directory entries (the confined-work surface, 2026-10-20) ─────────────────────────────────
// A call is covered by a dir entry when it has at least one resolvable path argument and EVERY
// resolvable path argument resolves under the entry's directory (path === dir, or startsWith
// dir + separator). Candidate extraction, v1:
//   file-shaped tools (the read/write families the Always-Deny shaped matchers already name,
//   plus the search/list spellings; mcp filesystem-style names ride the same suffix families)
//   contribute their path/file_path/PATH/notebook_path arguments;
//   bash-shaped tools contribute their ABSOLUTE and ~/-rooted tokens per sub-command segment
//   (redirect targets included — a leading >, >> or 2> prefix is stripped before resolution);
//   bare relative names are NOT path arguments — the call falls through to normal judgment.
// Paths match AS WRITTEN (absolute/tilde only): no cwd resolution, no realpath — a symlink
// that leaves the directory is a v1 accepted residual (the brain still judged the call).
// Most-specific covering entry wins (longest directory path; same-path ties resolve
// deny > ask > allow, the tool-entry convention). Deterministic — no brain consulted — so
// effects hold in every posture, brain down included. Optional expiry (ruling 5, GHI-17):
// a lapsed statement never covers — checked at consult time, exactly like command entries.

// The redirect operators that glue onto their target path (>/x, >>/x, 2>/x, 2>>/x, and the
// input form </x): stripped so the target resolves as an ordinary token — an input redirect
// reading OUTSIDE the directory must kill coverage exactly like a written path would.
const REDIRECT_PREFIX = /(^|[\s'"=(])(?:2>>|2>|>>|>|<)(?=(?:\/|~\/))/g;
const BASH_PATH_TOKEN = /(?:^|[\s'"=(])((?:\/|~\/)[^\s'"`;|&]*)/g;
const FILE_SHAPED_TOOL = /^(read|view|cat|notebookread|read_file|read_many_files|list_directory|search_file_content|grep_search|glob|grep|ls|list|find|search_files|write|edit|notebookedit|multiedit|write_file|replace|apply_patch|patch|delete)$|(^|_)(read|write|edit|delete)$/i;
const PATH_KEYS = ["path", "file_path", "filePath", "PATH", "notebook_path"];  // filePath: the camelCase spelling the Always-Deny legs read

const normalizeDir = (p) => {
  const r = resolve(String(p ?? ""));
  return r.length > 1 ? r.replace(/[\\/]+$/, "") : r;  // keep the root "/" bare
};
const expandTilde = (p) => (p === "~" || p.startsWith("~/") ? join(homedir(), p.slice(1)) : p);
const underDir = (p, dir) => (dir === sep ? p.startsWith(sep) : p === dir || p.startsWith(dir + sep));

// "mcp filesystem-style": the family is judged on the whole name AND the final `__` segment
// (mcp__filesystem__read_file carries read_file; the same families the verb-class patterns use).
const isFileShaped = (name) => {
  const n = String(name ?? "");
  const i = n.lastIndexOf("__");
  return FILE_SHAPED_TOOL.test(n) || (i >= 0 && FILE_SHAPED_TOOL.test(n.slice(i + 2)));
};

/** The call's resolvable path arguments: tilde-expanded absolute paths. Empty when the call
 *  carries none (bash without absolute/tilde tokens, non-file-shaped tools) — not covered,
 *  the plain verdict stands. */
export function pathArguments(tool, input) {
  if (isBashShaped(tool, input)) {
    const out = [];
    for (const seg of subCommands(input, tool)) {
      const cleaned = seg.replace(REDIRECT_PREFIX, "$1");
      for (const m of cleaned.matchAll(BASH_PATH_TOKEN)) out.push(expandTilde(m[1]));
    }
    return out;
  }
  if (!isFileShaped(tool)) return [];
  return PATH_KEYS.map((k) => input?.[k]).filter((v) => typeof v === "string" && v.trim()).map((v) => expandTilde(v.trim()));
}

/** The most-specific covering directory entry: { effect, path, id } of the longest-path entry
 *  whose directory covers every resolvable path argument, or null. */
export function dirEffect(tool, input, { cwd, env = process.env, warnStream } = {}) {
  void cwd;  // v1 matches absolute/tilde tokens as written; no cwd resolution
  const paths = pathArguments(tool, input);
  if (!paths.length) return null;
  let best = null;
  for (const entry of loadPolicyStore(env, { warnStream }).entries ?? []) {
    if (entry.kind !== "dir") continue;
    // Ruling 5 (GHI-17): a lapsed statement never covers — the same consult-time expiry
    // check commandConsult applies to command entries; the row stays listed [EXPIRED],
    // never purged (nothing deleted by hand, nothing deleted by code).
    if (!unexpired(entry)) continue;
    const dir = normalizeDir(entry.path);
    const effect = entry.effect || "allow";
    if (!paths.every((p) => underDir(p, dir))) continue;
    const score = dir.length * 10 + (EFFECT_RANK[effect] ?? 1);
    if (!best || score > best.score) best = { effect, path: dir, id: entry.id, score };
  }
  return best ? { effect: best.effect, path: best.path, id: best.id } : null;
}

// ── mutations (operator-gated, audited, locked) ───────────────────────────────────────────────
// The id distinguishes every operator-meaningful entry: two grants differing only by scope or
// expiry are different statements and must revoke independently (found live 2026-10-20: a
// /prod grant and a /staging ban on one pattern collided into one id).
const entryId = (kind, pattern, tool, scope, expiresAt) =>
  (kind === "command" ? "p-" : "t-") +
  createHash("sha256").update(`${kind}\0${pattern}\0${tool ?? ""}\0${scope ?? ""}\0${expiresAt ?? ""}`).digest("hex").slice(0, 4);

// Dir entries hash path + expiry (operator ruling 5, 2026-11-09, GHI-17): one statement
// per (directory, expiry) — `/scratch allow 7d` and `/scratch allow 30d` are different
// statements that must revoke independently, and widening is add-the-new-and-let-the-old-
// expire, nothing deleted by hand. Changing an effect is still remove + re-add (each
// deliberate, each audited) — never a silent overwrite of the standing posture.
const dirEntryId = (path, expiresAt) =>
  "d-" + createHash("sha256").update(`${path}\0${expiresAt ?? ""}`).digest("hex").slice(0, 4);

// Every mutation refuses a corrupt store: unknown state is never mutated or added onto (the
// old addRuling contract — fix or remove the store first). The corrupt flag itself never
// serializes: a refused flag written into an otherwise-valid file would wedge every later
// add even after the operator fixed the legacy source. A corrupt store stays corrupt (and
// mutation-refusing) until hand-fixed or deleted — that is the module contract.
function assertWritable(store) {
  if (store && store.corrupt) throw new Error("the store is unreadable — fix or remove it (and its legacy rulings/lane sources) before adding entries");
}

function saveStore(store, env, mutation) {
  mkdirSync(guardHome(env), { recursive: true, mode: 0o700 });
  // Pairing audit row BEFORE the store write: a crash in between leaves an orphan row (audit
  // newer than mtime → tamper check stays silent — harmless), whereas the reverse order
  // leaves a moved mtime with no row → a false tamper warning on the next consult. The row
  // keeps the old mutation shape (action "mutation" + op), so the tamper-evidence contract
  // and every reader of the audit log carry over the fold-in unchanged; a caller may hand a
  // complete `row` object instead (same pairing discipline, own vocabulary — the session-end
  // cleanup below writes its policy-remove row that way).
  try {
    appendFileSync(auditFile(env), JSON.stringify(mutation.row ?? { at: new Date().toISOString(), action: "mutation", op: mutation.op,
      ruling: mutation.id, effect: mutation.effect, pattern: mutation.pattern, scope: mutation.scope, via: mutation.via }) + "\n", { mode: 0o600 });
  } catch (err) { warn(`could not write the policy mutation row (${err.message})`); }
  delete store.corrupt;  // never persist the in-memory corruption marker
  atomicWrite(policyFile(env), JSON.stringify(store, null, 2) + "\n");
}

/** Add a tool-pattern entry (the `lane add` semantics: idempotent on the same pattern). */
export function addToolEntry({ pattern, effect, reason }, env = process.env, authority = {}) {
  const op = operatorContext(env, authority);
  const p = String(pattern ?? "").trim();
  const e = String(effect ?? "allow").toLowerCase();
  if (!p) throw new Error("a tool entry requires --tool <pattern>");
  if (!EFFECTS.includes(e)) throw new Error(`effect must be one of: ${EFFECTS.join(", ")}`);
  return withStoreLock(env, () => {
    const store = loadPolicyStore(env);
    assertWritable(store);
    store.entries = Array.isArray(store.entries) ? store.entries : [];
    const existing = store.entries.find((t) => (t.kind ?? "tool") === "tool" && t.pattern === p);
    if (existing) return { ...existing, existed: true };
    const entry = { id: entryId("tool", p), kind: "tool", pattern: p, effect: e, at: new Date().toISOString(), ...(reason ? { reason } : {}) };
    store.entries.push(entry);
    saveStore(store, env, { action: "policy-add", op: "add-tool", id: entry.id, effect: e, pattern: p, via: op.via });
    return { ...entry, existed: false };
  });
}

// GHI-7 (CAP-14): `--expires never` is the explicit permanent spelling — the exact
// statement `policy list` already renders for an entry with no expiry — normalized to an
// ABSENT field (never a sentinel string), so every downstream consumer (unexpired, the
// [EXPIRED] render, id hashing, the decision export) keeps reading the permanent shape.
// GHI-17 (operator ruling 5, 2026-11-09): dir entries carry expiry like command entries —
// ONE grammar, ONE parser; both kind-minters call it, so the kinds can never drift. Any
// value that is neither `never` (case-folded) nor an Nd/Nh/Nm span nor a parseable ISO
// date refuses with the accepted forms HERE, before any store write; a resolved date in
// the past refuses the same way. Returns { explicit, at }: explicit = a value was given
// (never included), at = the resolved absolute Date, null for never/absent.
function parseExpiresAt(expiresAt) {
  const neverExpires = typeof expiresAt === "string" && expiresAt.trim().toLowerCase() === "never";
  if (expiresAt !== undefined && !neverExpires && msSince(expiresAt) === null && Number.isNaN(Date.parse(expiresAt)))
    throw new Error(`bad --expires ${expiresAt} (accepted: <ISO date> | 7d | 12h | 30m | never)`);
  const span = neverExpires ? null : msSince(expiresAt);
  const at = expiresAt !== undefined && !neverExpires ? (span === null ? new Date(Date.parse(expiresAt)) : new Date(Date.now() + span)) : null;
  if (at && at.getTime() <= Date.now()) throw new Error(`expiry must be in the future (got ${at.toISOString()})`);
  return { explicit: expiresAt !== undefined, at };
}

/** Add a command-pattern entry (the `ruling add` semantics, standing form allowed). */
export function addCommandEntry({ effect, pattern, stages, tool, scope = "project", expiresAt, reason }, env = process.env, authority = {}) {
  const { warnStream, ...opAuthority } = authority ?? {};
  const op = operatorContext(env, opAuthority);
  if (effect !== "allow" && effect !== "deny") throw new Error("effect must be allow or deny");
  if (stages !== undefined) {
    if (!Array.isArray(stages) || stages.length === 0 || !stages.every((s) => typeof s === "string" && s.trim())) {
      throw new Error("stages must be a non-empty array of command globs (one per chain segment)");
    }
    if (pattern) throw new Error("use either --pattern or repeated --pattern (stages), not a mix");
    pattern = stages.join(" && ");
  } else if (!pattern) {
    throw new Error("pattern is required (a command glob, e.g. 'git push *')");
  }
  stages = Array.isArray(stages) ? stages.map((s) => s.trim()) : undefined;
  // The prefix-glob over-match warning fires on GLUED-star patterns only (`rm*` also matches
  // 'rmarkdown') and the bare catch-all: a SPACED trailing star (`git push *`, `cat *`)
  // already pins the subcommand — the warning's own recommended shape, the house defaults'
  // own entries, and the CAP-7 unblock suggestions all carry it, and warning there would
  // contradict the fix this text prescribes (found live in the suite's baseline output:
  // `cat *`, `ls *`, `grep *`, `kubectl get *` all warned against themselves).
  if (!stages && (String(pattern) === "*" || /\S\*$/.test(String(pattern))))
    warn(`'${pattern}' is a prefix glob: it matches more than the literal command ('rm*' also matches 'rmarkdown'). Consider a tighter pattern that pins the sub-command, e.g. 'rm -rf <exact path>' or a pattern that names the sub-command`, warnStream);
  // Scope resolution: the rulings grammar, carried verbatim — but a GLOBAL command entry may
  // stand WITHOUT an expiry here: the config surface is the per-install, operator-owned
  // standing posture (the same trust level as a tool entry), adopted or removed deliberately.
  // The `ruling add` alias keeps the old refusal for one release (cli.js).
  const resolved = scope === "global" ? "global"
    : scope.startsWith("session:") || scope.startsWith("project:") ? scope
    : scope === "session" ? throwMissing("session scope needs an id: --scope session:<id>")
    : scope === "project" ? `project:${resolve(".")}` : throwMissing(`unknown scope ${scope} (use global | project | project:<path> | session:<id>)`);
  // The one --expires grammar (parseExpiresAt above): an explicit value (never included) is
  // exactly what was typed — never defaulted; an ABSENT flag takes the scope-derived
  // default span below (the line the rules-doc drift alarm pins — keep the shape).
  const expiry = parseExpiresAt(expiresAt);
  const defaultSpan = { session: 7 * 864e5, project: 30 * 864e5 }[resolved.split(":")[0]];
  const at = expiry.at ?? (!expiry.explicit && defaultSpan ? new Date(Date.now() + defaultSpan) : null);
  return withStoreLock(env, () => {
    const store = loadPolicyStore(env);
    assertWritable(store);
    store.entries = Array.isArray(store.entries) ? store.entries : [];
    // validated above: `at` is always a real date here (span forms construct one directly,
    // ISO forms passed Date.parse) — the old buried `bad --expires` throw from this spot
    // is the pre-validation remnant GHI-7 removed.
    const expiresIso = at ? at.toISOString() : undefined;
    const entry = {
      id: entryId("command", pattern, tool, resolved, expiresIso),
      kind: "command",
      effect, pattern, ...(Array.isArray(stages) ? { stages } : {}), ...(tool ? { tool } : {}),
      scope: resolved,
      ...(at ? { expiresAt: expiresIso } : {}),
      reason: reason ?? "",
      createdAt: new Date().toISOString(),
      // Prompt-authority captures (rulings.js capturePromptRuling, the only constructor of a
      // prompt:* via) carry their provenance and minting session on the entry — additive
      // fields every other consumer ignores; they drive the per-session write cap and the
      // rulings-list provenance marker. Operator-minted entries carry neither.
      ...(op.via?.startsWith("prompt:") ? { via: op.via, ...(op.session ? { session: op.session } : {}) } : {}),
    };
    const existing = store.entries.find((t) => (t.kind ?? "tool") === "command" && t.pattern === pattern && (t.tool ?? "") === (tool ?? "") && (t.scope ?? "global") === resolved);
    if (existing) return { ...existing, existed: true };
    store.entries.push(entry);
    saveStore(store, env, { action: "policy-add", op: "add-command", id: entry.id, effect, pattern, scope: resolved, via: op.via });
    return { ...entry, existed: false };
  });
}

/** Add a directory entry (`policy add --dir <absolute path> --effect allow|ask|deny
 *  [--expires <ISO date> | 7d | 12h | 30m | never]`): calls whose argument paths all resolve
 *  under the directory take the effect — applied POST-brain (see dirEffect); the entry never
 *  replaces judgment. Operator ruling 5 (2026-11-09, GHI-17): dir entries carry expiry like
 *  command entries — the same grammar (parseExpiresAt, the one parser), absent = permanent
 *  (NO default span: dir entries have no scope dimension), `never` = the explicit permanent
 *  spelling, minted as NO field. Idempotent on the same (normalized path, expiry) statement
 *  like the tool surface; a NEW expiry on the same path is a NEW statement — widening is
 *  add-new-and-let-old-expire, nothing deleted by hand. */
export function addDirEntry({ path: rawPath, effect, expiresAt, reason }, env = process.env, authority = {}) {
  const op = operatorContext(env, authority);
  const p = String(rawPath ?? "").trim();
  const e = String(effect ?? "allow").toLowerCase();
  if (!p) throw new Error("a dir entry requires --dir <absolute path>");
  if (!isAbsolute(p)) throw new Error(`dir entries take an absolute path (got '${p}')`);
  if (!EFFECTS.includes(e)) throw new Error(`effect must be one of: ${EFFECTS.join(", ")}`);
  const expiry = parseExpiresAt(expiresAt);
  const expiresIso = expiry.at ? expiry.at.toISOString() : undefined;
  const dir = normalizeDir(p);
  return withStoreLock(env, () => {
    const store = loadPolicyStore(env);
    assertWritable(store);
    store.entries = Array.isArray(store.entries) ? store.entries : [];
    const existing = store.entries.find((t) => t.kind === "dir" && t.path === dir && (t.expiresAt ?? "") === (expiresIso ?? ""));
    if (existing) return { ...existing, existed: true };
    const entry = { id: dirEntryId(dir, expiresIso), kind: "dir", path: dir, effect: e, at: new Date().toISOString(), ...(expiresIso ? { expiresAt: expiresIso } : {}), ...(reason ? { reason } : {}) };
    store.entries.push(entry);
    saveStore(store, env, { action: "policy-add", op: "add-dir", id: entry.id, effect: e, pattern: dir, via: op.via });
    return { ...entry, existed: false };
  });
}

/** Remove one entry by id, exact pattern, or dir path (any kind). A dir path in raw spelling
 *  (`/tmp/`) matches the normalized entry: the same trailing-slash strip the stored path
 *  carries runs over the argument before the dir comparison. */
export function removeEntry(idOrPattern, env = process.env, authority = {}) {
  const op = operatorContext(env, authority);
  return withStoreLock(env, () => {
    const store = loadPolicyStore(env);
    assertWritable(store);
    store.entries = Array.isArray(store.entries) ? store.entries : [];
    const before = store.entries.length;
    const key = String(idOrPattern ?? "");
    const dirKey = key.length > 1 ? key.replace(/[\\/]+$/, "") : key;
    store.entries = store.entries.filter((t) => t.id !== idOrPattern && t.pattern !== idOrPattern && t.path !== dirKey);
    if (store.entries.length === before) return { removed: false };
    saveStore(store, env, { action: "policy-remove", op: "remove", id: idOrPattern, via: op.via });
    return { removed: true };
  });
}

/** Expire one session's prompt-captured grants (epic-prompt-rulings-session story 2, the
 *  R-2 cleanup half): the harness announced that session's end, so its prompt-captured
 *  session-scope allow entries die NOW instead of at the 24h mint-time cap. Scope discipline
 *  is hard: only kind command + effect allow + scope exactly `session:<sessionId>` + via
 *  `prompt:*` entries are eligible — operator-minted 7d session rulings (no via), project
 *  captures (cross-session by design), denies, and every other session are never touched.
 *  The mutation only ever REMOVES allows — it can mint nothing, so it runs un-gated on
 *  operator authority (the initStore precedent: never-mints mutations stay audited and
 *  tamper-clean, `via: "session-end:<harness>"` names the announcing channel, not an
 *  operator). A cleanup that removes nothing writes nothing (removeEntry's `removed:false`
 *  precedent — repeated session-end signals never spam the audit log); a corrupt store
 *  refuses like every mutation (throw; the caller catches and the 24h cap stays the
 *  backstop). The session id comes from the caller; the scope string is built here, never
 *  caller-supplied.
 *
 *  @param {string} sessionId  the harness session that ended
 *  @param {object} [env]      process env shape (GUARD_HOME)
 *  @param {{harness?: string, warnStream?: object}} [opts]  the announcing harness (row
 *    vocabulary, e.g. "claude" | "pi" | "acp") and the warn stream for load noise
 *  @returns {{removed: number}} how many prompt-captured grants died (0 = nothing to do) */
export function expirePromptSession(sessionId, env = process.env, { harness, warnStream } = {}) {
  if (typeof sessionId !== "string" || !sessionId.trim()) throw new Error("expirePromptSession needs the session id of the session that ended");
  if (harness !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(String(harness)))
    throw new Error("expirePromptSession's harness must name the announcing channel (letters/digits/._- — e.g. 'claude', 'pi', 'acp')");
  const scope = `session:${sessionId}`;
  return withStoreLock(env, () => {
    const store = loadPolicyStore(env, { warnStream });
    assertWritable(store);
    store.entries = Array.isArray(store.entries) ? store.entries : [];
    const doomed = store.entries.filter((t) =>
      (t.kind ?? "tool") === "command" && t.effect === "allow" && (t.scope ?? "global") === scope && String(t.via ?? "").startsWith("prompt:"));
    if (!doomed.length) return { removed: 0 };
    store.entries = store.entries.filter((t) => !doomed.includes(t));
    saveStore(store, env, {
      row: { at: new Date().toISOString(), action: "policy-remove", op: "expire-prompt-session",
        id: scope, pattern: `${doomed.length} prompt-captured ruling(s)`, scope, via: `session-end:${harness ?? "unknown"}` },
    });
    return { removed: doomed.length };
  });
}

export function listEntries(env = process.env, opts = {}) {
  return loadPolicyStore(env, opts).entries ?? [];
}

// ── store visibility (CAP-5, epic-github-field-reports entry 5 / GitHub issue 5) ──────────────
// The split: GUARD_HOME means the store home to this gate, but a harness deployment (the
// Hermes adapter is the field report's shape) must set GUARD_HOME to the FORK ROOT so the
// plugin can spawn `node $GUARD_HOME/src/cli.js hook` — so the harness-side gate reads
// <fork-root>/user-policy.json while an operator terminal without GUARD_HOME writes
// ~/.unjangled-guardrails/user-policy.json. Two stores, no side able to see the other. The
// visibility contract, additive only (resolution semantics unchanged):
//   every policy/ruling/lane command prints the store file it touched (cli.js footer);
//   gate processes that SERVE a harness record their resolved store root here;
//   policy commands warn when a recorded harness reads a different store; `policy where`
//   prints the whole map. The registry anchors at the DEFAULT home — guardHome({}) — the one
// location findable from any terminal regardless of its own GUARD_HOME: a terminal and a
// harness sharing an exported GUARD_HOME (the documented checkout-pointing residual) record
// consistently and warn never; the warning fires exactly when the anchors disagree.
const HARNESS_FRESH_MS = 6 * 36e5;  // a matching record refreshes at most every 6h — no per-call writes

/** The harness store registry: `<default home>/harness-stores.json`. The default home is
 *  derived BLIND to the GUARD_HOME spellings (an env carrying GUARD_HOME — the harness
 *  shape — still anchors at the plain default home) but HONORING the env's own HOME, so a
 *  spawn env a harness controls and the in-process default agree: every terminal and every
 *  harness read and write the same file. (Written out rather than guardHome-derived:
 *  guardHome's default branch reads the PROCESS-level homedir, which a passed env cannot
 *  steer — the ".unjangled-guardrails" name is its default dir, kept in step by the
 *  store-resolution suite.) */
export function harnessStoreRegistryFile(env = process.env) {
  return join(env.HOME ?? homedir(), ".unjangled-guardrails", "harness-stores.json");
}

/** Read the registry: `{ harnesses: { <name>: { home, spell, at } } }`; a missing file is
 *  an empty registry, a corrupt one warns and reads empty (fail-safe — the next recording
 *  regenerates it). Never throws. */
export function readHarnessStores(env = process.env, { warnStream } = {}) {
  let raw;
  try { raw = readFileSync(harnessStoreRegistryFile(env), "utf8"); }
  catch { return { version: 1, harnesses: {} }; }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed.harnesses !== "object" || parsed.harnesses === null) throw new Error("no harnesses object");
    return { version: 1, harnesses: parsed.harnesses };
  } catch (err) {
    warn(`harness store registry unreadable (${err.message}) — treating it as empty; the next harness record rewrites it`, warnStream);
    return { version: 1, harnesses: {} };
  }
}

/** Which env spelling decided a store resolution: "GUARD_HOME" | "JEV_GUARD_HOME" |
 *  "default" (the guard home under the user's home directory). Exported for the CLI's
 *  where rendering — the same vocabulary the registry records per harness. */
export function storeSpell(env = process.env) {
  return env.GUARD_HOME !== undefined && env.GUARD_HOME !== "" ? "GUARD_HOME"
    : env.JEV_GUARD_HOME !== undefined && env.JEV_GUARD_HOME !== "" ? "JEV_GUARD_HOME" : "default";
}

/** One harness entry in the registry: the resolved store root and which spelling decided
 *  it, with the last-seen timestamp. */
function harnessRecord(env = process.env) {
  return { home: guardHome(env), spell: storeSpell(env) };
}

/** Record where a harness's policy store lives: `<default home>/harness-stores.json`
 *  gains/refreshes `harnesses[agent] = { home, spell, at }`. Called from gate processes that
 *  SERVE a harness (the hook's main, the ACP proxy, the opencode plugin entries) — never
 *  from library surfaces, so test fixtures cannot pollute the operator's registry. Guards,
 *  both fail-safe silent (returns false, never throws — visibility must not break a host):
 *   - the env must look like a real process env (PATH and HOME present): synthetic `{}`
 *     envs (parse tests, probes) are not deployments;
 *   - the resolved store root must not sit under the OS tmpdir: scratch fixtures never
 *     record, durable installs (real forks, the default home) always do.
 *  A matching, fresh record writes nothing (idempotent until 6h stale); all failures are
 *  swallowed — an unwritable default home costs the registry, never the call. */
export function recordHarnessStore(agent, env = process.env, { now = () => new Date().toISOString(), freshMs = HARNESS_FRESH_MS } = {}) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(String(agent ?? ""))) return false;  // the harness names the announcing channel (the expirePromptSession convention)
  if (!env.PATH || !env.HOME) return false;  // a process env without PATH/HOME is a probe, not a deployment
  const { home, spell } = harnessRecord(env);
  if (home === tmpdir() || home.startsWith(tmpdir() + sep)) return false;  // scratch roots never record
  try {
    const registry = readHarnessStores(env);
    const existing = registry.harnesses[agent];
    const at = now();
    if (existing && existing.home === home && existing.spell === spell && Date.parse(at) - Date.parse(existing.at ?? 0) < freshMs)
      return false;  // unchanged and fresh — no write
    registry.harnesses[agent] = { home, spell, at };
    const registryFile = harnessStoreRegistryFile(env);
    mkdirSync(dirname(registryFile), { recursive: true, mode: 0o700 });
    atomicWrite(registryFile, JSON.stringify(registry, null, 2) + "\n");
    return true;
  } catch {
    return false;
  }
}

/** Every recorded harness whose store root differs from the command's own resolution —
 *  the divergence set the CLI warns over. Empty when nothing is recorded. */
export function divergentHarnessStores(env = process.env) {
  const resolved = guardHome(env);
  return Object.entries(readHarnessStores().harnesses)
    .filter(([, r]) => (r?.home ?? "") !== resolved)
    .map(([harness, r]) => ({ harness, home: r.home, spell: r.spell, at: r.at }));
}

// ── suggested defaults (never auto-applied) ───────────────────────────────────────────────────
const EXAMPLE_DEFAULTS = join(fileURLToPath(new URL("..", import.meta.url)), "examples", "user-policy.default.json");

/** The suggested-defaults example file — exported so install-time surfaces (setup's
 *  empty-policy warning, the install checklist) name the same file `policy adopt-defaults`
 *  reads: one source of truth, no second spelling to drift. */
export function suggestedDefaultsFile() { return EXAMPLE_DEFAULTS; }

/** Merge the suggested-defaults example into the store, on explicit operator command only.
 *  Entries already present (same kind + pattern/path + tool binding) are skipped, never
 *  overwritten — adoption is additive. Returns the counts and the source file. */
export function adoptDefaults(env = process.env, { file, ...authority } = {}) {
  const op = operatorContext(env, authority);
  const source = file ?? EXAMPLE_DEFAULTS;
  let parsed;
  try { parsed = JSON.parse(readFileSync(source, "utf8")); }
  catch (err) { throw new Error(`could not read the suggested defaults (${err.message}): ${source}`); }
  const incoming = Array.isArray(parsed?.entries) ? parsed.entries : null;
  if (!incoming) throw new Error("the suggested-defaults file has no entries array");
  for (const e of incoming) {
    if (!e || typeof e !== "object") throw new Error("a suggested entry must be an object");
    if (e.kind === "dir") {
      if (!e.path) throw new Error("a suggested dir entry needs a path");
      const p = String(e.path).trim();
      if (!isAbsolute(p)) throw new Error(`dir entries take an absolute path (got '${p}')`);  // same bar addDirEntry enforces — normalizeDir's resolve must never anchor a relative path to the process cwd
      if (!EFFECTS.includes(e.effect ?? "allow")) throw new Error(`entry '${e.path}' carries an unknown effect`);
      continue;
    }
    if (!e.pattern) throw new Error("a suggested entry needs a pattern");
    const kind = e.kind === "command" ? "command" : "tool";
    if (!EFFECTS.includes(e.effect ?? "allow")) throw new Error(`entry '${e.pattern}' carries an unknown effect`);
    if (kind === "command" && !COMMAND_EFFECTS.includes(e.effect ?? "allow")) throw new Error(`command entry '${e.pattern}' must carry allow or deny (ask is a tool-pattern effect)`);
  }
  return withStoreLock(env, () => {
    const store = loadPolicyStore(env);
    assertWritable(store);
    store.entries = Array.isArray(store.entries) ? store.entries : [];
    let added = 0, skipped = 0;
    for (const e of incoming) {
      if (e.kind === "dir") {
        const dir = normalizeDir(e.path);
        // GHI-17: an example dir entry may carry expiresAt — honored verbatim like the
        // command entries in examples (the file is operator-trusted content), dupe-checked
        // by (path, expiry) exactly like addDirEntry, so adoption never mints a shadow twin.
        if (store.entries.find((t) => t.kind === "dir" && t.path === dir && (t.expiresAt ?? "") === (e.expiresAt ?? ""))) { skipped++; continue; }
        store.entries.push({ id: dirEntryId(dir, e.expiresAt), kind: "dir", path: dir, effect: e.effect ?? "allow", at: new Date().toISOString(), ...(e.expiresAt ? { expiresAt: e.expiresAt } : {}), ...(e.reason ? { reason: e.reason } : {}) });
        added++;
        continue;
      }
      const kind = e.kind === "command" ? "command" : "tool";
      const dupe = store.entries.find((t) => (t.kind ?? "tool") === kind && t.pattern === e.pattern && (t.tool ?? "") === (e.tool ?? "") && (t.scope ?? "global") === (e.scope ?? "global"));
      if (dupe) { skipped++; continue; }
      const effect = e.effect ?? "allow";
      store.entries.push(kind === "command"
        ? { id: entryId("command", e.pattern, e.tool, e.scope ?? "global", e.expiresAt), kind, effect, pattern: e.pattern, ...(e.stages ? { stages: e.stages } : {}), ...(e.tool ? { tool: e.tool } : {}), scope: e.scope ?? "global", ...(e.expiresAt ? { expiresAt: e.expiresAt } : {}), reason: e.reason ?? "", createdAt: new Date().toISOString() }
        : { id: entryId("tool", e.pattern, e.tool, e.scope), kind, effect, pattern: e.pattern, at: new Date().toISOString(), ...(e.reason ? { reason: e.reason } : {}) });
      added++;
    }
    saveStore(store, env, { action: "adopt-defaults", op: "adopt-defaults", id: `+${added}/=${skipped}`, via: op.via });
    return { added, skipped, source, via: op.via };
  });
}

/** Set the degradation posture (the resolved design decision 2): what an UNMATCHED call does
 *  while the brain is down. fail-open (default) passes it; fail-closed denies. Operator-gated
 *  and audited like every mutation. The env surface (GUARD_FALLBACK=closed) still wins over
 *  this per-install option. */
export function setDegradation(degradation, env = process.env, authority = {}) {
  const op = operatorContext(env, authority);
  if (degradation !== "fail-open" && degradation !== "fail-closed") throw new Error("degradation must be fail-open or fail-closed");
  return withStoreLock(env, () => {
    const store = loadPolicyStore(env);
    assertWritable(store);
    store.entries = Array.isArray(store.entries) ? store.entries : [];
    store.degradation = degradation;
    saveStore(store, env, { action: "policy-set", op: "set-degradation", id: degradation, via: op.via });
    return { degradation: store.degradation, via: op.via };
  });
}

function throwMissing(msg) { throw new Error(msg); }
