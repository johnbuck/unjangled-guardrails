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
//   dir entries     { kind: "dir", path, effect, id, at, reason } — the confined-work surface
//                   (2026-10-20): "calls whose argument paths ALL resolve under this directory
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
import { homedir } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";
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
// effects hold in every posture, brain down included.

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

// Dir entries hash the path only: one statement per directory. Changing an effect is remove +
// re-add (each deliberate, each audited) — never a silent overwrite of the standing posture.
const dirEntryId = (path) =>
  "d-" + createHash("sha256").update(path).digest("hex").slice(0, 4);

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
  // and every reader of the audit log carry over the fold-in unchanged.
  try {
    appendFileSync(auditFile(env), JSON.stringify({ at: new Date().toISOString(), action: "mutation", op: mutation.op,
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
  if (!stages && String(pattern).endsWith("*"))
    warn(`'${pattern}' is a prefix glob: it matches more than the literal command ('rm*' also matches 'rmarkdown'). Consider a tighter pattern that pins the sub-command, e.g. 'rm -rf <exact path>' or a pattern that names the sub-command`, warnStream);
  // Scope resolution: the rulings grammar, carried verbatim — but a GLOBAL command entry may
  // stand WITHOUT an expiry here: the config surface is the per-install, operator-owned
  // standing posture (the same trust level as a tool entry), adopted or removed deliberately.
  // The `ruling add` alias keeps the old refusal for one release (cli.js).
  const resolved = scope === "global" ? "global"
    : scope.startsWith("session:") || scope.startsWith("project:") ? scope
    : scope === "session" ? throwMissing("session scope needs an id: --scope session:<id>")
    : scope === "project" ? `project:${resolve(".")}` : throwMissing(`unknown scope ${scope} (use global | project | project:<path> | session:<id>)`);
  const span = msSince(expiresAt);
  const defaultSpan = { session: 7 * 864e5, project: 30 * 864e5 }[resolved.split(":")[0]];
  const at = expiresAt ? (span === null ? new Date(Date.parse(expiresAt)) : new Date(Date.now() + span))
    : defaultSpan ? new Date(Date.now() + defaultSpan) : null;
  if (at && at.getTime() <= Date.now()) throw new Error(`expiry must be in the future (got ${at.toISOString()})`);
  return withStoreLock(env, () => {
    const store = loadPolicyStore(env);
    assertWritable(store);
    store.entries = Array.isArray(store.entries) ? store.entries : [];
    const expiresIso = at && !Number.isNaN(Date.parse(at)) ? at.toISOString() : undefined;
    const entry = {
      id: entryId("command", pattern, tool, resolved, expiresIso),
      kind: "command",
      effect, pattern, ...(Array.isArray(stages) ? { stages } : {}), ...(tool ? { tool } : {}),
      scope: resolved,
      ...(at ? { expiresAt: Number.isNaN(Date.parse(at)) ? throwMissing(`bad --expires ${expiresAt}`) : at.toISOString() } : {}),
      reason: reason ?? "",
      createdAt: new Date().toISOString(),
    };
    const existing = store.entries.find((t) => (t.kind ?? "tool") === "command" && t.pattern === pattern && (t.tool ?? "") === (tool ?? "") && (t.scope ?? "global") === resolved);
    if (existing) return { ...existing, existed: true };
    store.entries.push(entry);
    saveStore(store, env, { action: "policy-add", op: "add-command", id: entry.id, effect, pattern, scope: resolved, via: op.via });
    return { ...entry, existed: false };
  });
}

/** Add a directory entry (`policy add --dir <absolute path> --effect allow|ask|deny`): calls
 *  whose argument paths all resolve under the directory take the effect — applied POST-brain
 *  (see dirEffect); the entry never replaces judgment. Idempotent on the same normalized
 *  path, like the tool surface. */
export function addDirEntry({ path: rawPath, effect, reason }, env = process.env, authority = {}) {
  const op = operatorContext(env, authority);
  const p = String(rawPath ?? "").trim();
  const e = String(effect ?? "allow").toLowerCase();
  if (!p) throw new Error("a dir entry requires --dir <absolute path>");
  if (!isAbsolute(p)) throw new Error(`dir entries take an absolute path (got '${p}')`);
  if (!EFFECTS.includes(e)) throw new Error(`effect must be one of: ${EFFECTS.join(", ")}`);
  const dir = normalizeDir(p);
  return withStoreLock(env, () => {
    const store = loadPolicyStore(env);
    assertWritable(store);
    store.entries = Array.isArray(store.entries) ? store.entries : [];
    const existing = store.entries.find((t) => t.kind === "dir" && t.path === dir);
    if (existing) return { ...existing, existed: true };
    const entry = { id: dirEntryId(dir), kind: "dir", path: dir, effect: e, at: new Date().toISOString(), ...(reason ? { reason } : {}) };
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

export function listEntries(env = process.env, opts = {}) {
  return loadPolicyStore(env, opts).entries ?? [];
}

// ── suggested defaults (never auto-applied) ───────────────────────────────────────────────────
const EXAMPLE_DEFAULTS = join(fileURLToPath(new URL("..", import.meta.url)), "examples", "user-policy.default.json");

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
        if (store.entries.find((t) => t.kind === "dir" && t.path === dir)) { skipped++; continue; }
        store.entries.push({ id: dirEntryId(dir), kind: "dir", path: dir, effect: e.effect ?? "allow", at: new Date().toISOString(), ...(e.reason ? { reason: e.reason } : {}) });
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
