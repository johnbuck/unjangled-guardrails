// Per-session memory shared by hook invocations, which are separate processes on most hosts.
// One small JSON file per session under ~/.unjangled-guardrails/sessions: recent user prompts, the agent's stated intent,
// recent decisions, and every flagged piece of untrusted content — so a later tool call can be judged against them.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Exported for the path-based self-modification guard (orchestrate.js): the sessions dir holds
// the record of what the user actually asked, so agent writes into it are gate self-modification.
export function sessionsDir(env = process.env) {
  return env.GUARD_SESSIONS ?? env.JEV_GUARD_SESSIONS ?? join(homedir(), ".unjangled-guardrails", "sessions");
}
const DIR = () => sessionsDir();
const CAPS = { prompts: 6, intents: 3, calls: 12, flags: 10, created: 64 };
const EMPTY = () => ({ prompts: [], intents: [], calls: [], flags: [], created: [] });

export function sessionFile(id, env) {
  return join(env ? sessionsDir(env) : DIR(), createHash("sha1").update(String(id)).digest("hex").slice(0, 16) + ".json");
}

export function readSession(id, env) {
  if (!id) return EMPTY();
  try { return { ...EMPTY(), ...JSON.parse(readFileSync(sessionFile(id, env), "utf8")) }; } catch { return EMPTY(); }
}

/** Append `item` to one of the lists; oldest entries fall off. No-op without a session id. */
export function remember(id, key, item) {
  if (!id || !item) return;
  const s = readSession(id);
  s[key] = [...s[key], { ...item, at: Date.now() }].slice(-CAPS[key]);
  s.updated = Date.now();
  mkdirSync(DIR(), { recursive: true, mode: 0o700 });
  writeFileSync(sessionFile(id), JSON.stringify(s), { mode: 0o600 });
  prune();
}

/** Shallow-merge fields (e.g. {swept: true}) into the session record. */
export function update(id, patch) {
  if (!id) return;
  const s = { ...readSession(id), ...patch, updated: Date.now() };
  mkdirSync(DIR(), { recursive: true, mode: 0o700 });
  writeFileSync(sessionFile(id), JSON.stringify(s), { mode: 0o600 });
}

/** Remember one path this session's own ALLOWED calls created (CAP-11, entry 12): deduped by
 *  path (a re-created path refreshes its timestamp, never doubles), capped like every list.
 *  The consult side lives in guard.js's cleanup eligibility; recording sits at the adapter
 *  layer only, so library callers never pollute a real session store. */
export function rememberCreated(id, path, env) {
  if (!id || !path || typeof path !== "string") return;
  const s = readSession(id, env);
  s.created = [...s.created.filter((c) => c.path !== path), { path, at: Date.now() }].slice(-CAPS.created);
  s.updated = Date.now();
  mkdirSync(env ? sessionsDir(env) : DIR(), { recursive: true, mode: 0o700 });
  writeFileSync(sessionFile(id, env), JSON.stringify(s), { mode: 0o600 });
}

export function markReported(id) {
  if (!id) return;
  const s = readSession(id);
  if (!s.flags.some((f) => !f.reported)) return;
  s.flags = s.flags.map((f) => ({ ...f, reported: true }));
  writeFileSync(sessionFile(id), JSON.stringify(s), { mode: 0o600 });
}

// ponytail: sweep sessions older than 7 days once the directory passes 200 files; no scheduler.
function prune() {
  let files;
  try { files = readdirSync(DIR()); } catch { return; }
  if (files.length < 200) return;
  const cutoff = Date.now() - 7 * 86_400_000;
  for (const f of files) {
    const p = join(DIR(), f);
    try { if (statSync(p).mtimeMs < cutoff) unlinkSync(p); } catch {}
  }
}
