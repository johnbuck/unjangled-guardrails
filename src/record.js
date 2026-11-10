// Decision-candidates recorder (FR-E1, epic-classifier-evidence entry 3.4) — the evidence
// machine's feeder: every ask and deny the gate produces appends a redacted, versioned row
// to <guard home>/decisions-candidates.jsonl so real traffic becomes corpus candidates the
// operator curates by hand, and every allow appends to the sibling bulk store
// <guard home>/decisions-allows.jsonl (2026-10-26, ticket 5) — allows are high-volume
// routine traffic, so they get their own trim budget and never evict the scarce ask/deny
// corpus candidates from their window. ON by default (agents share the gate home; no env
// setup), off with GUARD_RECORD_DECISIONS=0|false|no|off. Recording is fail-open by
// contract: any failure here is logged (once per minute) and the verdict ships untouched.
// Row shape is a v:1 SIBLING of the contract decision record (src/contract.js) —
// level↔verdict plus recorder fields; FR-E3's round-trip work owns the mapping.
import { appendFileSync, existsSync, statSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { guardHome, warn } from "./rulings.js";
import { redactSecretShapes } from "./always-deny.js";

const CANDIDATES_FILE = "decisions-candidates.jsonl";
const ALLOWS_FILE = "decisions-allows.jsonl";
const MAX_BYTES = 1_000_000; // trim past 1MB — the store is operator-owned, this only bounds growth
const KEEP_ROWS = 400;
// The allow store's own budget (ticket 5): bulk volume, so a wider window — 2MB / newest
// 2000 rows, named in docs/decision-records.md as operator-tunable-on-request. The ask/deny
// constants above stay byte-identical in behavior.
const MAX_ALLOW_BYTES = 2_000_000;
const KEEP_ALLOW_ROWS = 2000;

export function candidatesFile(env = process.env) {
  return join(guardHome(env), CANDIDATES_FILE);
}

export function allowsFile(env = process.env) {
  return join(guardHome(env), ALLOWS_FILE);
}

// Row intake: `what` and `rulingHint` are masked here no matter what the caller already
// did — this file is an AT-REST store, so display-grade redaction is not enough. Exactly
// these two fields run the secret-shape mask: `what` is the display summary and `rulingHint`
// embeds raw command segments (rulingHintFor); the other fields are reason text, stats
// lines, and the value-masked command preview the callers already produced.The trim below is last-writer-wins under concurrency
// (append is O_APPEND-atomic per row; a concurrent append between the trim's read and write
// loses that row, never corrupts the file) — acceptable for an operator-owned curation
// store, recorded here so it is a decision, not an accident. Rows carry the core's ask
// verdict; on hosts without a prompt surface the ask converts to deny host-side
// (askBlockedDeny) and only this ask row exists — derivable, documented here.
let lastWarnAt = 0;
export function recordDecision(row, env = process.env, warnStream = process.stderr) {
  if (/^(0|false|no|off)$/i.test(String(env.GUARD_RECORD_DECISIONS ?? ""))) return false;
  try {
    const allow = row.level === "allow"; // store by level: allows bulk land in their own store, the ask/deny corpus window untouched
    const file = allow ? allowsFile(env) : candidatesFile(env);
    const dir = join(file, "..");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
    const safe = { ...row };
    if (row.what !== undefined) safe.what = redactSecretShapes(String(row.what));
    if (row.rulingHint !== undefined) safe.rulingHint = redactSecretShapes(String(row.rulingHint));
    appendFileSync(file, JSON.stringify({ v: 1, at: new Date().toISOString(), ...safe }) + "\n", { mode: 0o600 });
    trimIfNeeded(file, allow ? MAX_ALLOW_BYTES : MAX_BYTES, allow ? KEEP_ALLOW_ROWS : KEEP_ROWS);
    return true;
  } catch (err) {
    if (Date.now() - lastWarnAt > 60_000) { // warn-once per minute: a chronically broken store must not spam every verdict
      lastWarnAt = Date.now();
      warn(`decision recording failed (verdict unaffected): ${err?.message ?? err}`, warnStream);
    }
    return false;
  }
}

function trimIfNeeded(file, maxBytes, keepRows) {
  try {
    if (!existsSync(file) || statSync(file).size <= maxBytes) return;
    const lines = readFileSync(file, "utf8").trim().split("\n");
    writeFileSync(file, lines.slice(-keepRows).join("\n") + "\n", { mode: 0o600 });
  } catch { /* a failed trim is retried on the next append; never verdict-relevant */ }
}
