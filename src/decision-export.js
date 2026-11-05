// Decision-record export (FR-E3, CAP-2): emits the export document v1 documented in
// docs/decision-records.md. Default reads BOTH stores — decisions-candidates.jsonl (the
// ask/deny corpus candidates) and decisions-allows.jsonl (the bulk allow store, ticket 5) —
// and merges them into one timestamp-ordered document; --from pins the export to a single
// file. A pure read: nothing is written,
// and the rows come back verbatim — parse pass-through, nothing added, nothing stripped —
// because the store is the redaction boundary (rows are masked at intake, src/record.js),
// so an export's only job is faithful pass-through.
// Strict by contract: appends are atomic per row (src/record.js trim note), so a malformed
// line is corruption, never a skip — the throw names the line so the operator can repair.
// Strictness covers the row SHAPE too: the document promises v:1 rows verbatim, so a
// parse-valid non-object line (a number, null, an array) is corruption by the same rule.
// validateDecisionDocument (CAP-3) is the reading side of the same contract: it checks a
// document — including the committed reference record's export — against the documented
// v:1 rules and reports named errors instead of throwing.
import { readFileSync } from "node:fs";
import { candidatesFile, allowsFile } from "./record.js";

// The pinned redaction guarantee, verbatim from docs/decision-records.md ("Export document
// format v1"). test/decision-export.test.js derives it from the doc's own JSON example, so
// the doc and this emitter cannot drift apart silently.
const REDACTION_STATEMENT =
  "every credential-shaped value was masked at intake; this document carries masked values only";

export function exportDecisions({ source = null, now = new Date() } = {}) {
  const generated_at = (now instanceof Date ? now : new Date(now)).toISOString();
  let rows, sourceHeader;
  if (source) {
    // --from: single-file semantics, unchanged — strict, that file only.
    rows = readStore(source, true);
    sourceHeader = source;
  } else {
    // Default (ticket 5, 2026-10-26): read BOTH stores and merge into one timestamp-ordered
    // document. Missing stores are empty windows (a fresh install has neither file), unlike
    // the strict --from path. The ask/deny candidates rows enter the merge first, and
    // Array#sort is stable, so equal `at` stamps keep the candidates row first — the
    // documented tie-break. Allows are the bulk store; the merged total is the row count.
    const candidates = candidatesFile();
    const allows = allowsFile();
    rows = [...readStore(candidates, false), ...readStore(allows, false)].sort((x, y) => safeTime(x) - safeTime(y));
    sourceHeader = `${candidates} + ${allows}`;
  }
  return {
    schema_version: 1,
    generated_at,
    source: sourceHeader,
    row_count: rows.length,
    redaction_statement: REDACTION_STATEMENT,
    rows,
  };
}

// Date.parse guard for the merge ordering: a store row carries the recorder's toISOString
// stamp, but a hand-written or future row with an unparseable `at` sorts as 0 instead of
// throwing NaN (a silent no-op comparator) at the exporter.
const safeTime = (row) => {
  const t = Date.parse(row.at);
  return Number.isNaN(t) ? 0 : t;
};

// One store's rows, verbatim — parse pass-through, nothing added, nothing stripped (the
// store is the redaction boundary, src/record.js). Strict by contract: appends are atomic
// per row, so a malformed line is corruption, never a skip — the throw names the line so
// the operator can repair. Strictness covers the row SHAPE too: a parse-valid non-object
// line (a number, null, an array) is corruption by the same rule. `required` distinguishes
// the strict --from path (a missing file throws) from the merged default (a missing store
// is an empty window — a fresh install has neither file yet).
function readStore(store, required) {
  let text;
  try { text = readFileSync(store, "utf8"); }
  catch (err) {
    if (!required && err?.code === "ENOENT") return [];
    throw new Error(`decision export: cannot read the store at ${store}: ${err.message}`);
  }
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();  // the recorder ends every store with a newline
  const rows = [];
  for (let i = 0; i < lines.length; i++) {
    let row;
    try { row = JSON.parse(lines[i]); }
    catch { throw new Error(`decision export: malformed row at line ${i + 1} of ${store} — appends are atomic, so a malformed line is corruption`); }
    if (typeof row !== "object" || row === null || Array.isArray(row))
      throw new Error(`decision export: malformed row at line ${i + 1} of ${store} — rows are v:1 objects, so a non-object line is corruption`);
    rows.push(row);
  }
  return rows;
}

// validateDecisionDocument (CAP-3): checks a document against the documented v:1 rules
// (docs/decision-records.md — "Export document format v1" plus the v:1 row schema). The
// round-trip proof's third leg and any consumer's first line of defense. Naming errors,
// never throws: every finding is a string naming the header field or the row index and the
// rule; a document this reader rejects is malformed, not an exception. The conditional
// rules enforced are the ones the doc states as biconditionals — `ruling` on ruling rows
// only, `risk` rides on brain-path rows (brain, lane, dir, ruling — the score is the
// brain's, whatever layer decided) and never on floor or degraded rows — presence rules
// that depend on the deciding path's reason
// text (why, command) are typed when present, never required, because the doc makes them
// conditional on provenance a row cannot prove by itself.
const GOVERNING_SET = new Set(["floor", "brain", "lane", "dir", "ruling", "degraded", "escalator"]);
// `escalator` is the retired offline indirection escalator (retired 2026-10-25, see
// docs/rules-retirement.md): rows recorded under it are valid history, not corruption — the
// live store carries 18 of them (level ask, stats "offline escalator, no brain call", no risk
// — the escalator decided pre-brain, so it is not a brain-path row and carries no `risk`).
// The brain-path governing rows — the only rows that carry `risk` (guard.js:542 passes the
// score on every brain-path ask/deny whatever layer decided; guard.js:372 floor rows and
// degraded rows carry none). Review round 1 reconciled this with the doc, which had said
// "brain rows only" — lane/dir/ruling rows are brain-path rows too.
const RISK_GOVERNING = new Set(["brain", "lane", "dir", "ruling"]);

const isoUtc = (value) =>
  typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/.test(value) && !Number.isNaN(Date.parse(value));

export function validateDecisionDocument(document) {
  const errors = [];
  const fail = (message) => errors.push(message);
  try {
    if (typeof document !== "object" || document === null || Array.isArray(document))
      return {
        ok: false,
        errors: [`document: the export document is a JSON object (schema_version … rows), got ${Array.isArray(document) ? "an array" : document === null ? "null" : typeof document}`],
      };
    if (document.schema_version !== 1) fail(`header: schema_version must be 1 (document format v1), got ${JSON.stringify(document.schema_version)}`);
    if (!isoUtc(document.generated_at)) fail("header: generated_at must be an ISO 8601 UTC timestamp string (…Z)");
    if (typeof document.source !== "string" || document.source === "") fail("header: source must be a non-empty string naming the store the export read");
    if (typeof document.row_count !== "number" || !Number.isInteger(document.row_count)) fail("header: row_count must be an integer");
    if (document.redaction_statement !== REDACTION_STATEMENT) fail("header: redaction_statement must be the pinned guarantee, verbatim from docs/decision-records.md");
    if (!Array.isArray(document.rows)) {
      fail("rows: must be an array of v:1 rows");
      return { ok: errors.length === 0, errors };
    }
    if (Number.isInteger(document.row_count) && document.row_count !== document.rows.length)
      fail(`header: row_count (${document.row_count}) must equal rows.length (${document.rows.length})`);
    document.rows.forEach((row, index) => validateRow(row, index, fail));
  } catch (err) {
    fail(`validator: rejected an unexpected shape without throwing — ${err?.message ?? err}`);
  }
  return { ok: errors.length === 0, errors };
}

function validateRow(row, index, fail) {
  const where = `rows[${index}]`;
  if (typeof row !== "object" || row === null || Array.isArray(row)) {
    fail(`${where}: a v:1 row is a JSON object`);
    return;
  }
  if (row.v !== 1) fail(`${where}: v must be 1 (the row schema version), got ${JSON.stringify(row.v)}`);
  if (!isoUtc(row.at)) fail(`${where}: at must be an ISO 8601 UTC timestamp string (…Z)`);
  if (row.level !== "ask" && row.level !== "deny" && row.level !== "allow")
    fail(`${where}: level must be "ask", "deny" or "allow", got ${JSON.stringify(row.level)}`);
  if (typeof row.category !== "string" || row.category === "") fail(`${where}: category must be a non-empty string (the reason category)`);
  if (!GOVERNING_SET.has(row.governing)) fail(`${where}: governing must be one of floor|brain|lane|dir|ruling|degraded|escalator, got ${JSON.stringify(row.governing)}`);
  if (typeof row.stats !== "string" || row.stats === "") fail(`${where}: stats must be a non-empty string (the stats line)`);
  if (typeof row.what !== "string" || row.what === "") fail(`${where}: what must be a non-empty string (the masked display summary)`);
  // Conditional fields, exactly as the doc states them: "ruling rows only", "brain rows
  // only, absent when degraded" — and `floor` on floor rows where the deciding floor has a
  // name. The Gate Self-Protection family (src/always-deny.js selfModFamily) returns no
  // floor tag, so the guard.js:372 call writes floor: undefined and JSON drops it — a floor
  // row with no `floor` is that family's recorded shape (its stats line names the leg:
  // "policy store write", "gate source write", …), not a missing field.
  if (row.governing === "floor") {
    if (row.floor !== undefined && (typeof row.floor !== "string" || row.floor === ""))
      fail(`${where}: floor, when present, must be a non-empty string (the Always-Deny floor name; the self-protection family records none — its stats line names the leg)`);
  } else if ("floor" in row) {
    fail(`${where}: floor rides on floor rows only`);
  }
  if (row.governing === "ruling") {
    if (typeof row.ruling !== "string" || row.ruling === "") fail(`${where}: a ruling row carries the deciding ruling's id`);
  } else if ("ruling" in row) {
    fail(`${where}: ruling rides on ruling rows only`);
  }
  // Risk precedence (patch round, ticket 5): a `degraded: true` row is governed FIRST by
  // the degraded posture — no risk, whatever its governing string names as the deciding
  // effect layer (a brain-down lane/dir/ruling modifier rode over the posture's fallback;
  // the brain never scored). Only a NON-degraded row takes the brain-path requirement.
  if (row.degraded === true) {
    if ("risk" in row)
      fail(`${where}: risk is absent when degraded — governing ${JSON.stringify(row.governing)} rode over a brain-down posture, and a degraded row carries no brain score whatever effect layer decided`);
  } else if (RISK_GOVERNING.has(row.governing)) {
    if (typeof row.risk !== "number" || row.risk < 0 || row.risk > 3)
      fail(`${where}: risk rides on non-degraded brain-path rows (brain|lane|dir|ruling) as the brain's score, a number out of 3 — a degraded: true row is the one shape where these carry none`);
  } else if ("risk" in row) {
    fail(`${where}: risk rides on brain-path rows only — floor rows (the floor decides before the brain) and degraded rows carry none`);
  }
  if (row.degraded !== undefined) {
    if (typeof row.degraded !== "boolean") fail(`${where}: degraded must be a boolean`);
  }
  if (row.governing === "degraded" && row.degraded !== true) fail(`${where}: a degraded row (brain down) carries degraded: true`);
  // The doc's biconditionals, enforced (patch round, ticket 5): rulingHint is the ask
  // band's unblock hint and segments are ask/deny attribution — an allow row never
  // carries either, so presence there is corruption, not an extra field.
  if (row.level === "allow") {
    if ("rulingHint" in row) fail(`${where}: rulingHint is the ask band's unblock hint — an allow row never carries one`);
    if ("segments" in row) fail(`${where}: segments are ask/deny attribution — an allow row never carries any`);
  }
  // Provenance-dependent fields the doc types but never requires: present ⇒ right type.
  if ("command" in row && typeof row.command !== "string") fail(`${where}: command must be a string when present`);
  if ("why" in row && typeof row.why !== "string") fail(`${where}: why must be a string when present`);
  if ("rulingHint" in row && typeof row.rulingHint !== "string") fail(`${where}: rulingHint must be a string when present`);
  if ("segments" in row) {
    if (!Array.isArray(row.segments)) fail(`${where}: segments must be an array of {text, risk} attribution rows`);
    else
      row.segments.forEach((segment, j) => {
        if (typeof segment !== "object" || segment === null || Array.isArray(segment)) fail(`${where}: segments[${j}] is a {text, risk} object`);
        else if (typeof segment.text !== "string" || typeof segment.risk !== "number") fail(`${where}: segments[${j}] carries {text: string, risk: number}`);
      });
  }
}
