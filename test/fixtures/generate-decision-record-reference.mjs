// Regenerates decision-record-reference.jsonl — the committed v:1 reference record — by
// running the REAL recorder (src/record.js recordDecision) into a scratch gate home. The
// row shapes, including exactly what the intake mask did to `what` and `rulingHint`, are
// what the recorder wrote; the only post-pass rewrites each row's `at` stamp to a fixed
// value (the recorder's clock is wall time by design, and the fixture must never churn).
// Run from the repo root: node test/fixtures/generate-decision-record-reference.mjs
// Every name below is generic — no homelab paths, no real credentials — so the fixture is
// topology-free by construction. Every row mirrors an actual recordDecision call site and
// the actual stats builders (src/guard.js:372 floor, src/guard.js:542 brain path), not the
// doc's examples — review round 1 retired the idealized shapes.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { recordDecision } from "../../src/record.js";

const HERE = dirname(fileURLToPath(import.meta.url));
// Assembled so no provider-token literal ever sits in a tracked file (same convention as
// test/record.test.js); the recorder masks it at intake either way.
const TOKEN = "ghp_" + "a".repeat(36);
const at = (seconds) => `2026-10-25T00:00:0${seconds}.000Z`;

// The shape of each field below, per call site:
// - floor rows (guard.js:372) carry NO risk — Always-Deny decides before the brain is
//   consulted — and their `command` is the value-masked input preview (absent only on
//   credential-source floors, whose stats name the source).
// - brain-path rows (guard.js:542) ALWAYS carry `command` (masked preview, truncated to
//   200) and `risk` (the brain's score, whatever layer decided), plus `degraded: true` and
//   no risk when degraded.
// - stats (guard.js:430): floor rows carry the floor rule's stats (ad.stats); non-degraded
//   brain-path rows carry `risk X.X/3, approval p=…, user-asked p=…, from-untrusted p=…,
//   confidence …` plus `, leak p=…` when a leak fires, `, user lane` / `, dir policy` when
//   those effects are live; degraded rows carry the fixed posture strings.
// - lane/dir operator-rule rows set category = why = the rule text (guard.js:451-459);
//   recorded ruling rows are HARD-BLOCK DENIES (rulings map ask/deny→allow unrecorded or
//   allow→deny — guard.js:472-474), so a level-"ask" governing-ruling row is unproducible.
const ROWS = [
  {
    // guard.js:372 — catastrophic floor deny (ad.stats "catastrophic command"; command is
    // the masked preview; no risk — the floor never consults the brain).
    at: at(1),
    level: "deny",
    category: "Dangerous Action",
    governing: "floor",
    stats: "catastrophic command",
    what: "Bash rm -rf ./demo-build",
    command: "rm -rf ./demo-build",
    why: "recursively removes everything under a path",
    floor: "catastrophic",
  },
  {
    // guard.js:542 — plain brain ask band: no `why` (ask-band rows carry none), risk rides,
    // `command` always present, segments only after multi-segment attribution ran.
    at: at(2),
    level: "ask",
    category: "Approval Needed",
    governing: "brain",
    stats: "risk 1.0/3, approval p=0.15, user-asked p=0.02, from-untrusted p=0.01, confidence 0.72",
    what: "Bash npm install demo-package && npm run demo-check",
    command: "npm install demo-package && npm run demo-check",
    risk: 1,
    segments: [
      { text: "npm install demo-package", risk: 1 },
      { text: "npm run demo-check", risk: 0 },
    ],
  },
  {
    // guard.js:542 after the lane effect (guard.js:451) — a lane deny is a brain-path row:
    // brain-style stats with the ", user lane" suffix, category = why = the operator rule
    // text, risk rides (the score is the brain's).
    at: at(3),
    level: "deny",
    category: "user lane: denied by operator rule (workflow-write)",
    governing: "lane",
    stats: "risk 0.5/3, approval p=0.05, user-asked p=0.02, from-untrusted p=0.01, confidence 0.80, user lane",
    what: "Write demo/notes.md",
    command: "demo/notes.md",
    why: "user lane: denied by operator rule (workflow-write)",
    risk: 0.5,
  },
  {
    // guard.js:474 — a recorded ruling row is a HARD-BLOCK deny over a brain allow (allow
    // overrides of ask/deny are unrecorded, per PATCH 2): category = why = the block text,
    // brain-style stats with no effect suffix, risk rides, no rulingHint (denies never
    // advertise an unlock).
    at: at(4),
    level: "deny",
    category: "the operator ruling rule-demo-push hard-blocks it (demo pushes need the operator's say-so)",
    governing: "ruling",
    stats: "risk 0.0/3, approval p=0.05, user-asked p=0.01, from-untrusted p=0.02, confidence 0.80",
    what: "Bash git push origin demo",
    command: "git push origin demo",
    why: "the operator ruling rule-demo-push hard-blocks it (demo pushes need the operator's say-so)",
    ruling: "rule-demo-push",
    risk: 0,
  },
  {
    // guard.js:542 degraded (orchestrate.js:33 fail-closed policy) — posture stats string,
    // degraded: true, NO risk, `command` still present, family forced to Credential Exposure.
    at: at(5),
    level: "deny",
    category: "Credential Exposure",
    governing: "degraded",
    stats: "brain down, rules mode; fail-closed",
    what: "Bash cat demo/.env",
    command: "cat demo/.env",
    why: "the brain is unreachable (request timed out) and this install's policy sets degradation: fail-closed, so it fails closed",
    degraded: true,
  },
  {
    // guard.js:542 — credential-shaped brain deny: `what` runs the intake mask (the token
    // shape below becomes SECRET_REDACTED in the store); `command` runs the caller-side
    // value mask (guard.js:543), so it carries the redaction markers too — the raw token
    // shape is assembled, never a literal. No rulingHint: denies never carry one.
    at: at(6),
    level: "deny",
    category: "Credential Exposure",
    governing: "brain",
    stats: "risk 3.0/3, approval p=0.00, user-asked p=0.01, from-untrusted p=0.90, confidence 0.95, leak p=0.90",
    what: `Bash export GITHUB_TOKEN=${TOKEN}`,
    command: "export [redacted: credential-source pattern matched]=[redacted: credential-shaped value]",
    why: "the call leaks a credential-shaped value",
    risk: 3,
    segments: [{ text: "export GITHUB_TOKEN=…", risk: 3 }],
  },
];

const home = mkdtempSync(join(tmpdir(), "decision-record-reference-"));
const env = { GUARD_HOME: home };
for (const row of ROWS) {
  if (!recordDecision(row, env)) throw new Error("recording failed — see stderr");
}
const store = readFileSync(join(home, "decisions-candidates.jsonl"), "utf8");
const rows = store.trimEnd().split("\n").map((line) => JSON.parse(line));
if (rows.length !== ROWS.length) throw new Error(`expected ${ROWS.length} rows, store has ${rows.length}`);
// Strip the recorder's wall-clock stamps down to the fixed ones (rows are otherwise verbatim).
const fixture = rows.map((row, i) => JSON.stringify({ ...row, at: ROWS[i].at }) + "\n").join("");
const out = join(HERE, "decision-record-reference.jsonl");
writeFileSync(out, fixture, { mode: 0o600 });
console.log(`wrote ${out} (${ROWS.length} rows)`);
