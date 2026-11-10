// Story 1.2 (CAP-2): the decision-export emitter. The document contract is
// docs/decision-records.md — the pinned redaction_statement is DERIVED from the doc's own
// JSON example (never a hand-duplicated constant), so the emitter and the doc cannot drift.
// Every store fixture is a scratch temp file or a scratch GUARD_HOME — never the real gate
// home (the recorder is exercised through recordDecision into that scratch home only).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { exportDecisions, validateDecisionDocument } from "../src/decision-export.js";
import { SECRET_REDACTED } from "../src/always-deny.js";
import { candidatesFile, allowsFile, recordDecision } from "../src/record.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const doc = readFileSync(join(REPO, "docs/decision-records.md"), "utf8");
// The pinned string, extracted from the doc's example document — the contract lives there.
// The miss must surface as THIS assert, never a raw TypeError downstream: whitespace around
// the colon is tolerated so harmless example reformatting does not blind the extraction.
const DOC_STATEMENT_MATCH = doc.match(/"redaction_statement"\s*:\s*"([^"]+)"/);
assert.ok(DOC_STATEMENT_MATCH, "redaction_statement not found in docs/decision-records.md's example document");
const DOC_REDACTION_STATEMENT = DOC_STATEMENT_MATCH[1];

function scratchHome() {
  return mkdtempSync(join(tmpdir(), "decision-export-test-"));
}

// One line per array element; the array is written exactly as given (callers decide the
// trailing newline) so malformed-line tests can place the corruption at a known line.
function scratchStore(lines, trailing = "\n") {
  const file = join(scratchHome(), "decisions-candidates.jsonl");
  writeFileSync(file, lines.join("\n") + (lines.length ? trailing : ""), { mode: 0o600 });
  return file;
}

const ROW = {
  v: 1,
  at: "2026-10-25T00:00:00.000Z",
  level: "deny",
  category: "Dangerous Action",
  governing: "floor",
  stats: "catastrophic command",
  what: "Bash  rm -rf $TMP/build",
  why: "matches the catastrophic rule",
  floor: "catastrophic",
};

test("header shape: schema_version, generated_at (injected now), source, row_count, redaction_statement, rows", () => {
  const store = scratchStore([JSON.stringify(ROW)]);
  const d = exportDecisions({ source: store, now: new Date("2026-10-25T12:00:00.000Z") });
  assert.equal(d.schema_version, 1);
  assert.equal(d.generated_at, "2026-10-25T12:00:00.000Z");
  assert.equal(d.source, store);
  assert.equal(d.row_count, 1);
  assert.deepEqual(Object.keys(d), ["schema_version", "generated_at", "source", "row_count", "redaction_statement", "rows"]);
  assert.deepEqual(d.rows, [ROW]);
});

test("redaction_statement is exactly the doc's pinned string", () => {
  const store = scratchStore([]);
  assert.equal(exportDecisions({ source: store }).redaction_statement, DOC_REDACTION_STATEMENT);
});

test("rows verbatim: a row written by the real recorder round-trips unmodified", () => {
  const home = scratchHome();
  const env = { GUARD_HOME: home };
  assert.equal(recordDecision(ROW, env), true);
  const d = exportDecisions({ source: candidatesFile(env) });
  assert.equal(d.row_count, 1);
  assert.deepEqual(d.rows, [ROW]);  // JSON round-trip equality — nothing added, nothing stripped
});

test("empty store: row_count 0, rows []", () => {
  const store = scratchStore([]);
  const d = exportDecisions({ source: store });
  assert.equal(d.row_count, 0);
  assert.deepEqual(d.rows, []);
});

test("malformed line throws naming the line number", () => {
  const store = scratchStore([JSON.stringify(ROW), "{not json"]);
  assert.throws(() => exportDecisions({ source: store }), (e) => /line 2 of /.test(e.message));
});

test("parse-valid non-object lines are corruption too (v:1 rows are objects)", () => {
  for (const bad of ["42", "null", "[]"]) {
    const store = scratchStore([JSON.stringify(ROW), bad]);
    assert.throws(() => exportDecisions({ source: store }), (e) => /line 2 of /.test(e.message) && /non-object/.test(e.message), `not rejected: ${bad}`);
  }
});

test("unreadable store throws naming the path", () => {
  const missing = join(scratchHome(), "decisions-candidates.jsonl");
  assert.throws(() => exportDecisions({ source: missing }), (e) => e.message.includes(missing));
});

test("CLI: exit 0 and the documented document on stdout, --from honored", () => {
  const store = scratchStore([JSON.stringify(ROW), JSON.stringify({ ...ROW, level: "ask" })]);
  const r = spawnSync(process.execPath, [join(REPO, "src/cli.js"), "decision", "export", "--from", store], { encoding: "utf8" });
  assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
  const d = JSON.parse(r.stdout);
  assert.equal(d.schema_version, 1);
  assert.equal(d.source, store);
  assert.equal(d.row_count, 2);
  assert.equal(d.redaction_statement, DOC_REDACTION_STATEMENT);
  assert.deepEqual(d.rows, [ROW, { ...ROW, level: "ask" }]);
});

test("CLI: default export merges both stores through the gate home (GUARD_HOME), timestamp-ordered", () => {
  const home = scratchHome();
  // One ask/deny row into the candidates store, one allow into the allow store — the
  // default export reads BOTH and names both in source. The allow is stamped later, so
  // the merged order is candidates row first, allow second.
  const ask = { ...ROW, at: "2026-10-25T00:00:01.000Z" };
  const allow = { v: 1, at: "2026-10-25T00:00:02.000Z", level: "allow", category: "Approval Needed",
    governing: "brain", stats: "risk 0.2/3, approval p=0.05, confidence 0.80", what: "Bash git status", command: "git status", risk: 0.2 };
  writeFileSync(candidatesFile({ GUARD_HOME: home }), JSON.stringify(ask) + "\n", { mode: 0o600 });
  writeFileSync(allowsFile({ GUARD_HOME: home }), JSON.stringify(allow) + "\n", { mode: 0o600 });
  const r = spawnSync(process.execPath, [join(REPO, "src/cli.js"), "decision", "export"], {
    encoding: "utf8",
    env: { ...process.env, GUARD_HOME: home },
  });
  assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
  const d = JSON.parse(r.stdout);
  assert.equal(d.source, `${candidatesFile({ GUARD_HOME: home })} + ${allowsFile({ GUARD_HOME: home })}`);
  assert.equal(d.row_count, 2);
  assert.deepEqual(d.rows, [ask, allow]);
});

test("CLI: default export with neither store present exits 0, row_count 0", () => {
  const home = scratchHome(); // no files written — a fresh install's gate home
  const r = spawnSync(process.execPath, [join(REPO, "src/cli.js"), "decision", "export"], {
    encoding: "utf8",
    env: { ...process.env, GUARD_HOME: home },
  });
  assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
  const d = JSON.parse(r.stdout);
  assert.equal(d.row_count, 0);
  assert.deepEqual(d.rows, []);
});

// --- Ticket 5 (2026-10-26): the merged default export. Ordering by `at`, the stable
// candidates-first tie-break, missing-store tolerance, and --from staying single-file. ---
const ALLOW_ROW = { v: 1, at: "2026-10-25T00:00:00.000Z", level: "allow", category: "Approval Needed",
  governing: "brain", stats: "risk 0.2/3, approval p=0.05, confidence 0.80", what: "Bash git status", command: "git status", risk: 0.2 };
// Writes both store files into one scratch gate home (null = leave that store absent, the
// fresh-install shape) and returns the home plus the two paths.
const scratchStores = (candLines, allowLines) => {
  const home = scratchHome();
  const put = (name, lines) => {
    const f = join(home, name);
    if (lines) writeFileSync(f, lines.join("\n") + "\n", { mode: 0o600 });
    return f;
  };
  return { home, cand: put("decisions-candidates.jsonl", candLines), allow: put("decisions-allows.jsonl", allowLines) };
};

test("default merge orders by at across stores; equal stamps keep the candidates row first", () => {
  const c1 = { ...ROW, at: "2026-10-25T00:00:01.000Z" };
  const c3 = { ...ROW, level: "ask", at: "2026-10-25T00:00:03.000Z" };
  const a0 = { ...ALLOW_ROW, at: "2026-10-25T00:00:00.000Z" };
  const tie = { ...ALLOW_ROW, at: "2026-10-25T00:00:01.000Z" };   // same stamp as c1
  const a4 = { ...ALLOW_ROW, at: "2026-10-25T00:00:04.000Z" };
  const { home } = scratchStores([JSON.stringify(c1), JSON.stringify(c3)], [JSON.stringify(a0), JSON.stringify(tie), JSON.stringify(a4)]);
  // exportDecisions() defaults read process.env's gate home — point it at the scratch
  // home for the call (rulings.test.js's save/restore precedent)
  const saved = process.env.GUARD_HOME;
  try {
    process.env.GUARD_HOME = home;
    const merged = exportDecisions({ now: new Date("2026-10-25T12:00:00.000Z") });
    assert.deepEqual(merged.rows.map((r) => [r.level, r.at]), [
      ["allow", "2026-10-25T00:00:00.000Z"], // a0
      ["deny", "2026-10-25T00:00:01.000Z"],  // c1 — tie: candidates first
      ["allow", "2026-10-25T00:00:01.000Z"], // tie
      ["ask", "2026-10-25T00:00:03.000Z"],   // c3
      ["allow", "2026-10-25T00:00:04.000Z"], // a4
    ]);
    assert.equal(merged.row_count, 5);
    assert.deepEqual(validateDecisionDocument(merged), { ok: true, errors: [] });
  } finally {
    if (saved === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = saved;
  }
});

test("default merge tolerates a missing store (fresh install has neither file; one-sided windows read fine)", () => {
  const saved = process.env.GUARD_HOME;
  try {
    const onlyCandidates = scratchStores([JSON.stringify(ROW)], null);
    process.env.GUARD_HOME = onlyCandidates.home;
    let d = exportDecisions({});
    assert.equal(d.row_count, 1);
    assert.deepEqual(d.rows, [ROW]);
    const onlyAllows = scratchStores(null, [JSON.stringify(ALLOW_ROW)]);
    process.env.GUARD_HOME = onlyAllows.home;
    d = exportDecisions({});
    assert.equal(d.row_count, 1);
    assert.deepEqual(d.rows, [ALLOW_ROW]);
  } finally {
    if (saved === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = saved;
  }
});

test("--from stays single-file: the named file only, strict, source is that path alone", () => {
  const { allow } = scratchStores(null, [JSON.stringify(ALLOW_ROW)]);
  const d = exportDecisions({ source: allow, now: new Date("2026-10-25T12:00:00.000Z") });
  assert.equal(d.source, allow);
  assert.deepEqual(d.rows, [ALLOW_ROW]);
  // and a missing --from file still throws (strict), unlike the tolerant merged default
  const missing = join(scratchHome(), "decisions-allows.jsonl");
  assert.throws(() => exportDecisions({ source: missing }), (e) => e.message.includes(missing));
});

test("CLI: empty store exits 0 with row_count 0 and rows []", () => {
  const store = scratchStore([]);
  const r = spawnSync(process.execPath, [join(REPO, "src/cli.js"), "decision", "export", "--from", store], { encoding: "utf8" });
  assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
  const d = JSON.parse(r.stdout);
  assert.equal(d.row_count, 0);
  assert.deepEqual(d.rows, []);
});

test("CLI: malformed store exits 1 with a naming stderr message", () => {
  const store = scratchStore([JSON.stringify(ROW), "{broken"]);
  const r = spawnSync(process.execPath, [join(REPO, "src/cli.js"), "decision", "export", "--from", store], { encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /malformed row at line 2/);
  assert.equal(r.stdout, "");
});

test("CLI: unreadable store exits 1 with a naming stderr message", () => {
  const missing = join(scratchHome(), "decisions-candidates.jsonl");
  const r = spawnSync(process.execPath, [join(REPO, "src/cli.js"), "decision", "export", "--from", missing], { encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, new RegExp(missing.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.equal(r.stdout, "");
});

// --- Story 1.3 (CAP-3): the committed reference record, the document validator, and the
// round-trip + redaction-through-export proofs. The fixture (decision-record-reference.jsonl)
// is generated by the real recorder via generate-decision-record-reference.mjs; row order in
// it: 0 floor deny, 1 brain ask, 2 lane deny, 3 ruling ask, 4 degraded deny, 5 credential
// brain deny (what and rulingHint masked at intake). ---
const FIXTURE = join(REPO, "test/fixtures/decision-record-reference.jsonl");
const fixtureRows = readFileSync(FIXTURE, "utf8")
  .trimEnd()
  .split("\n")
  .map((line) => JSON.parse(line));
const VALID_DOC = exportDecisions({ source: FIXTURE, now: new Date("2026-10-25T00:00:00.000Z") });
const cloneDoc = () => structuredClone(VALID_DOC);

test("round-trip: the committed reference record exports valid, rows deep-equal the fixture", () => {
  const d = exportDecisions({ source: FIXTURE, now: new Date("2026-10-25T00:00:00.000Z") });
  assert.deepEqual(validateDecisionDocument(d), { ok: true, errors: [] });
  assert.equal(d.row_count, fixtureRows.length);
  assert.deepEqual(d.rows, fixtureRows);  // nothing added, nothing stripped
});

// --- Live-shape conformance (decision-audit story, 2026-10-26): the second committed fixture
// holds one row per distinct shape class the live store carries (escalator, the Gate
// Self-Protection floor rows with no `floor` field, the seven floor classes, the brain-path
// key-sets) plus the governing classes the current window lacks (lane, dir, ruling,
// degraded). The validator may never again reject a shape the recorder writes. ---
const LIVE_SHAPES = join(REPO, "test/fixtures/decision-record-live-shapes.jsonl");
const liveShapeRows = readFileSync(LIVE_SHAPES, "utf8")
  .trimEnd()
  .split("\n")
  .map((line) => JSON.parse(line));

test("live-shapes round-trip: every live shape class exports valid, rows deep-equal the fixture", () => {
  const d = exportDecisions({ source: LIVE_SHAPES, now: new Date("2026-10-26T00:00:00.000Z") });
  assert.deepEqual(validateDecisionDocument(d), { ok: true, errors: [] });
  assert.equal(d.row_count, liveShapeRows.length);
  assert.deepEqual(d.rows, liveShapeRows);
});

test("live-shapes fixture pins the reconciled classes", () => {
  // The retired escalator class: governing outside the old set, no risk — valid history.
  const escalator = liveShapeRows.find((r) => r.governing === "escalator");
  assert.ok(escalator, "the fixture must carry the escalator class");
  assert.equal(escalator.level, "ask");
  assert.ok(!("risk" in escalator), "escalator rows decided pre-brain and carry no risk");
  // The Gate Self-Protection class: a floor row with no `floor` field — the recorder's
  // shape (guard.js:372 writes floor: undefined; JSON drops it).
  const selfMod = liveShapeRows.find((r) => r.governing === "floor" && r.category === "Gate Self-Protection");
  assert.ok(selfMod, "the fixture must carry the self-protection floor class");
  assert.equal(!("floor" in selfMod), true, "the self-protection row records no floor name");
  assert.equal(selfMod.stats, "policy store write", "the stats line names the leg instead");
  // And every governing value the schema names appears at least once.
  for (const g of ["floor", "brain", "lane", "dir", "ruling", "degraded", "escalator"])
    assert.ok(liveShapeRows.some((r) => r.governing === g), `fixture must cover governing "${g}"`);
});

// --- Patch round (ticket 5): the modifier-over-degraded classes, probed through the real
// gate with a brain-down stub and pinned in the live-shapes fixture. A lane/dir/ruling
// effect can decide the verdict over the degraded posture's fallback — the row carries
// that effect layer as governing WITH degraded: true and no risk, and the validator's
// degraded precedence must accept exactly that. ---
test("live-shapes fixture pins the modifier-over-degraded classes", () => {
  const rulingDeg = liveShapeRows.find((r) => r.governing === "ruling" && r.degraded === true);
  assert.ok(rulingDeg, "the fixture must carry the deny-ruling-over-degraded class");
  assert.equal(rulingDeg.level, "deny");
  assert.equal(rulingDeg.ruling, "rule-demo-push", "the hard-block rides the deciding ruling's id");
  assert.equal(rulingDeg.stats, "brain down, rules mode");
  assert.ok(!("risk" in rulingDeg), "a degraded row carries no risk whatever its governing layer");
  const laneDeg = liveShapeRows.find((r) => r.governing === "lane" && r.degraded === true);
  assert.ok(laneDeg, "the fixture must carry the lane-ask-over-degraded class");
  assert.equal(laneDeg.level, "ask");
  assert.equal(laneDeg.why, "user lane: always asks by operator rule (mcp__mail__send_email)");
  assert.ok(!("risk" in laneDeg));
});

test("validator: degraded precedence — effect-layer rows under brain-down validate, a score on one fails", () => {
  const d = structuredClone(VALID_DOC);
  d.rows.push(
    { v: 1, at: "2026-10-25T00:00:08.000Z", level: "deny", governing: "ruling", ruling: "rule-demo-push", degraded: true,
      category: "the operator ruling rule-demo-push hard-blocks it (demo pushes need the operator's say-so)",
      why: "the operator ruling rule-demo-push hard-blocks it (demo pushes need the operator's say-so)",
      stats: "brain down, rules mode", what: "Bash git push origin demo", command: "git push origin demo" },
    { v: 1, at: "2026-10-25T00:00:09.000Z", level: "ask", governing: "lane", degraded: true,
      category: "user lane: always asks by operator rule (demo)", why: "user lane: always asks by operator rule (demo)",
      stats: "brain down, rules mode", what: "Bash demo", command: "demo" },
  );
  d.row_count = d.rows.length;
  assert.deepEqual(validateDecisionDocument(d), { ok: true, errors: [] });
  const bad = structuredClone(d);
  bad.rows[6].risk = 1; // the brain never scored a degraded verdict — no governing string changes that
  const v = validateDecisionDocument(bad);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => /rows\[6\]: risk is absent when degraded/.test(e)), JSON.stringify(v.errors));
});

// --- Ticket 5 (2026-10-26): the allow store's own live-shape fixture. Every allow class
// the gate can produce, driven through the REAL assessAction with a stub backend in
// scratch homes (generate-decision-record-live-allows.mjs). The validator may never
// reject a shape the allow path writes. ---
const LIVE_ALLOWS = join(REPO, "test/fixtures/decision-record-live-allows.jsonl");
const liveAllowRows = readFileSync(LIVE_ALLOWS, "utf8")
  .trimEnd()
  .split("\n")
  .map((line) => JSON.parse(line));

test("live-allows round-trip: every allow shape class exports valid, rows deep-equal the fixture", () => {
  const d = exportDecisions({ source: LIVE_ALLOWS, now: new Date("2026-10-26T00:00:00.000Z") });
  assert.deepEqual(validateDecisionDocument(d), { ok: true, errors: [] });
  assert.equal(d.row_count, liveAllowRows.length);
  assert.deepEqual(d.rows, liveAllowRows);
});
test("live-allows fixture pins the allow classes", () => {
  // Every governing value an allow can carry, at level allow: brain (plain + user-words
  // lift), lane, dir, ruling (over an ask and over a deny), degraded. Never floor (the
  // floor only denies) and never escalator (retired).
  for (const g of ["brain", "lane", "dir", "ruling", "degraded"])
    assert.ok(liveAllowRows.some((r) => r.level === "allow" && r.governing === g), `fixture must cover allow governing "${g}"`);
  // Allow-row field discipline, from the recorded rows: no ask-band hint, no attribution
  // segments, no floor tag; the degraded allow stamps degraded: true and carries no risk;
  // every brain-path allow carries its risk.
  for (const row of liveAllowRows) {
    assert.ok(!("rulingHint" in row), "an allow row never carries the ask-band hint");
    assert.ok(!("segments" in row), "attribution never runs on an allow");
    assert.ok(!("floor" in row), "an allow row never carries a floor tag");
    if (row.governing === "degraded") {
      assert.equal(row.degraded, true);
      assert.ok(!("risk" in row), "a degraded allow carries no risk");
    } else {
      assert.equal(typeof row.risk, "number", "a brain-path allow carries the brain's score");
    }
  }
  // The user-words lift and both ruling override wordings ride the recorded rows.
  assert.ok(liveAllowRows.some((r) => r.why === "the user explicitly asked for it"));
  assert.ok(liveAllowRows.some((r) => r.governing === "ruling" && r.why === "by ruling r-demo-push (operator unblock)"));
  assert.ok(liveAllowRows.some((r) => r.governing === "ruling" && r.why === "deny overridden by ruling r-demo-push (operator unblock)"));
});

test("validator: allow is governed too — an unknown level still fails, allow passes", () => {
  const d = structuredClone(VALID_DOC);
  d.rows.push(ALLOW_ROW);
  d.row_count = d.rows.length;
  assert.deepEqual(validateDecisionDocument(d), { ok: true, errors: [] });
  const bad = structuredClone(d);
  bad.rows[bad.rows.length - 1].level = "block";
  const v = validateDecisionDocument(bad);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => /rows\[\d+\]: level must be "ask", "deny" or "allow"/.test(e)), JSON.stringify(v.errors));
});

test("validator: escalator is governed, not free — a risk on an escalator row still fails", () => {
  const d = structuredClone(VALID_DOC);
  d.rows.push({ v: 1, at: "2026-10-25T00:00:07.000Z", level: "ask", category: "Indirection Escalation",
    governing: "escalator", stats: "offline escalator, no brain call", what: "Bash  demo", command: "demo", risk: 1 });
  const v = validateDecisionDocument(d);
  assert.equal(v.ok, false);
  assert.ok(v.errors.some((e) => /rows\[\d+\]: risk rides on brain-path rows only/.test(e)), JSON.stringify(v.errors));
});

test("validator: rejects each corruption class with an error naming the row index and the rule", () => {
  const cases = [
    // Header classes.
    [() => { const d = cloneDoc(); delete d.generated_at; return [d, /header:.*generated_at/]; }],
    [() => { const d = cloneDoc(); d.schema_version = 2; return [d, /schema_version must be 1/]; }],
    [() => { const d = cloneDoc(); d.row_count = d.rows.length + 1; return [d, /row_count \(\d+\) must equal rows\.length/]; }],
    [() => { const d = cloneDoc(); d.redaction_statement = "tampered"; return [d, /redaction_statement/]; }],
    [() => { const d = cloneDoc(); d.rows = "not-an-array"; return [d, /rows: must be an array/]; }],
    // Row classes — each names the row index.
    [() => { const d = cloneDoc(); d.rows[0].level = "block"; return [d, /rows\[0\]: level must be/]; }],
    [() => { const d = cloneDoc(); d.rows[1].governing = "vibes"; return [d, /rows\[1\]: governing must be/]; }],
    [() => { const d = cloneDoc(); d.rows[1] = 42; return [d, /rows\[1\]: a v:1 row is a JSON object/]; }],
    [() => { const d = cloneDoc(); d.rows[3].at = "yesterday"; return [d, /rows\[3\]: at must be an ISO 8601 UTC/]; }],
    [() => { const d = cloneDoc(); d.rows[5].v = 2; return [d, /rows\[5\]: v must be 1/]; }],
    // Conditional-field classes, exactly as the doc states them. NOTE: a floor row with NO
    // `floor` field is the Gate Self-Protection family's recorded shape (its stats line names
    // the leg) — valid, pinned by the live-shapes fixture below. What still fails: a present
    // floor that is empty/not a string, a floor on a non-floor row.
    [() => { const d = cloneDoc(); d.rows[0].floor = ""; return [d, /rows\[0\]: floor, when present, must be a non-empty string/]; }],
    [() => { const d = cloneDoc(); d.rows[0].floor = 7; return [d, /rows\[0\]: floor, when present, must be a non-empty string/]; }],
    [() => { const d = cloneDoc(); d.rows[1].floor = "sneaky"; return [d, /rows\[1\]: floor rides on floor rows only/]; }],
    [() => { const d = cloneDoc(); delete d.rows[1].risk; return [d, /rows\[1\]: risk rides on non-degraded brain-path rows \(brain\|lane\|dir\|ruling\)/]; }],
    [() => { const d = cloneDoc(); d.rows[4].risk = 2; return [d, /rows\[4\]: risk is absent when degraded/]; }],
    [() => { const d = cloneDoc(); d.rows[0].risk = 1; return [d, /rows\[0\]: risk rides on brain-path rows only/]; }],
    // Patch round (ticket 5): the degraded-precedence negatives. A NON-degraded lane row
    // without risk still fails (the requirement's remaining true half)…
    [() => { const d = cloneDoc(); delete d.rows[2].risk; return [d, /rows\[2\]: risk rides on non-degraded brain-path rows/]; }],
    // …and an effect-layer row under brain-down carries no score either.
    [() => { const d = cloneDoc(); d.rows.push({ v: 1, at: "2026-10-25T00:00:08.000Z", level: "ask", category: "user lane: always asks by operator rule (demo)",
      governing: "lane", stats: "brain down, rules mode", what: "Bash demo", command: "demo", degraded: true, risk: 1 }); d.row_count = d.rows.length;
      return [d, /rows\[6\]: risk is absent when degraded/]; }],
    // The allow-row biconditionals (patch round, ticket 5): rulingHint and segments are
    // ask/deny-only — presence on an allow row is corruption.
    [() => { const d = cloneDoc(); d.rows.push({ ...ALLOW_ROW, rulingHint: "unjangled-guardrails ruling add --effect allow --pattern 'demo'" }); d.row_count = d.rows.length;
      return [d, /rows\[\d+\]: rulingHint is the ask band's unblock hint — an allow row never carries one/]; }],
    [() => { const d = cloneDoc(); d.rows.push({ ...ALLOW_ROW, segments: [{ text: "demo", risk: 0 }] }); d.row_count = d.rows.length;
      return [d, /rows\[\d+\]: segments are ask\/deny attribution — an allow row never carries any/]; }],
    [() => { const d = cloneDoc(); d.rows[4].degraded = false; return [d, /rows\[4\]: a degraded row \(brain down\) carries degraded: true/]; }],
    [() => { const d = cloneDoc(); d.rows[5].segments = "nope"; return [d, /rows\[5\]: segments must be an array/]; }],
  ];
  for (const [make, pattern] of cases) {
    const [doc, rule] = make();
    const v = validateDecisionDocument(doc);
    assert.equal(v.ok, false, `accepted a corruption: ${pattern}`);
    assert.ok(
      v.errors.some((e) => rule.test(e)),
      `no error matched ${rule}: ${JSON.stringify(v.errors)}`,
    );
  }
});

test("validator: never throws, even on garbage — ok false with named errors instead", () => {
  for (const garbage of [undefined, null, 42, "nope", [], {}]) {
    const v = validateDecisionDocument(garbage);
    assert.equal(v.ok, false, `accepted garbage: ${String(garbage)}`);
    assert.ok(v.errors.length >= 1, `no error named for ${String(garbage)}`);
  }
});

test("redaction through export: a credential-shaped store exports masked only (no raw shape survives)", () => {
  const home = scratchHome();
  const env = { GUARD_HOME: home };
  // Assembled, never a literal: no provider-token shape or provider env-var name in a tracked
  // file (as record.test.js; the patch round assembled the previously-intact names — the
  // write floor reads whole files, and this test carries egress text).
  const rawToken = "ghp_" + "z".repeat(36);
  const ENV_VAR = ["GITHUB", "TOKEN"].join("_");
  const rows = [
    {
      level: "deny",
      category: "Credential Exposure",
      governing: "brain",
      stats: "risk 3/3, approval p=0.00, confidence 0.95",
      what: `Bash  export ${ENV_VAR}=${rawToken}`,
      why: "matches the credential-exposure rule",
      risk: 3,
      segments: [{ text: "credential export", risk: 3 }],
      rulingHint: `retry without the value; segments carry ${rawToken}`,
    },
    {
      level: "ask",
      category: "Approval Needed",
      governing: "brain",
      stats: "risk 2/3, approval p=0.05, confidence 0.80",
      what: `Bash  curl -H "Authorization: Bearer ${rawToken}" https://api.example.test/v1/demo`,
      risk: 2,
      segments: [{ text: "credential in header", risk: 2 }],
    },
  ];
  for (const row of rows) assert.equal(recordDecision(row, env), true);
  const d = exportDecisions({ source: candidatesFile(env), now: new Date("2026-10-25T00:00:00.000Z") });
  assert.deepEqual(validateDecisionDocument(d), { ok: true, errors: [] });
  const text = JSON.stringify(d);
  assert.ok(text.includes(SECRET_REDACTED), "the document must carry SECRET_REDACTED markers");
  assert.ok(!text.includes(rawToken), "the raw token value must never survive the export");
  // Same shape as before, name assembled: this matches every KEY=token pair the old
  // `_TOKEN=` literal matched (the word class already covers the underscore) plus bare
  // TOKEN= names — at least as strong, no intact name in the file.
  assert.ok(!/[A-Za-z0-9_]*TOKEN=[A-Za-z0-9]/.test(text), "no raw KEY=token shape may survive the export");
  assert.ok(!/ghp_[A-Za-z0-9]/.test(text), "no raw provider-key shape may survive the export");
});
