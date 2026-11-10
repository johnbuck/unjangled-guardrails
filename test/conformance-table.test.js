// Entry 2 (epic-rules-of-record): the conformance validator as part of the node floor. The
// checker (tools/rules-conformance.mjs) executes the DECLARED rule surface through the real
// assessAction pipeline — offline and deterministic (scripted and sentinel brains, scratch
// GUARD_HOMEs) — and this file keeps the suite green only while declared and actual agree.
// Both drift directions are proven here at unit level, not just asserted: a tampered
// expectation turns the checker red, and a module leg without a registered probe turns the
// inventory red.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  runRulesConformance, checkThresholds, checkAlwaysDeny,
  THRESHOLDS, AD_PROBES,
} from "../tools/rules-conformance.mjs";

test("conformance table: the declared rule surface matches the actual verdicts (thresholds, Always-Deny, defaults, precedence)", async () => {
  const r = await runRulesConformance();
  // The full table goes to stderr so a failure here is diagnosable from the test output.
  if (!r.ok) process.stderr.write(r.report + "\n");
  assert.equal(r.failures.length, 0, `${r.failures.length}/${r.rows.length} conformance rows failed: ` +
    r.failures.slice(0, 5).join("; "));
  // every section actually ran (a silently skipped section is not conformance)
  for (const section of ["thresholds", "always-deny", "defaults", "precedence"])
    assert.ok(r.rows.some((row) => row.section === section), `the ${section} section ran`);
}, { timeout: 120000 });

test("drift direction 1 — declared-but-not-actual: a tampered threshold expectation fails the checker", () => {
  const r = checkThresholds({ ...THRESHOLDS, userP: 0.85 });  // the pre-2026-10-16 value
  assert.ok(r.failures.some((f) => f.startsWith("thresholds().userP:")), JSON.stringify(r.failures));
});

test("drift direction 1 — declared-but-not-actual: a wrong Always-Deny expectation fails the checker", async () => {
  const doctored = AD_PROBES
    .filter((p) => p.id === "cat-force-push")
    .map((p) => ({ ...p, expect: { ...p.expect, floor: "secrets" } }));
  const r = await checkAlwaysDeny({ declared: doctored });
  assert.ok(r.failures.some((f) => f.startsWith("cat-force-push:")), JSON.stringify(r.failures));
});

test("drift direction 2 — actual-but-not-declared: a module leg without a registered probe fails the inventory", async () => {
  const pruned = AD_PROBES.filter((p) => p.register !== "system credential file grep");
  const r = await checkAlwaysDeny({ declared: pruned });
  assert.ok(r.failures.some((f) => f.includes("system credential file grep") && f.includes("actual-but-not-declared")),
    JSON.stringify(r.failures));
});
