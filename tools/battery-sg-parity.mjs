#!/usr/bin/env node
// Battery v4: run secrets-guard's own parity corpus (cases.mjs, vendored verbatim) through
// the jev-guard Jev gate. Measures overlap: which deterministic-deny cases does the Jev
// layer catch (deny/ask) vs allow?
//
// TR-7 (M2, honest battery): the expected Secrets Guard verdict is DERIVED FROM THE CORPUS
// ITSELF — the corpus tags allow-cases with "(allow)" in the label and every untagged row
// is a deny-case. The old v3 hardcoded sgVerdict:"deny" for every row, which made the
// closeout number underivable (it also mislabeled the 30 allow rows).
//
// Usage: node tools/battery-sg-parity.mjs [outfile]
//   outfile defaults to evidence/battery-sg-parity-<date>.jsonl; pass a path to keep
//   concurrent runs from clobbering each other.
import { bashCases as cases } from "../vendor/secrets-guard-core/cases.mjs";
import { assessAction } from "../src/guard.js";
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";

const expected = (label) => (label.includes("(allow)") ? "allow" : "deny");

const outDir = join(dirname(new URL(import.meta.url).pathname), "..", "evidence");
mkdirSync(outDir, { recursive: true });
const outFile = process.argv[2] ?? join(outDir, `battery-sg-parity-${new Date().toISOString().slice(0, 10)}.jsonl`);
const rows = [];
for (const [label, cmd] of cases) {
  const t0 = performance.now();
  const r = await assessAction({ tool: "Bash", input: { command: cmd }, cwd: process.cwd() });
  rows.push({ label, cmd, sgVerdict: expected(label), level: r.level,
    answers: { risk: r.risk, approval: r.approval, fromUntrusted: r.fromUntrusted, leak: r.leak },
    latencyMs: Math.round(performance.now() - t0) });
  console.error(`${expected(label).toUpperCase().padEnd(5)} → ${r.level.toUpperCase().padEnd(5)} ${label}`);
}
writeFileSync(outFile, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");

// Honest closeout: score each half of the corpus by its own expectation.
const denyRows = rows.filter((r) => r.sgVerdict === "deny");
const allowRows = rows.filter((r) => r.sgVerdict === "allow");
const caught = denyRows.filter((r) => r.level !== "allow");           // SG deny-cases the gate catches
const missed = denyRows.filter((r) => r.level === "allow");           // SG deny-cases allowed — each needs a reason
const falseDens = allowRows.filter((r) => r.level === "deny");        // SG allow-cases the gate denies
const falseAsks = allowRows.filter((r) => r.level === "ask");
console.log(`total=${rows.length} (deny-corpus=${denyRows.length} allow-corpus=${allowRows.length})`);
console.log(`deny-corpus caught(deny+ask)=${caught.length}/${denyRows.length} ALLOWED=${missed.length}`);
console.log(`allow-corpus: denied=${falseDens.length} asked=${falseAsks.length} allowed=${allowRows.length - falseDens.length - falseAsks.length}`);
console.log(`jev_overlap=${(caught.length / denyRows.length * 100).toFixed(0)}%`);
if (missed.length) console.log("DENY-CORPUS MISSED_LABELS:\n" + missed.map((m) => `  ${m.label} :: ${m.cmd.slice(0, 70)}`).join("\n"));
if (falseDens.length) console.log("ALLOW-CORPUS DENIED_LABELS:\n" + falseDens.map((m) => `  ${m.label} :: ${m.cmd.slice(0, 70)}`).join("\n"));
console.log(`written: ${outFile}`);
