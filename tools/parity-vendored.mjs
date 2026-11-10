// Story 12 (T12.4): parity proof for the vendored Secrets Guard core.
//
// Runs the FULL SG case corpus (78 bash + 14 read rows) through the vendored engine
// (vendor/secrets-guard-core/rules.mjs) and, when the origin tree is present on this
// host, through the original engine too — verdicts must match identically
// (pre-divergence: the vendored copy is byte-identical to the origin, sha256-checked).
// Gate-level divergences (operator-approved) live ABOVE the engine, in the
// orchestrator — see docs/rules-retirement.md.
//
// Output: evidence/parity-vendored-2026-10-04.jsonl (one row per case) + stdout summary.
// Exit 0 only when every verdict matches and the vendored files are byte-identical.
import { createHash } from "node:crypto";
import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { checkBash, checkRead } from "../vendor/secrets-guard-core/rules.mjs";
import { bashCases, readCases } from "../vendor/secrets-guard-core/cases.mjs";

const ORIGIN = `${process.env.HOME}/Projects/dotfiles/secrets-guard/core`;
const OUT = new URL("../evidence/parity-vendored-2026-10-04.jsonl", import.meta.url).pathname;
const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
import { readFileSync } from "node:fs";

const files = ["rules.mjs", "cases.mjs"];
const identical = files.map((f) => {
  const vendored = new URL(`../vendor/secrets-guard-core/${f}`, import.meta.url).pathname;
  const same = existsSync(`${ORIGIN}/${f}`) && sha(vendored) === sha(`${ORIGIN}/${f}`);
  return `${f}: ${same ? "IDENTICAL" : "DIFFERS"} (${sha(vendored).slice(0, 16)}…)`;
});

const dec = (reason) => (reason ? "DENY" : "ALLOW");
const rows = [];
let mismatches = 0;

for (const [label, cmd] of bashCases) {
  const vendored = dec(checkBash(cmd));
  const original = existsSync(`${ORIGIN}/rules.mjs`) ? dec((await import(`${ORIGIN}/rules.mjs`)).checkBash(cmd)) : null;
  const match = original === null || original === vendored;
  if (!match) mismatches++;
  rows.push({ kind: "bash", case: label, input: cmd, verdict: vendored, originalVerdict: original, match });
}
for (const [label, path] of readCases) {
  const vendored = dec(checkRead(path));
  const original = existsSync(`${ORIGIN}/rules.mjs`) ? dec((await import(`${ORIGIN}/rules.mjs`)).checkRead(path)) : null;
  const match = original === null || original === vendored;
  if (!match) mismatches++;
  rows.push({ kind: "read", case: label, input: path, verdict: vendored, originalVerdict: original, match });
}

mkdirSync(new URL("../evidence/", import.meta.url).pathname, { recursive: true });
writeFileSync(OUT, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");

const denies = rows.filter((r) => r.verdict === "DENY").length;
console.log(`vendored: ${files.map((f, i) => `${f} ${identical[i].split(":")[1].trim()}`).join(", ")}`);
console.log(`cases: ${rows.length} (${rows.filter((r) => r.kind === "bash").length} bash + ${rows.filter((r) => r.kind === "read").length} read); DENY ${denies}, ALLOW ${rows.length - denies}`);
console.log(`verdict parity vs origin engine: ${mismatches === 0 ? "IDENTICAL ✅" : `${mismatches} MISMATCHES ❌`}`);
console.log(`rows written to ${OUT}`);
process.exit(mismatches === 0 && identical.every((s) => s.includes("IDENTICAL")) ? 0 : 1);
