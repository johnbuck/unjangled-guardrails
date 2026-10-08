// Verbatim-behavior proof for BOTH vendored cores, against real corpora already in evidence/.
// 1. Secrets Guard core: tools/parity-vendored.mjs (hash + full corpus) — run separately.
// 2. Guardrails core: evaluate the ORIGINAL regex arrays straight from the verbatim source
//    (never touching our generated export), run both engines over every command in the
//    recorded batteries + the SG corpus, and require identical verdicts on every row.
import { readFileSync } from "node:fs";
import { checkCatastrophic, SECRET_SHAPE } from "../vendor/guardrails-core/rules.mjs";

const v = readFileSync("vendor/guardrails-core/guardrails.verbatim.js", "utf8");
const grab = (name) => { const s = v.indexOf("const " + name + " = ["); const open = v.indexOf("[", s); return v.slice(open, v.indexOf("];", open) + 2); };
const ORIG_CAT = new Function("return " + grab("CATASTROPHIC"))();
const ORIG_SECRET = new Function("return " + grab("SECRET_SHAPE"))();
const origCata = (cmd) => ORIG_CAT.some((r) => r.test(cmd));

const rows = [];
for (const f of ["evidence/battery-2026-10-04.jsonl", "evidence/battery-secrets-2026-10-04.jsonl", "evidence/battery-sg-parity-2026-10-04.jsonl"]) {
  try { for (const line of readFileSync(f, "utf8").split("\n")) { if (line.trim()) rows.push(JSON.parse(line).cmd); } } catch {}
}
const casesText = readFileSync("vendor/secrets-guard-core/cases.mjs", "utf8");
let extra = [];
try { extra = JSON.parse(casesText.slice(casesText.indexOf("["), casesText.lastIndexOf("]") + 1)).map((c) => c.cmd ?? c.command ?? c.input ?? "").filter(Boolean); } catch {}
const all = [...new Set([...rows, ...extra, "git status", "ls -la", "node --test test/"])].filter(Boolean);

let catSame = 0, catDiff = 0;
for (const cmd of all) {
  if (origCata(cmd) === !!checkCatastrophic(cmd)) catSame++;
  else { catDiff++; console.log("CATA DIFF:", cmd.slice(0, 60)); }
}
const secretIdentical = SECRET_SHAPE.length === ORIG_SECRET.length && SECRET_SHAPE.every((r, i) => String(r) === String(ORIG_SECRET[i]));
console.log(`guardrails catastrophic: ${catSame}/${all.length} identical verdicts vs the verbatim source regexes${catDiff ? ` — ${catDiff} DIFFER` : ""}`);
console.log(`guardrails secret-shape:  ${secretIdentical ? "patterns identical to verbatim source" : "DIFFER"}`);
console.log(`corpus: ${rows.length} battery rows + ${extra.length} SG corpus cases exercised`);
