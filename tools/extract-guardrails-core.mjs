// Extracts the CATASTROPHIC and SECRET_SHAPE rule arrays from the verbatim vendored
// guardrails plugin into exported form. Run after updating the verbatim copy:
//   node tools/extract-guardrails-core.mjs
// The regexes themselves are never edited — sliced verbatim between the array markers.
import { readFileSync, writeFileSync } from "node:fs";

const src = readFileSync("vendor/guardrails-core/guardrails.verbatim.js", "utf8");
const grab = (name) => {
  const start = src.indexOf(`const ${name} = [`);
  if (start < 0) throw new Error(`marker for ${name} not found`);
  let depth = 0, i = src.indexOf("[", start);
  for (; i < src.length; i++) {
    if (src[i] === "[") depth++;
    else if (src[i] === "]") { depth--; if (!depth) break; }
  }
  return src.slice(src.indexOf("[", start), i + 1);
};
const catastrophic = grab("CATASTROPHIC");
const secretShape = grab("SECRET_SHAPE");
const out = `// GENERATED from vendor/guardrails-core/guardrails.verbatim.js — do not edit by hand.
// Provenance: OpenCode guardrails plugin (dotfiles opencode/plugins/guardrails.js,
// sha256-verified verbatim copy). Regenerate with tools/extract-guardrails-core.mjs.
export const CATASTROPHIC = ${catastrophic};
export const SECRET_SHAPE = ${secretShape};
export function checkCatastrophic(cmd) {
  return CATASTROPHIC.some((r) => r.test(cmd))
    ? "a catastrophic-command rule matched (mass deletion, device overwrite, force push, recursive 777, or pipe-to-shell)"
    : null;
}
`;
writeFileSync("vendor/guardrails-core/rules.mjs", out);
console.log(`extracted: ${catastrophic.split("\n").filter((l) => l.trim().startsWith("/")).length} catastrophic regexes (source ${catastrophic.length} chars)`);
