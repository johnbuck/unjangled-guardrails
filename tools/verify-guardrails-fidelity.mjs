import { readFileSync } from "node:fs";
const v = readFileSync("vendor/guardrails-core/guardrails.verbatim.js", "utf8");
const m = readFileSync("vendor/guardrails-core/rules.mjs", "utf8");
const slice = (src, name) => src.slice(src.indexOf(`const ${name} = [`), src.indexOf("];", src.indexOf(`const ${name} = [`)) + 2);
const gen = (src, name) => src.slice(src.indexOf(`export const ${name} = [`), src.indexOf("];", src.indexOf(`export const ${name} = [`)) + 2);
for (const name of ["CATASTROPHIC", "SECRET_SHAPE"]) {
  const orig = slice(v, name).replace(`const ${name} = `, "").trim();
  const ours = gen(m, name).replace(`export const ${name} = `, "").trim();
  console.log(`${name}: ${orig === ours ? "BYTE-IDENTICAL to verbatim source" : "DIFFERS — investigate"}`);
}
