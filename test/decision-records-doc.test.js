// Divergence guard (CAP-1): docs/decision-records.md must match the rows the code actually
// constructs. Field lists are extracted from code tokens — the recorder's stamped base
// object in src/record.js plus every recordDecision({...}) call site in src/guard.js —
// never hardcoded, so a renamed or dropped field fails this test until the doc moves with it.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(root, p), "utf8");

// Split an object literal's property list on top-level commas only — nested calls carry
// their own commas, so depth is tracked across (), [] and {}.
function topProperties(body) {
  const parts = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === "," && depth === 0) {
      parts.push(body.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(body.slice(start));
  return parts;
}

function rowKeys(literalBody) {
  const keys = [];
  for (const prop of topProperties(literalBody)) {
    const shorthand = prop.trim().match(/^([A-Za-z_$][\w$]*)$/);
    const keyed = prop.match(/([A-Za-z_$][\w$]*)\s*:/);
    if (shorthand) keys.push(shorthand[1]);
    else if (keyed) keys.push(keyed[1]);
    // spreads (`...safe`) contribute no field name
  }
  return keys;
}

const doc = read("docs/decision-records.md");
const recordSrc = read("src/record.js");
const guardSrc = read("src/guard.js");

test("every row field the code constructs is named in the schema doc", () => {
  // The recorder stamps the base object inside JSON.stringify(...).
  const base = recordSrc.match(/JSON\.stringify\(\{([^}]*)\}\)/);
  assert.ok(base, "src/record.js row construction not found");
  // Callers spread the rest; each recordDecision literal ends at its fixed `}, env` suffix.
  const callSites = [...guardSrc.matchAll(/recordDecision\(\{([\s\S]*?)\},\s*env/g)].map((m) => m[1]);
  assert.ok(callSites.length >= 3, "expected the recordDecision call sites in src/guard.js");
  const keys = rowKeys(base[1]);
  for (const body of callSites) keys.push(...rowKeys(body));
  assert.ok(keys.length >= 10, `suspiciously few row keys extracted: ${keys.join(", ")}`);
  const missing = keys.filter((k) => !doc.includes(`\`${k}\``));
  assert.deepEqual(missing, [], "row fields in code but missing from docs/decision-records.md");
});

test("the doc names every export header field", () => {
  // The header is now emitted by src/decision-export.js (story 1.2, CAP-2); the field list
  // is extracted from that code's return literal — token-derived, never hardcoded here.
  const exportSrc = read("src/decision-export.js");
  const header = exportSrc.match(/return\s*\{([\s\S]*?)\n  \};/);
  assert.ok(header, "src/decision-export.js header construction not found");
  const headerFields = rowKeys(header[1]);
  assert.ok(headerFields.length >= 5, `suspiciously few header fields extracted: ${headerFields.join(", ")}`);
  const missing = headerFields.filter((f) => !doc.includes(`\`${f}\``));
  assert.deepEqual(missing, [], "header fields in the emitting code but missing from docs/decision-records.md");
});

test("the doc names the store and the off-switch by their code tokens", () => {
  const store = recordSrc.match(/const CANDIDATES_FILE = "([^"]+)"/);
  assert.ok(store, "CANDIDATES_FILE not found in src/record.js");
  assert.ok(doc.includes(store[1]), "doc does not name the candidates store");
  // The allow store (ticket 5) is named by its code token too.
  const allows = recordSrc.match(/const ALLOWS_FILE = "([^"]+)"/);
  assert.ok(allows, "ALLOWS_FILE not found in src/record.js");
  assert.ok(doc.includes(allows[1]), "doc does not name the allow store");
  assert.ok(doc.includes("GUARD_RECORD_DECISIONS"), "doc does not name the off-switch");
});
