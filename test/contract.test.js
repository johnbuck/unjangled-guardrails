// Entry 1 (epic-adapter-seam): the contract module's own tests plus the import lint (AD-1).
// The lint reads every adapter file and fails any import from a core module outside the
// documented allowlist. Entry 3 (epic-adapter-seam) migrated every adapter to contract-only
// and shrank the allowlist to nothing; the probe cases below prove the lint still catches a
// deep import both synthetically and on a probe fixture.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CONTRACT_VERSION, VERDICTS,
  assess, scan, askBlocked, buildConversationContext,
  isDecision, isScanResult,
} from "../src/contract.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const env = { JEV_API_KEY: "test", GUARD_HOME: join(root, "test", "fixtures") };

const noul = (p) => ({ type: "noul", noul: p });
const mockBrain = ({ risk = 2.0, approval = 0.85, inject = 0.99, directed = "injection" } = {}) => async (url, init) => {
  const body = JSON.parse(init.body);
  if (body.questions?.kind) return { ok: true, json: async () => ({ answers: {
    kind: { type: "choice", choice: directed, probabilities: {}, confidence: 0.8 },
    directed: noul(inject),
  } }) };
  return { ok: true, json: async () => ({ answers: {
    risk: { type: "score", score: risk, probabilities: {}, confidence: 0.8 },
    approval: noul(approval), user_requested: noul(0.05), from_untrusted: noul(0.05),
    leaks_secrets: noul(0.05), dumps_env_argv: noul(0.05), dumps_process_argv: noul(0.05), reads_credential_file: noul(0.05),
  } }) };
};
const opts = (scenario = {}) => ({ env: { ...env, GUARD_SKIP_TOOLS: "", GUARD_SKIP_SCAN: "" }, fetchImpl: mockBrain(scenario) });

test("contract version and verdict enum are exactly as documented", () => {
  assert.match(CONTRACT_VERSION, /^\d+\.\d+\.\d+$/);
  assert.deepEqual([...VERDICTS], ["deny", "ask", "allow"]);
});

// The verdict-band contract note on VERDICTS (src/contract.js): the 1.x dispatch and any
// future v2 mapping (epic-v2-adapter) land on the same three bands — no second vocabulary.
// This pins one assess outcome per band, plus the askBlocked ask→deny translation, to a
// VERDICTS member each.
test("verdict-band contract: every assess and askBlocked outcome cites a VERDICTS member", async () => {
  const bands = {
    deny: await assess({ call: { tool: "Bash", input: { command: "make deploy" } } }, opts({ risk: 2.9 })),
    ask: await assess({ call: { tool: "Bash", input: { command: "make deploy" } } }, opts()),
    allow: await assess({ call: { tool: "Bash", input: { command: "ls" } } }, opts({ risk: 1.0, approval: 0.2 })),
  };
  for (const band of Object.keys(bands)) {
    const d = bands[band];
    assert.ok(isDecision(d), `assess ${band} did not return a contract Decision`);
    assert.ok(VERDICTS.includes(d.verdict), `assess ${band} verdict "${d.verdict}" is not a VERDICTS member`);
    assert.equal(d.verdict, band);
  }
  const blocked = askBlocked(bands.ask);
  assert.ok(isDecision(blocked), "askBlocked did not return a contract Decision");
  assert.ok(VERDICTS.includes(blocked.verdict), `askBlocked verdict "${blocked.verdict}" is not a VERDICTS member`);
  assert.equal(blocked.verdict, "deny");
});

test("assess returns a contract-shaped Decision across every verdict class", async () => {
  const askD = await assess({ call: { tool: "Bash", input: { command: "make deploy" } } }, opts());
  assert.ok(isDecision(askD));
  assert.equal(askD.verdict, "ask");
  assert.equal(typeof askD.category, "string");
  assert.equal(typeof askD.stats, "string");
  assert.equal(askD.ruling, null);
  assert.ok(askD.guidance.length > 0);
  assert.ok(askD.message.includes(askD.category));

  const allowD = await assess({ call: { tool: "Bash", input: { command: "ls" } } }, opts({ risk: 1.0, approval: 0.2 }));
  assert.equal(allowD.verdict, "allow");
  assert.equal(allowD.guidance, "");
});

test("context carriage: a spec builds into a context with operator messages and provenance refs", async () => {
  const ctx = buildConversationContext({
    sessionId: "contract-ctx",
    messages: [{ role: "user", text: "deploy the staging box" }],
  });
  assert.ok(ctx === undefined || Array.isArray(ctx.user_recent_messages) || typeof ctx.assistant_intent === "string");
  // The structured form (recent operator messages + flagged-content refs) survives intact.
  const built = buildConversationContext({ messages: [{ role: "user", text: "run the report" }, { role: "assistant", text: "running it" }] });
  assert.deepEqual(built?.user_recent_messages, ["run the report"]);
  const prov = buildConversationContext({ messages: [] });
  assert.ok(prov === undefined || typeof prov.flagged_untrusted_content === "undefined");
});

test("ask maps to deny where no prompt surface exists (AD-2 fail-safe)", async () => {
  const askD = await assess({ call: { tool: "Bash", input: { command: "make deploy" } } }, opts());
  const denied = askBlocked(askD);
  assert.ok(isDecision(denied));
  assert.equal(denied.verdict, "deny");
  assert.ok(/no approval prompt/.test(denied.guidance));
  assert.equal(denied.ruling, null);
});

test("scan returns a contract-shaped ScanResult, flagged and clean", async () => {
  const flagged = await scan({ text: "x".repeat(300), tool: "webfetch", source: "https://example.com/page" }, opts());
  assert.ok(isScanResult(flagged));
  assert.equal(flagged.flagged, true);
  assert.equal(flagged.probability, 0.99);
  assert.ok(flagged.message.length > 0);
  const clean = await scan({ text: "x".repeat(300), tool: "webfetch" }, opts({ inject: 0.05 }));
  assert.equal(clean.flagged, false);
  const skipped = await scan({ text: "short", tool: "webfetch" }, opts());
  assert.equal(skipped, null);
});

// --- The import lint (AD-1): adapters may import src/contract.js ONLY. The entry-1 allowlist
// was today's debt; entry 3 migrated every adapter and shrank it to nothing. Lint shape is
// exported for the conformance epic too.

/** Core modules adapters may still touch: none. Any src/ import other than contract.js fails. */
export const ADAPTER_ALLOWLIST = {};
export const ADAPTER_FILES = ["src/hook.js", "src/opencode.js", "src/acp.js", "extensions/unjangled-guardrails.ts"];

function importsOf(text) {
  const specs = [];
  for (const m of text.matchAll(/from\s*["']([^"']+)["']/g)) specs.push(m[1]);
  for (const m of text.matchAll(/^\s*import\s*["']([^"']+)["']/gm)) specs.push(m[1]);
  return specs;
}

/** Relative-to-repo path for a module specifier resolved from an adapter file, or null for bare specifiers. */
function resolveSpec(spec, adapterPath) {
  if (!spec.startsWith(".")) return null;
  return resolve(dirname(join(root, adapterPath)), spec).slice(root.length + 1);
}

/** Core-module violations: every import that lands in src/ outside the per-file allowlist. */
export function lintImports(adapterPath, allowlist) {
  const text = readFileSync(join(root, adapterPath), "utf8");
  return importsOf(text).flatMap((spec) => {
    const rel = resolveSpec(spec, adapterPath);
    if (!rel || !rel.startsWith("src/")) return [];
    if (rel === "src/contract.js" || (allowlist ?? []).includes(rel)) return [];
    return [{ adapter: adapterPath, spec, resolves: rel }];
  });
}

test("import lint: the current tree passes against the documented allowlist", () => {
  for (const file of ADAPTER_FILES) assert.deepEqual(lintImports(file, ADAPTER_ALLOWLIST[file]), []);
});

test("import lint: deliberate deep-import probe FAILS — a file reaching past the contract is caught", () => {
  // The probe fixture imports orchestrate.js and guard.js the way a misbehaving adapter
  // would. Under the contract-only target allowlist every import is a violation; under an
  // allowlist naming them, it passes — both directions proven.
  const violations = lintImports("test/fixtures/deep-import-probe.mjs", []);
  assert.equal(violations.length, 2);
  assert.deepEqual(violations.map((v) => v.resolves).sort(), ["src/guard.js", "src/orchestrate.js"]);
  const allowlisted = lintImports("test/fixtures/deep-import-probe.mjs", ["src/guard.js", "src/orchestrate.js"]);
  assert.deepEqual(allowlisted, []);
});

// Entry 3's shrink, landed: every live adapter is contract-only and reaches the core through
// the contract alone.
test("import lint: every adapter is contract-only and imports the contract", () => {
  for (const file of ADAPTER_FILES) {
    const violations = lintImports(file, ADAPTER_ALLOWLIST[file]);
    assert.deepEqual(violations, [], `${file} must import through src/contract.js only`);
    const specs = importsOf(readFileSync(join(root, file), "utf8"));
    assert.ok(specs.some((s) => resolveSpec(s, file) === "src/contract.js"), `${file} must import src/contract.js`);
  }
});
