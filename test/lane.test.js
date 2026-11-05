// The tool-entry (user-lane) surface of the CONFIG policy (consolidation 2026-10-20; the lane
// itself shipped 2026-10-17, effects 2026-10-19): operator-owned standing allowance with
// per-entry allow/deny/ask effects, most-specific pattern wins, deterministic (holds
// degraded). Non-entry tools: unchanged. The store is user-policy.json now; the legacy
// user-lane.json seed shape below doubles as the migration fixture.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toolEffect, toolPatternMatches, listEntries, addToolEntry, addCommandEntry, policyFile } from "../src/policy.js";
import { assessAction } from "../src/guard.js";

const mkdtemp = () => mkdtempSync(join(tmpdir(), "unjangled-guardrails-policy-"));
const env = (home) => ({ JEV_API_KEY: "test", GUARD_HOME: home });
const seedLane = (home, entries) => {
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, "user-lane.json"),
    JSON.stringify({ tools: entries.map((e) => ({ ...(typeof e === "string" ? { pattern: e } : e), id: "lane-test" })) }));
};
const brain = ({ risk = 0.5, approval = 0.2, userRequested = 0.05 } = {}) => async () => ({
  ok: true,
  json: async () => ({ answers: {
    risk: { type: "score", score: risk, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: approval }, user_requested: { type: "noul", noul: userRequested },
    from_untrusted: { type: "noul", noul: 0.05 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
  } }),
});
const opts = (home, brainOpts) => ({ env: env(home), fetchImpl: brain(brainOpts) });

test("tool pattern forms: exact, server-wide boundary prefix, verb-class", () => {
  assert.equal(toolPatternMatches("mcp__server__recall", "mcp__server__recall"), true);
  assert.equal(toolPatternMatches("mcp__server__recall", "mcp__server__remember"), false);
  assert.equal(toolPatternMatches("mcp__server", "mcp__server__recall"), true);      // server-wide: boundary prefix
  assert.equal(toolPatternMatches("mcp__server", "mcp__serverx__x"), false);         // no partial-segment creep
  assert.equal(toolPatternMatches("mcp__server*", "mcp__server__recall"), true);
  assert.equal(toolPatternMatches("mcp__*@read", "mcp__code__read_file"), true);
  assert.equal(toolPatternMatches("mcp__*@read", "mcp__mem__recall"), false);        // "rec" ≠ "rea"
});

test("toolEffect specificity: exact beats server-wide, ties deny > ask > allow", () => {
  const home = mkdtemp();
  seedLane(home, [{ pattern: "mcp__mail", effect: "allow" }, { pattern: "mcp__mail__send_email", effect: "ask" }]);
  assert.equal(toolEffect("mcp__mail__send_email", env(home)).effect, "ask");
  assert.equal(toolEffect("mcp__mail__search_emails", env(home)).effect, "allow");
  // a second home for the tie (the store, once migrated, is the live surface — legacy
  // re-seeds after first consult would be shadowed)
  const tie = mkdtemp();
  seedLane(tie, [{ pattern: "mcp__mail", effect: "allow" }, { pattern: "mcp__mail", effect: "deny" }]);
  assert.equal(toolEffect("mcp__mail__anything", env(tie)).effect, "deny");
});

test("the legacy user-lane.json migrates into the policy store on first consult", () => {
  const home = mkdtemp();
  seedLane(home, [{ pattern: "mcp__mail", effect: "allow" }, { pattern: "mcp__mail__send_email", effect: "ask" }]);
  assert.equal(existsSync(policyFile(env(home))), false, "no policy store yet");
  assert.equal(toolEffect("mcp__mail__send_email", env(home)).effect, "ask", "the migrated entry resolves");
  assert.equal(existsSync(policyFile(env(home))), true, "the store exists after the first run");
  const store = JSON.parse(readFileSync(policyFile(env(home)), "utf8"));
  assert.equal(store.entries.filter((e) => e.kind === "tool").length, 2);
  assert.ok(store.entries.every((e) => e.pattern), "every migrated entry carries its pattern");
  const audit = readFileSync(join(home, "rulings-use.jsonl"), "utf8").trim().split("\n");
  assert.equal(JSON.parse(audit[0]).action, "migration", "the migration paired with an audit row");
});

test("email composition: server allow + send ask — sends always prompt, sibling reads pass", async () => {
  const home = mkdtemp();
  seedLane(home, [
    { pattern: "mcp__mail", effect: "allow" },
    { pattern: "mcp__mail__send_email", effect: "ask" },
  ]);
  const send = await assessAction({ tool: "mcp__mail__send_email", input: { to: "x@y" }, cwd: "/proj" },
    opts(home, { risk: 0.2, approval: 0.1 }));  // brain would ALLOW — the lane asks anyway
  assert.equal(send.level, "ask");
  assert.match(send.why, /user lane: always asks/);
  const read = await assessAction({ tool: "mcp__mail__search_emails", input: { q: "x" }, cwd: "/proj" },
    opts(home, { risk: 0.2, approval: 0.1 }));
  assert.equal(read.level, "allow", "the server-wide allow passes the ask band for siblings");
});

test("deny effect blocks even over a brain allow; brain deny stops under every effect", async () => {
  const home = mkdtemp();
  seedLane(home, [{ pattern: "mcp__mail", effect: "deny" }]);
  const banned = await assessAction({ tool: "mcp__mail__send_email", input: {}, cwd: "/proj" },
    opts(home, { risk: 0.2, approval: 0.1 }));
  assert.equal(banned.level, "deny");
  assert.match(banned.why, /user lane: denied by operator rule/);
  // the brain's own deny line stops a lane tool under every effect (dangerous is dangerous)
  const dangerousHome = mkdtemp();
  seedLane(dangerousHome, [{ pattern: "mcp__mem", effect: "allow" }]);
  const denied = await assessAction({ tool: "mcp__mem__recall", input: {}, cwd: "/proj" },
    opts(dangerousHome, { risk: 2.9, approval: 0.9 }));
  assert.equal(denied.level, "deny");
  assert.equal(denied.category, "Dangerous Action");
});

test("default effect is allow (shipped-entry backcompat): ask band passes", async () => {
  const home = mkdtemp();
  seedLane(home, ["mcp__mem"]);  // the legacy string shape, no effect field
  const r = await assessAction({ tool: "mcp__mem__recall", input: {}, cwd: "/proj" },
    opts(home, { risk: 1.9, approval: 0.9 }));  // the ask band
  assert.equal(r.level, "allow");
  assert.match(r.why, /user lane: pass/);
  assert.match(r.stats, /user lane/);
});

test("non-entry tools unchanged; ask effect prompts even degraded", async () => {
  const home = mkdtemp();
  seedLane(home, [{ pattern: "mcp__mail", effect: "ask" }]);
  const other = await assessAction({ tool: "WebFetch", input: { url: "https://x" }, cwd: "/proj" },
    opts(home, { risk: 0.2, approval: 0.1 }));
  assert.equal(other.level, "allow", "a tool with no entry takes the plain brain verdict");
  // degraded: the ask effect still prompts (deterministic — no brain needed for effects)
  const degraded = await assessAction({ tool: "mcp__mail__send_email", input: {}, cwd: "/proj" },
    { env: env(home), fetchImpl: async () => { throw new Error("down"); } });
  assert.equal(degraded.level, "ask");
  assert.match(degraded.why, /user lane: always asks/);
  assert.equal(degraded.degraded, true);
});

test("policy mutations are operator-only — no agent self-grant", async () => {
  const home = mkdtemp();
  assert.throws(() => addToolEntry({ pattern: "x", effect: "allow" }, env(home)), /operator-only/);
  assert.equal(listEntries(env(home)).length, 0);
  const granted = addToolEntry({ pattern: "mcp__ok", effect: "allow" }, { ...env(home), GUARD_OPERATOR_CLI: "1" });
  assert.equal(granted.pattern, "mcp__ok");
  assert.equal(listEntries(env(home)).length, 1);
});

test("same pattern, different scope: distinct ids, independent revoke", async () => {
  const home = mkdtemp();
  const E = { ...env(home), GUARD_OPERATOR_CLI: "1" };
  const grant = addCommandEntry({ effect: "allow", pattern: "terraform *", scope: "project:/prod" }, E);
  const ban = addCommandEntry({ effect: "deny", pattern: "terraform *", scope: "project:/staging" }, E);
  assert.notEqual(grant.id, ban.id, "cross-scope entries must not share an id");
  const { removeEntry } = await import("../src/policy.js");
  removeEntry(ban.id, E);
  const left = listEntries(E).filter((e) => e.pattern === "terraform *");
  assert.equal(left.length, 1, "revoking one scope leaves the other");
  assert.equal(left[0].id, grant.id);
});

test("a corrupt store refuses EVERY mutation until hand-fixed — and the flag never serializes", async () => {
  const { writeFileSync, mkdirSync, readFileSync } = await import("node:fs");
  const { removeEntry, setDegradation, adoptDefaults } = await import("../src/policy.js");
  const home = mkdtemp();
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, "rulings.json"), "{not json");  // corrupt legacy source: the migration marks the store corrupt
  const E = { ...env(home), GUARD_OPERATOR_CLI: "1" };
  await assert.rejects(async () => addToolEntry({ pattern: "x", effect: "allow" }, E), /unreadable/);
  await assert.rejects(async () => removeEntry("whatever", E), /unreadable/);
  await assert.rejects(async () => setDegradation("fail-closed", E), /unreadable/);
  await assert.rejects(async () => adoptDefaults(E), /unreadable/);
  // the store file (if one ever got written) must not carry the corrupt flag
  if (existsSync(policyFile(E))) {
    const onDisk = JSON.parse(readFileSync(policyFile(E), "utf8"));
    assert.equal(onDisk.corrupt, undefined, "the corruption marker never persists");
  }
});

test("a deny-effect tool entry surfaces as the operator's own ban (authority, category, guidance)", async () => {
  const home = mkdtemp();
  seedLane(home, [{ pattern: "mcp__mail", effect: "deny" }]);
  const r = await assessAction({ tool: "mcp__mail__send_email", input: {}, cwd: "/proj" },
    opts(home, { risk: 0.2, approval: 0.1 }));
  assert.equal(r.level, "deny");
  assert.match(r.message, /denied by the Unjangled Guardrails classifier\. Reason: \[user lane: denied by operator rule/);
  assert.match(r.message, /The operator banned this outcome on purpose/);  // operator family text (message registry 2026-10-25)
  assert.equal(r.category, "user lane: denied by operator rule (mcp__mail)");
});

test("a deny-effect entry holds under an unreachable brain (fail-closed load-bearing)", async () => {
  const home = mkdtemp();
  seedLane(home, [{ pattern: "mcp__mail", effect: "deny" }]);
  const r = await assessAction({ tool: "mcp__mail__send_email", input: {}, cwd: "/proj" },
    { env: env(home), fetchImpl: async () => { throw Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:9"), { code: "ECONNREFUSED" }); } });
  assert.equal(r.level, "deny");
  assert.match(r.why, /user lane: denied by operator rule/);
});
