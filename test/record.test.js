// Decision-candidates recorder (FR-E1, entry 3.4): every ask and deny appends a redacted
// versioned row to <guard home>/decisions-candidates.jsonl — governing layer, category,
// stats, ruling hint — with credential-source rows carrying the shape and never the text.
// OFF with GUARD_RECORD_DECISIONS=0. Allows record to the sibling bulk store
// decisions-allows.jsonl (ticket 5) with its own trim budget — never into the candidates
// window. A broken recorder never touches the verdict.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync, chmodSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessAction } from "../src/guard.js";
import { candidatesFile, allowsFile, recordDecision } from "../src/record.js";
import { SECRET_REDACTED } from "../src/always-deny.js";

const env0 = (over = {}) => ({ GUARD_HOME: mkdtempSync(join(tmpdir(), "rec-")), SYSTEMONE_URL: "http://brain.test", ...over });

function brain(counter, score = (cmd) => (/git push|chmod -R/.test(cmd) ? 2.1 : 0.2)) {
  return async (_url, { body }) => {
    counter.calls += 1;
    const { state } = JSON.parse(body);
    const cmd = JSON.stringify(state.input);
    const s = score(cmd);
    return {
      ok: true,
      json: async () => ({
        answers: {
          risk: { type: "score", score: s, probabilities: {}, confidence: 0.8 },
          approval: { type: "noul", noul: s >= 2 ? 0.85 : 0.05 },
          user_requested: { type: "noul", noul: 0.05 },
          from_untrusted: { type: "noul", noul: 0.05 },
          leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
          dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
        },
      }),
    };
  };
}

const rows = (env) => readFileSync(candidatesFile(env), "utf8").trim().split("\n").map((l) => JSON.parse(l));

test("an ask with the brain up records a governing-brain row with redacted command text", async () => {
  const env = env0();
  const counter = { calls: 0 };
  await assessAction({ tool: "Bash", input: { command: "git push origin main && git status" }, cwd: process.cwd() }, { env, fetchImpl: brain(counter) });
  assert.ok(existsSync(candidatesFile(env)), "no candidates file written");
  const [row] = rows(env);
  assert.equal(row.level, "ask");
  assert.equal(row.governing, "brain");
  assert.equal(row.v, 1);
  assert.ok(row.command.includes("git push origin main"), "the non-credential command text rides the row");
  assert.equal(typeof row.risk, "number");
});

test("a credential-source floor deny records the shape, never the text", async () => {
  const env = env0();
  const r = await assessAction({ tool: "Bash", input: { command: "cat prod.env" }, cwd: process.cwd() }, { env });
  assert.equal(r.level, "deny");
  const [row] = rows(env);
  assert.equal(row.governing, "floor");
  assert.equal(row.command, undefined, "credential-source rows carry no command text field");
  // the amended preview discipline (2026-10-25) displays matched pattern/path structure with
  // VALUES masked — so the row may name the path, but no value shapes may ride it
  assert.ok(!/BEGIN [A-Z ]*PRIVATE KEY|[A-Za-z0-9_]+_TOKEN=|api[_-]?key\s*[:=]\s*\S/i.test(JSON.stringify(row)), "no credential value shapes may ride the row");
});

test("intake masks both what and rulingHint at rest — no raw shape survives to the store", async () => {
  const env = env0(); // scratch GUARD_HOME (fresh temp dir) — never the real gate home
  // the token value is composed at runtime so this tracked source carries no provider shape
  const raw = "GITHUB_TOKEN=" + "ghp_" + "a".repeat(36);
  recordDecision({
    level: "ask", governing: "brain", stats: "s",
    what: `Bash cat .env ${raw}`,
    rulingHint: `unjangled-guardrails ruling add --effect allow --pattern 'cat .env ${raw}' --scope 'project:/tmp' --reason 'operator unblock'`,
  }, env);
  const [row] = rows(env);
  assert.ok(row.what.includes(SECRET_REDACTED), "what must come back masked");
  assert.ok(row.rulingHint.includes(SECRET_REDACTED), "rulingHint must come back masked");
  const stored = JSON.stringify(row);
  assert.ok(!stored.includes("ghp_" + "a".repeat(36)), "the raw token value must never reach the store");
  assert.ok(!/[A-Za-z0-9_]+_TOKEN=ghp_/.test(stored), "no raw token shape may survive at rest");
});

test("allow rows get the identical intake mask, in their own store", () => {
  const env = env0(); // scratch GUARD_HOME — never the real gate home
  const raw = "GITHUB_TOKEN=" + "ghp_" + "b".repeat(36);
  recordDecision({ level: "allow", category: "Approval Needed", governing: "brain", stats: "s",
    what: `Bash cat .env ${raw}` }, env);
  const [row] = readFileSync(allowsFile(env), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.ok(row.what.includes(SECRET_REDACTED), "the allow row's what must come back masked");
  assert.ok(!JSON.stringify(row).includes("ghp_" + "b".repeat(36)), "the raw token value must never reach the allow store");
});

test("the retired escalator category never appears in recorded rows", async () => {
  const env = env0();
  await assessAction({ tool: "Bash", input: { command: "echo $(x; y)" }, cwd: process.cwd() }, { env });
  if (!existsSync(candidatesFile(env))) return; // a benign degraded pass records nothing
  for (const row of rows(env)) assert.notEqual(row.category, "Indirection Escalation", "the ask family is retired — no row may carry it");
});

test("a substitution-wrapped credential read takes the body-floor deny row with no command text", async () => {
  const env = env0();
  const r = await assessAction({ tool: "Bash", input: { command: "echo $(cat prod.env)" }, cwd: process.cwd() }, { env });
  assert.equal(r.level, "deny");
  const [row] = rows(env);
  assert.equal(row.governing, "floor");
  assert.equal(row.command, undefined, "the credential-source body-floor row carries no command text");
});

test("the candidates file trims to its newest rows past the size bound", async () => {
  const env = env0();
  const { recordDecision } = await import("../src/record.js");
  for (let i = 0; i < 450; i++) recordDecision({ level: "deny", category: "t", why: "w", governing: "brain", stats: "s", what: "x".repeat(2500) }, env);
  recordDecision({ level: "ask", category: "t", why: "w", governing: "brain", stats: "s", what: "final" }, env);
  const all = rows(env);
  assert.ok(all.length <= 401, `trim should hold the file near the bound, got ${all.length} rows`);
  assert.equal(all.at(-1).what, "final", "the newest row survives the trim");
});

test("GUARD_RECORD_DECISIONS=0 records nothing, in either store", async () => {
  const off = env0({ GUARD_RECORD_DECISIONS: "0" });
  await assessAction({ tool: "Bash", input: { command: "git push origin main" }, cwd: process.cwd() }, { env: off, fetchImpl: brain({ calls: 0 }) });
  assert.ok(!existsSync(candidatesFile(off)), "the switch must silence the candidates recorder");
  assert.ok(!existsSync(allowsFile(off)), "the switch must silence the allow recorder");
});

// The eviction-isolation property (ticket 5): allows are bulk traffic, so they land in the
// allow store ONLY — the candidates store's scarce window is untouched by allow volume,
// even past the allow store's own trim bound. Proven here with real allow rows at bulk
// scale: 2100 rows (~5 MB) blow past the 2 MB cap, the allow store trims to its newest
// window, and the candidates store still does not exist.
test("an allow records to the allow store only; bulk allow volume never touches the candidates store", async () => {
  const env = env0();
  const allowRow = { level: "allow", category: "Approval Needed", governing: "brain", stats: "s", what: "x".repeat(2500) };
  for (let i = 0; i < 2100; i++) recordDecision(allowRow, env);
  recordDecision({ ...allowRow, what: "final" }, env);
  const all = readFileSync(allowsFile(env), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.ok(all.length <= 2001, `the allow trim should hold the file near its bound, got ${all.length} rows`);
  assert.equal(all.at(-1).what, "final", "the newest allow row survives the trim");
  assert.ok(!existsSync(candidatesFile(env)), "allow volume must never create or touch the candidates store");
  // and the routing is by level: the next ask/deny opens the candidates store, the allow
  // store keeps only allows
  await assessAction({ tool: "Bash", input: { command: "git push origin main" }, cwd: process.cwd() }, { env, fetchImpl: brain({ calls: 0 }) });
  const candRows = readFileSync(candidatesFile(env), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(candRows.length, 1, "the ask/deny row lands in the candidates store");
  assert.notEqual(candRows[0].level, "allow");
  assert.ok(readFileSync(allowsFile(env), "utf8").trim().split("\n").every((l) => JSON.parse(l).level === "allow"),
    "the allow store carries only allow rows");
});

test("an assessAction allow writes exactly one allow row, redacted, and no ask/deny row", async () => {
  const env = env0();
  const r = await assessAction({ tool: "Bash", input: { command: "git status" }, cwd: process.cwd() }, { env, fetchImpl: brain({ calls: 0 }) });
  assert.equal(r.level, "allow");
  const [row] = readFileSync(allowsFile(env), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(row.level, "allow");
  assert.equal(row.governing, "brain");
  assert.equal(row.v, 1);
  assert.ok(!existsSync(candidatesFile(env)), "the ask/deny store stays closed on a pure allow");
  assert.equal(row.rulingHint, undefined, "allows never carry the ask-band hint");
  assert.equal(row.segments, undefined, "attribution never runs on an allow");
});

test("a broken recorder leaves the verdict unchanged", async () => {
  const env = env0();
  chmodSync(env.GUARD_HOME, 0o500); // directory unwritable — the recorder cannot append
  const r = await assessAction({ tool: "Bash", input: { command: "git push origin main" }, cwd: process.cwd() }, { env, fetchImpl: brain({ calls: 0 }) });
  assert.equal(r.level, "ask", "a recording failure must never change the verdict");
  chmodSync(env.GUARD_HOME, 0o700); // let the temp dir clean up
});
