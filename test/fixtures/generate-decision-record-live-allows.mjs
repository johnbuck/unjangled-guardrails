// Regenerates decision-record-live-allows.jsonl — the committed allow-store conformance
// fixture (ticket 5, 2026-10-26) — by driving the REAL gate (src/guard.js assessAction)
// with a stub backend through every allow path in scratch gate homes, so the rows are
// exactly what the recorder wrote to decisions-allows.jsonl. One row per allow class:
// plain brain allow, the user-words lift, lane pass, dir pass, ruling override over an
// ask and over a deny, and the degraded fail-open allow — the full governing set an allow
// row can carry (never floor: the floor only denies; never escalator: retired). Only the
// post-pass rewrite touches each row's `at` stamp (and a scratch-home path embedded in
// the dir row's why), the live-shapes precedent. Run from the repo root:
// node test/fixtures/generate-decision-record-live-allows.mjs
// Every name below is generic — no homelab paths, no real credentials — so the fixture is
// topology-free by construction. Red/green: the run validates the fixture through
// exportDecisions + validateDecisionDocument BEFORE writing it, so a validator that
// rejects what the gate actually records fails here, not in review.
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { assessAction } from "../../src/guard.js";
import { allowsFile } from "../../src/record.js";
import { exportDecisions, validateDecisionDocument } from "../../src/decision-export.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const at = (seconds) => `2026-10-26T01:00:${String(seconds).padStart(2, "0")}.000Z`;
const SCRATCH = "/tmp/decision-record-live-allows-scratch";

// The stub brain: answers keyed off the state, TypeSafe's response shape (test/guard.test.js
// and test/record.test.js established the fake). `userAsked` lifts user_requested when the
// recent message names the call; `down` throws for the degraded posture.
const brain = ({ risk = 0.2, approval = 0.05, userAsked = false } = {}) => async (_url, { body }) => {
  const { state } = JSON.parse(body);
  return {
    ok: true,
    json: async () => ({ answers: {
      risk: { type: "score", score: risk, probabilities: {}, confidence: 0.8 },
      approval: { type: "noul", noul: approval },
      user_requested: { type: "noul", noul: userAsked ? 0.95 : 0.05 },
      from_untrusted: { type: "noul", noul: 0.05 },
      leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
      dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
    } }),
  };
};
const down = async () => { throw new Error("brain unreachable (fixture stub)"); };

// One probe = one fresh scratch gate home, one assessAction call, the allow store's last
// row. Each probe asserts its governing class and its why, so a silent semantics drift
// fails the generation instead of shipping a mislabeled fixture row.
const fixtures = [];
const assertGoverning = {
  brain: "brain", userwords: "brain", lane: "lane", dir: "dir",
  rulingAsk: "ruling", rulingDeny: "ruling", degraded: "degraded",
};
async function probe(stamp, label, assertWhy, run) {
  const home = mkdtempSync(join(tmpdir(), `decision-record-live-allows-${label}-`));
  const verdict = await run(home);
  if (verdict.level !== "allow") throw new Error(`${label}: expected an allow, got ${verdict.level}`);
  if (assertWhy && verdict.why !== assertWhy) throw new Error(`${label}: why drifted to ${JSON.stringify(verdict.why)}`);
  const raw = JSON.parse(readFileSync(allowsFile({ GUARD_HOME: home }), "utf8").trimEnd().split("\n").pop());
  if (raw.governing !== assertGoverning[label]) throw new Error(`${label}: governing drifted to ${raw.governing}`);
  if (raw.level !== "allow") throw new Error(`${label}: the store row is not an allow`);
  // strip this probe's scratch home out of any field that embeds it (the dir row's why)
  const row = JSON.parse(JSON.stringify(raw).split(home).join(SCRATCH));
  fixtures.push({ stamp, row });
}

await probe(at(1), "brain", undefined, (home) =>
  assessAction({ tool: "Bash", input: { command: "npm run demo-check" }, cwd: "/proj" },
    { env: { GUARD_HOME: home }, fetchImpl: brain() }));

await probe(at(2), "userwords", "the user explicitly asked for it", (home) =>
  assessAction({ tool: "Bash", input: { command: "git push origin demo-branch" }, cwd: "/proj",
      context: { user_recent_messages: ["git push origin demo-branch"] } },
    { env: { GUARD_HOME: home }, fetchImpl: brain({ risk: 2.9, approval: 0.85, userAsked: true }) }));

await probe(at(3), "lane", "user lane: pass (operator-owned tool)", (home) => {
  mkdirSync(home, { recursive: true });
  // the legacy user-lane seed shape (test/lane.test.js's migration fixture) — it migrates
  // into the policy store on first consult
  writeFileSync(join(home, "user-lane.json"),
    JSON.stringify({ tools: [{ pattern: "mcp__mail__send_email", effect: "allow", id: "fixture-lane" }] }));
  return assessAction({ tool: "mcp__mail__send_email", input: { to: "x@example.test" }, cwd: "/proj" },
    { env: { GUARD_HOME: home }, fetchImpl: brain({ risk: 0.5, approval: 0.85 }) });
});

await probe(at(4), "dir", undefined, (home) => {
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, "user-policy.json"),
    JSON.stringify({ version: 1, entries: [{ id: "fixture-dir", kind: "dir", path: join(home, "demo"), effect: "allow", at: "2026-10-26T00:00:00.000Z" }] }, null, 2));
  return assessAction({ tool: "Write", input: { file_path: join(home, "demo", "notes.md"), content: "demo" }, cwd: "/proj" },
    { env: { GUARD_HOME: home }, fetchImpl: brain({ risk: 0.5, approval: 0.85 }) })
    .then((v) => { if (!/^dir policy: pass/.test(v.why)) throw new Error(`dir why drifted: ${v.why}`); return v; });
});

const rulingSeed = (home) => writeFileSync(join(home, "rulings.json"),
  JSON.stringify([{ id: "r-demo-push", effect: "allow", pattern: "git push*", scope: "project:/proj", reason: "operator unblock" }]));
await probe(at(5), "rulingAsk", "by ruling r-demo-push (operator unblock)", (home) => {
  mkdirSync(home, { recursive: true });
  rulingSeed(home);
  return assessAction({ tool: "Bash", input: { command: "git push origin demo-branch" }, cwd: "/proj" },
    { env: { GUARD_HOME: home }, fetchImpl: brain({ risk: 0.5, approval: 0.85 }) });
});
await probe(at(6), "rulingDeny", "deny overridden by ruling r-demo-push (operator unblock)", (home) => {
  mkdirSync(home, { recursive: true });
  rulingSeed(home);
  return assessAction({ tool: "Bash", input: { command: "git push origin demo-branch" }, cwd: "/proj" },
    { env: { GUARD_HOME: home }, fetchImpl: brain({ risk: 2.9, approval: 0.05 }) });
});

await probe(at(7), "degraded", undefined, (home) =>
  assessAction({ tool: "Bash", input: { command: "npm run demo-check" }, cwd: "/proj" },
    { env: { GUARD_HOME: home }, fetchImpl: down })
    .then((v) => { if (v.degraded !== true) throw new Error("the degraded allow lost its posture stamp"); return v; }));

// Post-pass: strip the recorder's wall-clock stamps down to the fixed ones (rows are
// otherwise verbatim — the reference fixture's precedent, keeps regeneration byte-stable).
// Then prove the fixture validates BEFORE committing it — generation is red/green.
const fixture = fixtures.map(({ stamp, row }) => JSON.stringify({ ...row, at: stamp }) + "\n").join("");
const probeHome = mkdtempSync(join(tmpdir(), "decision-record-live-allows-probe-"));
const probeFile = join(probeHome, "fixture-probe.jsonl");
writeFileSync(probeFile, fixture, { mode: 0o600 });
const verdict = validateDecisionDocument(exportDecisions({ source: probeFile }));
if (!verdict.ok) throw new Error(`generated fixture does not validate:\n${verdict.errors.join("\n")}`);
const out = join(HERE, "decision-record-live-allows.jsonl");
writeFileSync(out, fixture, { mode: 0o600 });
console.log(`wrote ${out} (${fixtures.length} rows, validates ok)`);
