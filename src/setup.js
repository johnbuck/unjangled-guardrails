// `setup <agent>` — the tracer's one commanded path from clone to a verified first session
// (epic-installer ticket 1). Chains the layers that were three disconnected manual steps:
// the install step (src/install.js), the stranger-owned empty rulings store (rulings.initStore),
// and runLiveVerify against the configured brain — then prints the five-section readiness
// report (backend / registration / rulings / verification / calibration) and appends one
// topology-free evidence row to evidence/setup-<date>.jsonl.
//
// Agent-runnable end to end: no TTY and no operator authority anywhere in the chain — an empty
// store grants none (initStore is deliberately not operator-gated; add/revoke stay gated).
// Calibration reads PENDING until entry 2.5 lands and never gates the exit code. Exit codes:
// 0 all-green-or-pending, 1 any RED, 3 hard error (the CLI dispatches die()).
import { Writable } from "node:stream";
import { appendFileSync, mkdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { backend } from "./jev.js";
import { initStore, loadRulings, rulingsFile } from "./rulings.js";
import { installFor, INSTALL_TARGETS } from "./install.js";
import { runLiveVerify } from "../tools/verify/live-verify.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const KEY_HINT = "set SYSTEMONE_URL for a local service, or run `unjangled-guardrails key <key>` / `unjangled-guardrails key --local <url>`";

const SECTIONS = ["backend", "registration", "rulings", "verification", "calibration"];

// No env option on purpose: the chain must read process.env with one voice. installFor resolves
// its config paths from homedir() and runLiveVerify's isolatedEnv spreads process.env, so an
// injected env would split the run across two environments and could write hooks into the real
// home while the backend check looked at the injected one. The spawn (temp HOME / GUARD_HOME in
// the child's environment) is the isolation boundary.
export async function runSetup(target, { log = console.log } = {}) {
  if (!INSTALL_TARGETS.includes(target))
    throw new Error(`setup target must be one of ${INSTALL_TARGETS.join(", ")} (ACP is configured in the editor: see README)`);

  const sections = {}, detail = {};

  // Backend: the same check keyHint() makes — backend() already reads the new names first with
  // the JEV_* fallback, so this section inherits the back-compat convention by construction.
  const b = backend();
  sections.backend = b ? "GREEN" : "RED";
  detail.backend = b ? `(${b.kind}${b.url ? ` ${b.url}` : ""})` : `— no brain configured (${KEY_HINT})`;

  // Registration: run the install step in-process and reuse the path it reports — never
  // re-derived. An install failure (unwritable home) is a RED section, not a crash.
  try { detail.registration = `(${installFor(target, { log }).file})`; sections.registration = "GREEN"; }
  catch (err) { sections.registration = "RED"; detail.registration = `— ${err.message}`; }

  // Rulings: the stranger-owned empty store, then judged by the gate's own loader — the same
  // tamper check a consult runs, so a store this step created reads GREEN only while it stays
  // paired with its audit row.
  const created = initStore();
  const rulings = rulingsStatus();
  sections.rulings = rulings.status;
  detail.rulings = `(${created ? "empty store created" : "store already present"}${rulings.note ? `, ${rulings.note}` : ""})`;

  // Verification: the REAL harness surface with the battery's two probes. live-verify's own
  // lines stream through the same log; its 0 is GREEN, anything else RED.
  const ret = await verifyStep(target, log);
  sections.verification = ret === 0 ? "GREEN" : "RED";
  detail.verification = ret === 0 ? "" : `(live-verify exited ${ret})`;

  // Calibration: entry 2.5 owns the probe; until then the section reads PENDING and is the one
  // status that never gates the exit code.
  sections.calibration = "PENDING";
  detail.calibration = "(entry 2.5)";

  for (const s of SECTIONS) log(`${s}: ${sections[s]}${detail[s] ? ` ${detail[s]}` : ""}`);
  const exit = Object.values(sections).includes("RED") ? 1 : 0;

  const date = new Date().toISOString().slice(0, 10);
  const file = join(REPO, "evidence", `setup-${date}.jsonl`);
  mkdirSync(dirname(file), { recursive: true });
  // Topology-free by construction: status words only — no URLs, no hosts, no keys, no paths
  // (the same scrub rules live-verify's record() applies).
  appendFileSync(file, JSON.stringify({ at: new Date().toISOString(), command: "setup", harness: target,
    sections: { ...sections }, exit }) + "\n");
  log(`evidence: evidence/setup-${date}.jsonl`);
  return exit;
}

/** runLiveVerify both returns the verdict code and (on failure) leaves process.exitCode set by
 *  its drivers; snapshot-and-restore keeps a host process's exit code from leaking in. */
async function verifyStep(target, log) {
  const saved = process.exitCode;
  process.exitCode = undefined;
  try { return await runLiveVerify(target, { log }); }
  catch (err) {  // e.g. the brain-down floor's stderr warning breaks the hook's reply contract — RED, not a crash
    log(`  live-verify could not complete: ${String(err.message ?? err).slice(0, 200)}`);
    return 2;
  }
  finally { process.exitCode = saved; }  // undefined restores "unset"; the property is not deletable
}

// GREEN = the store exists, parses as an array, sits at 0600, and passes loadRulings' tamper
// check with no warning (its warnStream is captured here). Anything else is RED, with the
// reason carried into the report line.
function rulingsStatus(env) {
  try {
    const mode = statSync(rulingsFile(env)).mode & 0o777;
    if (mode !== 0o600) return { status: "RED", note: `store mode is ${mode.toString(8)}, not 600` };
    const chunks = [];
    const warnStream = new Writable({ write(c, _e, cb) { chunks.push(c); cb(); } });
    const { rulings } = loadRulings(env, { warnStream });
    if (!Array.isArray(rulings)) return { status: "RED", note: "store unreadable or corrupt" };
    if (chunks.length) return { status: "RED", note: "store changed without its audit row (tamper warning)" };
    return { status: "GREEN", note: "0600" };
  } catch {
    return { status: "RED", note: "store missing after init" };
  }
}
