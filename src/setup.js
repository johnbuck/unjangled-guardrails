// `setup <agent>` — the tracer's one commanded path from clone to a verified first session
// (epic-installer ticket 1). Chains the layers that were three disconnected manual steps:
// the install step (src/install.js), the stranger-owned empty rulings store (rulings.initStore),
// and runLiveVerify against the configured brain — then prints the seven-section readiness
// report (backend / registration / rulings / policy / posture / verification / calibration) and
// appends one topology-free evidence row to evidence/setup-<date>.jsonl.
//
// Agent-runnable end to end: no TTY and no operator authority anywhere in the chain — an empty
// store grants none (initStore is deliberately not operator-gated; add/revoke stay gated).
// Calibration reads PENDING until entry 2.5 lands and never gates the exit code. Exit codes:
// 0 all-green-or-pending (WARN joins PENDING as never gating — an empty policy is the
// deliberate fresh-install state, not a failure — and the posture words rules/layered/closed
// never gate either: a posture is an operator choice, not a failure state), 1 any RED, 3 hard
// error (the CLI dispatches die()).
import { Writable } from "node:stream";
import { appendFileSync, mkdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { backend } from "./jev.js";
import { initStore, loadRulings, guardHome } from "./rulings.js";
import { loadPolicyStore, policyFile, suggestedDefaultsFile } from "./policy.js";
import { fallbackMode, failClosed } from "./orchestrate.js";
import { installFor, INSTALL_TARGETS, ACP_NOTE, KEY_HINT } from "./install.js";
import { runLiveVerify } from "../tools/verify/live-verify.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const SECTIONS = ["backend", "registration", "rulings", "policy", "posture", "verification", "calibration"];

// No env option on purpose: the chain must read process.env with one voice. installFor resolves
// its config paths from homedir() and runLiveVerify's isolatedEnv spreads process.env, so an
// injected env would split the run across two environments and could write hooks into the real
// home while the backend check looked at the injected one. The spawn (temp HOME / GUARD_HOME in
// the child's environment) is the isolation boundary.
export async function runSetup(target, { log = console.log } = {}) {
  if (!INSTALL_TARGETS.includes(target))
    throw new Error(`setup target must be one of ${INSTALL_TARGETS.join(", ")} ${ACP_NOTE}`);

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

  // Policy: the config layer's CONTENT half (the rulings section above is the store-integrity
  // half). A fresh install ends with an empty policy BY DESIGN — adoption stays an explicit
  // operator act — so empty is a loud WARN, never a RED: the report must say the defaults were
  // not adopted HERE, before the gap surfaces days later as repeated approval prompts on
  // routine commands (GitHub issue 19 / CAP-13). The warning names the defaults file and the
  // adopt command; it never runs it. WARN never gates the exit code (like PENDING).
  const policy = policyStatus();
  sections.policy = policy.status;
  detail.policy = policy.note ? `(${policy.note})` : "";

  // Posture: the brain-down axis (GitHub issue 16 / CAP-13) — which posture is active
  // (rules | layered | closed), how it was set (the env spelling or the policy option), and
  // the one-line command that changes it. Printed, never run; the status word is the posture
  // itself and never gates the exit code.
  const posture = postureStatus();
  sections.posture = posture.status;
  detail.posture = `(${posture.note})`;

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
// reason carried into the report line. No env parameter on purpose — the chain reads
// process.env with one voice (see the runSetup header), so this reads the default store only.
function rulingsStatus() {
  try {
    const mode = statSync(policyFile()).mode & 0o777;
    if (mode !== 0o600) return { status: "RED", note: `store mode is ${mode.toString(8)}, not 600` };
    const chunks = [];
    const warnStream = new Writable({ write(c, _e, cb) { chunks.push(c); cb(); } });
    const { rulings } = loadRulings(undefined, { warnStream });
    if (!Array.isArray(rulings)) return { status: "RED", note: "store unreadable or corrupt" };
    if (chunks.length) return { status: "RED", note: "store changed without its audit row (tamper warning)" };
    return { status: "GREEN", note: "0600" };
  } catch {
    return { status: "RED", note: "store missing after init" };
  }
}

// The content half (GitHub issue 19 / CAP-13): WARN on zero entries — the loud day-one
// "defaults not adopted" the reporter never got — GREEN with the count otherwise, RED when
// the store will not load (a corrupt store is NOT "defaults not adopted"; the corrupt check
// comes first so the warning never fires on unknown state). Load noise is captured, not
// sprayed mid-report — and captured noise alone is NOT a failure (a first-run migration
// success warns too), so only the corrupt flag reads RED. Degradation does not quiet the
// warning: posture is not entries, and the ask-flood gap stands at any posture. Same no-env
// rule as rulingsStatus.
function policyStatus() {
  const warnStream = new Writable({ write(c, _e, cb) { cb(); } });
  const store = loadPolicyStore(undefined, { warnStream });
  if (store.corrupt) return { status: "RED", note: "store unreadable or corrupt — fix or remove it, then re-run setup" };
  const n = (store.entries ?? []).length;
  return n
    ? { status: "GREEN", note: `${n} entries` }
    : { status: "WARN", note: `empty — recommended defaults not adopted: review ${relative(REPO, suggestedDefaultsFile())}, then run policy adopt-defaults (adoption is explicit, never automatic)` };
}

// The posture half (GitHub issue 16 / CAP-13): the active brain-down posture, its source, and
// the change command — the reading the reporter lacked ("an outage falls back to the offline
// rules gate — but nothing says which posture is active"). Resolved through the SAME two
// resolvers the runtime consults (orchestrate.js fallbackMode for the env axis, the policy
// store's degradation option for the per-install axis) so the report can never disagree with a
// verdict: rules = unmatched calls pass (fail-open, the default), closed = unmatched calls deny
// (env sole-gate OR the policy option degradation: fail-closed), layered = defer to the host
// heuristic stack. The status word IS the posture (rules | layered | closed — the env option
// wins over the policy option, the resolution order degradedVerdict itself uses). The section
// never reads RED/WARN and never gates: a posture is an operator choice, not a failure (the
// PENDING/WARN precedent). Same no-env rule as rulingsStatus/policyStatus.
function postureStatus() {
  const env = process.env;
  const mode = fallbackMode(env);
  const fb = env.GUARD_FALLBACK ?? env.JEV_GUARD_FALLBACK;
  const fbName = env.GUARD_FALLBACK !== undefined ? "GUARD_FALLBACK" : "JEV_GUARD_FALLBACK";
  const legacyName = env.GUARD_FAIL_CLOSED !== undefined ? "GUARD_FAIL_CLOSED" : "JEV_GUARD_FAIL_CLOSED";
  const unsetNote = (v) => `unset ${v} in the env that runs the gate — the env posture wins over policy set --degradation while set`;
  if (mode === "layered")
    return { status: "layered", note: `set by env ${fbName}=layered — brain-down: unmatched calls defer to the host heuristic stack; change: ${unsetNote(fbName)}` };
  if (mode === "closed") {
    // Which spelling closed it: GUARD_FALLBACK=closed (the current name) or the legacy
    // GUARD_FAIL_CLOSED flag (all spellings map to closed — failClosed's own parser). The
    // env spelling wins the source line because it wins the resolution.
    if (fb === "closed")
      return { status: "closed", note: `set by env ${fbName}=closed — brain-down: unmatched calls deny; change: ${unsetNote(fbName)}` };
    return { status: "closed", note: `set by legacy env ${legacyName}=${String(env.GUARD_FAIL_CLOSED ?? env.JEV_GUARD_FAIL_CLOSED)} — all spellings map to closed; brain-down: unmatched calls deny; change: ${unsetNote(legacyName)}` };
  }
  // rules mode: the per-install policy option decides what an unmatched call does — read from
  // the same store load policyStatus judges (a corrupt store is the policy section's RED;
  // here it only means the option is unreadable, and unknown is not "the built-in default").
  const warnStream = new Writable({ write(c, _e, cb) { cb(); } });
  const store = loadPolicyStore(undefined, { warnStream });
  if (store.corrupt)
    return { status: "rules", note: `env unset and the policy option unreadable — the corrupt store is the policy section's RED; brain-down: unmatched calls pass; change: ${postureChangeCommand("fail-closed")}` };
  if (store.degradation === "fail-closed")
    return { status: "closed", note: `set by policy: degradation=fail-closed — brain-down: unmatched calls deny; change: ${postureChangeCommand("fail-open")}` };
  const source = store.degradation === "fail-open" ? "set by policy: degradation=fail-open" : "the built-in default";
  return { status: "rules", note: `${source} — brain-down: unmatched calls pass; change: ${postureChangeCommand("fail-closed")}` };
}

// The one-line change command, in the 1.4 idiom (CAP-7's paste-runnable discipline): the
// resolved GUARD_HOME and this repo's own node entry — a clone install has no bin on PATH —
// plus a trailing shell comment naming the store the paste will write (the CAP-5 visibility
// discipline; the CLI's own store footer echoes the same file after the paste). Paths
// carrying a single quote degrade to the shorter spellings (no GUARD_HOME prefix, then the
// bare subcommand) rather than print a broken quoted line.
function postureChangeCommand(value) {
  const home = guardHome(), entry = join(REPO, "src", "cli.js");
  const core = `policy set --degradation ${value}`;
  const line = !home.includes("'") && !entry.includes("'")
    ? `GUARD_HOME='${home}' node '${entry}' ${core}`
    : !entry.includes("'") ? `node '${entry}' ${core}` : core;
  return `${line} # policy store: ${policyFile()}`;
}
