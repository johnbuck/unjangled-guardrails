// The live-verify runner (entry 4, epic-adapter-seam; spec CAP-2's live-verify clause).
//
// `unjangled-guardrails verify <harness>` drives the REAL harness surface with the two battery
// probe cases — a must-pass safe call and a must-stop destructive call, imported from
// tools/battery.mjs so no new probe text is ever authored here — and records one JSONL evidence
// line per probe in evidence/live-verify-<harness>-<date>.jsonl (harness, date, probe, verdicts,
// gate version/commit, per-harness method note).
//
// Classification-only: probes are scored, never executed. Every driver hands the probe text to
// the adapter's judging surface (the hook command's stdin, the plugin's tool.execute.before, the
// extension's tool_call) and reads the verdict back; nothing shells out the probe as a command.
//
// Harnesses:
//   claude/codex/copilot/gemini/cursor — the harness's PreToolUse-shaped payload piped through the
//       installed hook command (the entry `install` registers) with the real backend behind it.
//   opencode — the installed plugin adapter's tool.execute.before entry, driven in-process (headless
//       OpenCode sessions are not scriptable; the artifact says so honestly).
//   pi — the installed extension's tool_call entry, driven in-process with no UI (an ask then
//       fail-safe-blocks per AD-2); the interactive manual step is recorded in the artifact.
//
// Fleet-closure reuses this command for the remaining harnesses (Hermes, Paseo).
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { CONTRACT_VERSION } from "../../src/contract.js";
import { backend as configuredBrain } from "../../src/jev.js";
import { BATTERY } from "../battery.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// Honest governing-layer note (the plan's brain-unreachable row): a run with no brain configured
// is floor-governed, not live-governed — recorded as such instead of claiming a live backend.
const BACKEND_NOTE = (configuredBrain() ? "live backend (operator config)" : "no brain configured — the offline floor governed these probes")
  + "; guard home + session store isolated to a temp dir";

// The two probes, by battery id — never re-authored here (the battery owns the case text).
const MUST_PASS_ID = "s3";  // expect "safe" — a read-only everyday call; the gate must allow it
const MUST_STOP_ID = "d1";  // expect "destructive" — the battery's never-allow floor; the gate must stop it

// An allow is the only passing verdict for the safe call; the destructive call passes when the
// gate stops it (deny, or ask on hosts with a prompt surface — never allow, like the battery).
const passed = (probe, verdict) => (probe.expect === "safe" ? verdict === "allow" : verdict !== "allow");

export const SUPPORTED = ["opencode", "claude", "pi", "codex", "copilot", "gemini", "cursor"];

/** Collapse the home directory to ~ so recorded paths carry no machine-specific username. */
const homepath = (p) => (p.startsWith(homedir()) ? `~${p.slice(homedir().length)}` : p);

// ── shared plumbing ──────────────────────────────────────────────────────────────────────────

function probes() {
  const mustPass = BATTERY.find((c) => c.id === MUST_PASS_ID);
  const mustStop = BATTERY.find((c) => c.id === MUST_STOP_ID);
  if (!mustPass || !mustStop) throw new Error(`live-verify: battery cases ${MUST_PASS_ID}/${MUST_STOP_ID} missing from tools/battery.mjs`);
  return [
    { role: "must-pass", ...mustPass },
    { role: "must-stop", ...mustStop },
  ];
}

/** A temp guard home + session store so a verify run never touches operator state; the backend
 *  (SYSTEMONE_URL / key config) stays the operator's live one — that is the point of "live". */
function isolatedEnv(extra = {}) {
  const root = mkdtempSync(join(tmpdir(), "ug-liveverify-"));
  const guardHome = join(root, "guard-home");
  const sessions = join(root, "sessions");
  mkdirSync(guardHome, { recursive: true });
  mkdirSync(sessions, { recursive: true });
  return { root, env: { ...process.env, GUARD_HOME: guardHome, GUARD_SESSIONS: sessions, ...extra } };
}

/** One evidence JSONL line, appended under evidence/. Kept free of topology: no URLs, no hosts,
 *  no usernames — the backend is described as "live backend (operator config)" only. */
function record(harness, probe, { verdict, pass, method, extra = {} }) {
  const date = new Date().toISOString().slice(0, 10);
  const file = join(REPO, "evidence", `live-verify-${harness}-${date}.jsonl`);
  mkdirSync(dirname(file), { recursive: true });
  const line = {
    harness,
    date,
    probe: { id: probe.id, role: probe.role, expect: probe.expect, cmd: probe.cmd, source: "tools/battery.mjs" },
    observedVerdict: verdict,
    pass,
    method,
    backend: BACKEND_NOTE,
    contractVersion: CONTRACT_VERSION,
    commit: commit(),
    ...extra,
    at: new Date().toISOString(),
  };
  appendFileSync(file, JSON.stringify(line) + "\n");
  return { file, line };
}

function commit() {
  try {
    const head = readFileSync(join(REPO, ".git", "HEAD"), "utf8").trim();
    if (!head.startsWith("ref: ")) return head;
    const ref = head.slice(5);
    return readFileSync(join(REPO, ".git", ref), "utf8").trim();
  } catch {
    return "unknown";
  }
}

// ── the hook-surface harnesses: claude, codex, copilot, gemini, cursor ───────────────────────

/** Each dialect: the payload shape its harness sends for a Bash PreToolUse event, the CLI flags
 *  its install registers, and how its reply spells the verdict (null reply = allow everywhere). */
const HOOK_DIALECTS = {
  claude: {
    payload: (cmd, sid) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: cmd }, session_id: sid, cwd: process.cwd() }),
    args: [],
    verdict: (out) => out?.hookSpecificOutput?.permissionDecision ?? "allow",
    text: (out) => out?.hookSpecificOutput?.permissionDecisionReason ?? "",
  },
  codex: {
    payload: (cmd, sid) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: cmd }, session_id: sid, cwd: process.cwd(), turn_id: sid, model: "live-verify" }),
    args: ["--agent", "codex"],
    verdict: (out) => out?.hookSpecificOutput?.permissionDecision ?? "allow",
    text: (out) => out?.hookSpecificOutput?.permissionDecisionReason ?? "",
  },
  copilot: {
    payload: (cmd, sid) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: cmd }, session_id: sid, cwd: process.cwd(), timestamp: new Date().toISOString() }),
    args: ["--agent", "copilot"],
    verdict: (out) => out?.permissionDecision ?? out?.hookSpecificOutput?.permissionDecision ?? "allow",
    text: (out) => out?.permissionDecisionReason ?? out?.hookSpecificOutput?.permissionDecisionReason ?? "",
  },
  gemini: {
    payload: (cmd, sid) => ({ hook_event_name: "BeforeTool", tool_name: "Bash", tool_input: { command: cmd }, session_id: sid, cwd: process.cwd() }),
    args: [],
    verdict: (out) => (out === null || out === undefined ? "allow" : (out.decision ?? "allow")),
    text: (out) => out?.reason ?? "",
  },
  cursor: {
    payload: (cmd, sid) => ({ eventName: "beforeShellExecution", command: cmd, cwd: process.cwd(), sessionId: sid }),
    args: [],
    verdict: (out) => out?.permission ?? "allow",
    text: (out) => out?.user_message ?? "",
  },
};

/** The hook command the harness would really run: the entry registered in the harness's own
 *  settings when present, else the exact command `install` writes (recorded as unregistered). */
function installedHookCommand(harness) {
  if (harness !== "claude") {
    // The other hook hosts run the same CLI; their registrations carry no per-host flags beyond
    // what the dialect args already encode, so the canonical command is the live surface.
    return { command: [process.execPath, join(REPO, "src", "cli.js"), "hook"], registered: false, config: null };
  }
  const settings = join(homedir(), ".claude", "settings.json");
  if (!existsSync(settings)) return { command: [process.execPath, join(REPO, "src", "cli.js"), "hook"], registered: false, config: null };
  const ours = /unjangled-guardrails|jev-guard/;
  try {
    const cfg = JSON.parse(readFileSync(settings, "utf8"));
    for (const group of Object.values(cfg.hooks ?? {})) {
      for (const g of group ?? []) {
        for (const h of g?.hooks ?? []) {
          if (ours.test(h.command ?? "")) {
            return { command: tokenize(h.command), registered: true, config: "~/.claude/settings.json" };
          }
        }
      }
    }
  } catch { /* unreadable settings → fall through to the canonical command */ }
  return { command: [process.execPath, join(REPO, "src", "cli.js"), "hook"], registered: false, config: null };
}

/** Split a registered command string the way the shell would: double-quoted segments stay whole. */
function tokenize(command) {
  const parts = [];
  const re = /"([^"]*)"|(\S+)/g;
  let m;
  while ((m = re.exec(command)) !== null) parts.push(m[1] ?? m[2]);
  return parts;
}

function runHookCommand(argv, payload, env) {
  return new Promise((res, rej) => {
    const child = spawn(argv[0], argv.slice(1), { env, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", rej);
    child.on("close", (code) => {
      const line = out.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).find(Boolean);
      if (line) return res(line);
      // The hook contract: exit 0 with no JSON is a silent allow; a crash is stderr + non-zero.
      // Stderr on an exit-0 run is the degrade marker (brain unreachable), not a crash — the
      // consolidation routes formerly-skipped probes through the degraded posture, which warns
      // and passes; the probe verdict is still the gate's decision.
      if (code === 0) return res(null);
      rej(new Error(`live-verify: hook exited ${code} without a JSON reply (stderr: ${err.slice(0, 300)})`));
    });
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

async function verifyHookHarness(harness, list, log) {
  const d = HOOK_DIALECTS[harness];
  if (!d) throw new Error(`live-verify: no hook dialect for ${harness}`);
  const { command, registered, config } = installedHookCommand(harness);
  const { root, env } = isolatedEnv();
  // The container proof (scripts/verify-claude-container.sh) drives this same surface inside a
  // clean container; rows say so when the run is containerized AND the registration was found, so
  // a containerized registration proof is never misread as the host's own registration — and an
  // unregistered container run never claims the registration was written.
  const containerized = existsSync("/.dockerenv");
  const method = (registered
    ? `the hook command registered in ${config}, spawned with the harness's PreToolUse JSON on stdin`
    : `the exact hook command \`install ${harness}\` registers (spawned directly — no ${harness} registration found in its settings file; record says so)`)
    + (containerized && registered ? " — inside a container (/.dockerenv present); the registration is present in this container's settings file" : "");
  log(`  hook command: ${command.join(" ")}${registered ? "" : "  (unregistered — canonical install command)"}`);
  try {
    for (const probe of list) {
      const sid = `liveverify-${harness}-${probe.role}-${Date.now()}`;
      const out = await runHookCommand([...command, ...d.args], d.payload(probe.cmd, sid), env);
      const verdict = d.verdict(out);
      const ok = passed(probe, verdict);
      log(`  ${ok ? "ok  " : "FAIL"} ${probe.role}  ${probe.id} '${probe.cmd}' → ${verdict}${ok ? "" : `  (${d.text(out).slice(0, 160)})`}`);
      record(harness, probe, { verdict, pass: ok, method, extra: { registered, hookConfig: config, containerized } });
      if (!ok) process.exitCode = 2;
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// ── opencode: the installed plugin adapter, driven at tool.execute.before ───────────────────────

async function verifyOpencode(list, log) {
  const adapter = join(homedir(), ".config", "opencode", "plugins", "unjangled-guardrails.js");
  const used = existsSync(adapter) ? adapter : join(REPO, "src", "opencode.js");
  const mod = await import(pathToFileURL(used).href);
  // Generation-aware drive (found by the fleet-Macs cutover 2026-10-15: the v2 adapter
  // default-exports the {id, setup} definition, which the v1-only driver crashed on —
  // "UnjangledGuardrails is not a function" on every probe). v1: the named plugin
  // function returning tool.execute.before handlers. v2: setup(ctx) registers
  // ctx.tool.hook("execute.before"/"execute.after") and ctx.permission.hook("evaluate")
  // — the drive captures them with a stand-in ctx and invokes the before handler with
  // the v2 event shape {tool, sessionID, input} (deny throws; allow AND ask resolve —
  // ask defers to the host's permission flow, which the stand-in does not exercise; the
  // probe list is the allow/deny bands, so the semantics hold).
  const v2def = mod.default?.setup ? mod.default : mod.UnjangledGuardrailsV2?.setup ? mod.UnjangledGuardrailsV2 : null;
  const UnjangledGuardrails = v2def ? null : mod.UnjangledGuardrails;
  if (!v2def && typeof UnjangledGuardrails !== "function")
    throw new Error(`opencode adapter at ${used} is neither generation (no named UnjangledGuardrails, no setup definition)`);
  const { root, env } = isolatedEnv();
  // Minimal in-process stand-in for the OpenCode host SDK: the plugin entry, the installed adapter,
  // and the live backend are real; a headless OpenCode session is not scriptable (the artifact
  // records this method note verbatim).
  const client = {
    tui: { showToast: async () => {} },
    app: { log: () => {} },
    session: { messages: async () => ({ data: [] }) },
  };
  const saved = { home: process.env.GUARD_HOME, sessions: process.env.GUARD_SESSIONS };
  process.env.GUARD_HOME = env.GUARD_HOME;
  process.env.GUARD_SESSIONS = env.GUARD_SESSIONS;
  const method = `the installed plugin adapter's tool.execute.before entry, driven in-process (headless OpenCode sessions are not scriptable; the client SDK calls are an in-process stand-in — the adapter, the plugin entry and the live backend are real)`;
  log(`  adapter surface: ${used}`);
  try {
    let drive;
    let generation = "v1";
    if (v2def) {
      generation = "v2";
      const hooks = {};
      await v2def.setup({
        tool: { hook: (name, fn) => { hooks[name] = fn; } },
        permission: { hook: (name, fn) => { hooks[`permission:${name}`] = fn; } },
        event: { subscribe: () => {} },
        session: { synthetic: async () => {} },
        location: { directory: process.cwd() },
      });
      const before = hooks["execute.before"];
      if (!before) throw new Error("v2 adapter registered no execute.before hook");
      drive = (sid, probe) => before({ tool: "Bash", sessionID: sid, input: { command: probe.cmd } });
    } else {
      const handlers = await UnjangledGuardrails({ client, directory: process.cwd() });
      drive = (sid, probe) => handlers["tool.execute.before"]({ tool: "Bash", sessionID: sid }, { args: { command: probe.cmd } });
    }
    const sid = `liveverify-opencode-${Date.now()}`;
    for (const probe of list) {
      let verdict, note = "";
      try {
        await drive(sid, probe);
        verdict = "allow";  // a pass-through resolve is the host proceeding with the call (v2: allow, or ask deferred to the host permission flow)
      } catch (e) {
        verdict = /no approval prompt/.test(e.message ?? "") ? "ask" : "deny";  // a throw is the host being blocked (v2 throws only on deny)
        note = String(e.message ?? e).slice(0, 160);
      }
      const ok = passed(probe, verdict);
      log(`  ${ok ? "ok  " : "FAIL"} ${probe.role}  ${probe.id} '${probe.cmd}' → ${verdict}${ok ? "" : `  (${note})`}`);
      record("opencode", probe, { verdict, pass: ok, method, extra: { adapterSurface: homepath(used), adapterInstalled: existsSync(adapter), adapterGeneration: generation } });
      if (!ok) process.exitCode = 2;
    }
  } finally {
    if (saved.home === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = saved.home;
    if (saved.sessions === undefined) delete process.env.GUARD_SESSIONS; else process.env.GUARD_SESSIONS = saved.sessions;
    rmSync(root, { recursive: true, force: true });
  }
}

// ── pi: the installed extension, driven at tool_call with no UI ──────────────────────────────

async function verifyPi(list, log) {
  const settingsFile = join(homedir(), ".pi", "agent", "settings.json");
  let registered = null;
  try {
    const ours = /unjangled-guardrails|jev-guard/;
    const cfg = JSON.parse(readFileSync(settingsFile, "utf8"));
    registered = (cfg.extensions ?? []).find((p) => ours.test(p)) ?? null;
  } catch { /* no readable settings → fall back to the repo extension, recorded as unregistered */ }
  const used = registered ?? join(REPO, "extensions", "unjangled-guardrails.ts");
  const mod = await import(pathToFileURL(used).href);
  const { root, env } = isolatedEnv();
  const saved = { home: process.env.GUARD_HOME, sessions: process.env.GUARD_SESSIONS };
  process.env.GUARD_HOME = env.GUARD_HOME;
  process.env.GUARD_SESSIONS = env.GUARD_SESSIONS;
  const method = `the installed extension's tool_call entry, driven in-process with the UI surface off (an ask then fail-safe-blocks per AD-2; a real pi session would execute the safe probe, and probes are scored, never executed). Manual interactive step: run pi, ask it for a read-only command, confirm the guard stays silent and does not prompt.`;
  log(`  adapter surface: ${used}`);
  try {
    const handlers = {};
    mod.default({ on: (name, fn) => { handlers[name] = fn; } });
    const sid = `liveverify-pi-${Date.now()}`;
    const ctx = {
      sessionManager: { getSessionId: () => sid, getBranch: () => [] },
      cwd: process.cwd(), sessionID: sid, signal: undefined, hasUI: false,
      ui: { notify: () => {}, confirm: async () => false },
    };
    for (const probe of list) {
      const r = await handlers.tool_call({ toolName: "Bash", input: { command: probe.cmd } }, ctx);
      let verdict = "allow", note = "";
      if (r?.block) {
        verdict = /no UI|User rejected/.test(r.reason ?? "") ? "ask" : "deny";  // an ask held without UI blocks (AD-2)
        note = String(r.reason ?? "").slice(0, 160);
      }
      const ok = passed(probe, verdict);
      log(`  ${ok ? "ok  " : "FAIL"} ${probe.role}  ${probe.id} '${probe.cmd}' → ${verdict}${ok ? "" : `  (${note})`}`);
      record("pi", probe, { verdict, pass: ok, method, extra: { adapterSurface: homepath(used), registered: !!registered } });
      if (!ok) process.exitCode = 2;
    }
  } finally {
    if (saved.home === undefined) delete process.env.GUARD_HOME; else process.env.GUARD_HOME = saved.home;
    if (saved.sessions === undefined) delete process.env.GUARD_SESSIONS; else process.env.GUARD_SESSIONS = saved.sessions;
    rmSync(root, { recursive: true, force: true });
  }
}

// ── orchestration ────────────────────────────────────────────────────────────────────────────

export async function runLiveVerify(harness, { log = () => {} } = {}) {
  if (!harness || !SUPPORTED.includes(harness)) {
    log(`live-verify: unsupported harness '${harness ?? ""}' — supported: ${SUPPORTED.join(", ")}`);
    return 1;
  }
  const list = probes();
  log(`live-verify ${harness} — must-pass ${MUST_PASS_ID} ('${list[0].cmd}'), must-stop ${MUST_STOP_ID} ('${list[1].cmd}'); probes are scored, never executed`);
  if (harness === "opencode") await verifyOpencode(list, log);
  else if (harness === "pi") await verifyPi(list, log);
  else await verifyHookHarness(harness, list, log);
  const date = new Date().toISOString().slice(0, 10);
  log(`evidence: evidence/live-verify-${harness}-${date}.jsonl`);
  return process.exitCode ?? 0;
}
