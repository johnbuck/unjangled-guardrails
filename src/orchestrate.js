// Orchestrator (Story 12): one judgment order for every adapter.
//   brain up    → the semantic verdict decides; the vendored Secrets Guard rules apply only as a
//                 measured floor for families the brain has not yet proven closed (every family
//                 is evidence-driven-retired in docs/rules-retirement.md, so the floor list is
//                 empty today), and operator-approved divergences (rules deny, brain allows by
//                 design) never escalate.
//   brain down  → rulings resolve first (matching needs no brain); on sole-gate hosts
//                 (JEV_GUARD_FALLBACK=closed, legacy JEV_GUARD_FAIL_CLOSED=1) the vendored
//                 rules ARE the gate — deny for their classes, deny-all for the rest. Where the
// Postures (GUARD_FALLBACK): `rules` (default), `layered` (explicit opt-in
// pass-through to a host heuristic stack), `closed` (sole-gate deny-all).
//                 steps aside and passes through with a marker on stderr.
import { checkBash, checkRead } from "../vendor/secrets-guard-core/rules.mjs";
import { checkCatastrophic } from "../vendor/guardrails-core/rules.mjs";
import { resolveRuling, warn, guardHome } from "./rulings.js";
import { sessionsDir } from "./session.js";
import { CONFIG_FILE, LEGACY_CONFIG_FILE } from "./jev.js";
import { homedir } from "node:os";
import { join, resolve, sep } from "node:path";

export const MARKER = "Unjangled Guardrails: brain unreachable — the built-in offline rules are the gate until it returns";

// Tools whose calls are never worth a Jev round-trip (read-only), and whose results are never
// external content. Names as each agent reports them: Claude/Codex/Copilot (Read, Bash…),
// pi/OpenCode (read, bash, list…), Gemini (read_file, run_shell_command…), Cursor (Shell, Delete, MCP:x).
// Lives here (not guard.js) so degradedGate can judge "is this tool something the rules can
// actually see" without a circular import — guard.js imports it from here.
// Agent-orchestration tool names (operator ruling 2026-10-07): coordination calls that manage
// other agents — launching, messaging, approving, listing, archiving. They don't execute code,
// touch files, or access credentials; the subagent's own gate handles the actual work. Skipping
// them prevents the orchestrator's transcript (full of security-shaped text from directing the
// work) from triggering leak/approval misfires on routine management calls.
export const COORDINATION = new Set([
  "paseo_create_agent", "paseo_send_agent_prompt", "paseo_respond_to_permission",
  "paseo_get_agent_status", "paseo_get_agent_activity", "paseo_list_agents",
  "paseo_list_pending_permissions", "paseo_archive_agent", "paseo_cancel_agent",
  "paseo_kill_agent", "paseo_update_agent", "paseo_set_agent_mode",
  "paseo_create_workspace", "paseo_list_workspaces", "paseo_rename_workspace",
  "paseo_archive_workspace",
  "paseo_create_heartbeat", "paseo_delete_heartbeat",
  "paseo_create_schedule", "paseo_list_schedules", "paseo_inspect_schedule",
  "paseo_update_schedule", "paseo_pause_schedule", "paseo_resume_schedule",
  "paseo_run_schedule_once", "paseo_delete_schedule", "paseo_schedule_logs",
  "paseo_list_providers", "paseo_list_models", "paseo_inspect_provider", "paseo_list_profiles",
  "paseo_list_workspace_scripts", "paseo_start_workspace_script", "paseo_stop_workspace_script",
  "sendmessage", "send_agent_prompt", "respond_to_permission",
  "get_agent_status", "list_pending_permissions",
])

// Operator ruling 2026-10-08: the Paseo orchestration plane is standing-allowed in code —
// prefix-matched rather than enumerated. The exact-name set above (operator ruling
// 2026-10-07) never matched the mcp__paseo__* names the Claude hook actually delivers
// (hook.js builds that shape for Cursor MCP events and passes tool_name through raw for
// Claude), so the skip silently never fired there. Adapters that strip the server prefix
// deliver bare paseo_* names; both spellings match, and the 2026-10-07 aliases stay.
export function isCoordinationTool(name) {
  name = String(name ?? "").toLowerCase();
  return name.startsWith("paseo_") || name.includes("__paseo__") || COORDINATION.has(name);
};

export const READ_ONLY = new Set(["read", "glob", "grep", "ls", "list", "find", "webfetch", "websearch", "todowrite", "todoread", "askuserquestion", "exitplanmode",
  "notebookread", "listmcpresourcestool", "readmcpresourcetool", "toolsearch", "skill", "task", "agent", "tabs_context_mcp", "read_page", "get_page_text",
  "read_file", "read_many_files", "list_directory", "search_file_content", "grep_search", "google_web_search", "web_fetch", "write_todos",
  "search_files", "web_search", "web_extract", "session_search", "skill_view", "skills_list", "todo", "vision_analyze", "delegate_task"]);

// Operator ruling 2026-10-04 (final form): the vendored rules ARE the fallback. Default "rules":
// brain down -> the built-in offline rules (secrets-guard core + catastrophic list) gate.
// "layered" is the explicit opt-in for hosts that keep an external heuristic stack installed;
// "closed" denies everything unmatched and is for sole-gate hardening. All spellings of the
// legacy fail-closed flag map to closed.
// One truthiness parser for the legacy fail-closed flag (M4/TR-6): call sites used to check it
// three different ways ("=== 1", truthy — under which "0" closed! — and "=== '1'"). "1"/"true"
// (any case) close; "0"/"false"/unset/"" stay open; any other spelling is ambiguous and fails
// closed, which is the safe side for a security flag.
export function failClosed(env = process.env) {
  const v = String(env.GUARD_FAIL_CLOSED ?? env.JEV_GUARD_FAIL_CLOSED ?? "").trim().toLowerCase();
  return !(v === "" || v === "0" || v === "false");
}

export function fallbackMode(env = process.env) {
  const fb = env.GUARD_FALLBACK ?? env.JEV_GUARD_FALLBACK;
  if (fb === "layered") return "layered";
  if (fb === "closed" || failClosed(env)) return "closed";
  return "rules";
}

// Rule families whose denies ESCALATE the brain verdict while the brain is up (the measured
// floor). Populated only on evidence that the brain misses a class the rules catch — each
// entry must have a row in docs/rules-retirement.md citing corpus + probe evidence, and each
// is removed when the brain's questions prove closure (the Story 8/9 playbook). Empty today:
// every SG rule family is retired-semantic or an approved divergence.
export const ACTIVE_FLOOR = [];

// Rule families where the brain intentionally allows what the rules deny — operator-approved
// (the status-only `docker inspect -f '{{.State.Status}}'` rows; SG denies every docker
// inspect, format-selected or not). The floor must never escalate these.
export const DIVERGENCE_FAMILIES = ["docker-inspect-format"];

// Map a vendored-rules deny reason to its rule family (docs/rules-retirement.md).
export function familyOf(reason) {
  // Order matters: several reasons mention other families' tools in their advice text
  // (the credential-file reason suggests `infisical run`; the docker-env reason says "environment").
  if (/credential file/i.test(reason)) return "credential-file";
  if (/config\.ya?ml/i.test(reason)) return "agent-config";
  if (/traces every expanded command/i.test(reason)) return "shell-tracing";
  if (/docker/i.test(reason) || /container's full environment/i.test(reason))
    return /Config\.Env|format/i.test(reason) ? "docker-inspect-format" : "docker-env";
  if (/clientSecret|secretValue|secrets\/raw|universal-auth/i.test(reason)) return "curl-secret-api";
  if (/infisical/i.test(reason)) return "infisical";
  if (/printenv|full environment/i.test(reason)) return "env-dump";
  if (/command line|argv|environ|pgrep/i.test(reason)) return "process-argv";
  return "unclassified";
}

// Run the vendored rules for shell/read-shaped tools. Returns { family, reason } on deny,
// null when the rules allow (or the tool is not one they judge).
export function ruleVerdict(tool, input) {
  const name = String(tool ?? "").toLowerCase();
  if (/bash|shell|run_shell_command|terminal|zsh|sh/.test(name)) {
    const cmd = String(input?.command ?? "");
    const catastrophic = checkCatastrophic(cmd);
    if (catastrophic) return { family: "catastrophic", reason: catastrophic };
    const reason = checkBash(cmd);
    return reason ? { family: familyOf(reason), reason } : null;
  }
  // TR-3 (H1): every read-shaped shape the adapters report whose input carries paths — not just
  // read/view/cat, or Gemini's read_file slipped the gate. read_many_files takes a paths array.
  if (/^(read|view|cat|read_file|read_many_files)$/.test(name)) {
    const candidates = Array.isArray(input?.paths) ? input.paths : [input?.file_path ?? input?.path ?? ""];
    const reason = candidates.map((p) => checkRead(String(p ?? ""))).find(Boolean);
    return reason ? { family: familyOf(reason), reason } : null;
  }
  return null;
}

// Gate self-modification guard: deny attempts to grant rulings or edit the gate's own files from
// agent context (the escalation path a model-facing hint or injected instruction would take).
// Two layers, per plan 1.1 (red-team R1):
//   bash-shaped tools — the original regex on the command text;
//   every other tool — path-based: any file_path-like input that resolves into the guard's own
//   store/audit/config/sessions paths denies, whatever the tool name (Write, Edit, NotebookEdit,
//   MCP file tools — the shapes the bash regex can never see).
// Returns a reason string on match, null otherwise. Not liftable by rulings — the gate does not
// accept keys cut against itself; genuine user words (user_requested >= 0.85) still lift it.
// The guarded paths: the ruling store + audit log + config (which define what lifts and what
// the gate trusts) and the sessions dir (which defines what counts as the user's own words).
export function selfModVerdict(tool, input, { cwd, env = process.env } = {}) {
  const name = String(tool ?? "").toLowerCase();
  const cmd = /bash|shell|run_shell_command|terminal|zsh|sh/.test(name) ? String(input?.command ?? "") : "";
  if (/ruling\s+add|rulings(?:-use)?\.json|(?:GUARD|JEV_GUARD)_OPERATOR_CLI\s*=/.test(cmd))
    return "this command modifies the gate's own rulings — operator-only (run it from your own terminal)";
  return pathSelfModVerdict(tool, input, { cwd, env });
}

// Read-shaped tools never write: a Read of the gate's files is not self-modification.
const READ_SHAPED_TOOL = /^(read|view|cat|read_file|read_many_files|notebookread|list_directory|search_file_content|grep_search|glob|grep|ls|list)$|(^|_)read$/i;
// Write/edit-shaped tools get the "does not edit itself" phrasing; other non-read tools the neutral one.
const WRITE_SHAPED_TOOL = /^(write|edit|notebookedit|multiedit|write_file|replace|apply_patch|patch|delete)$|(^|_)(write|edit|delete)$/i;

// The path branch, split out so callers can scope the user-words lift to it: only a PATH-guard
// deny yields to the user's own words (operator ruling 2026-10-04); the bash-regex layer above
// denies unchanged in all cases (matrix row 5).
export function pathSelfModVerdict(tool, input, { cwd, env = process.env } = {}) {
  const candidate = typeof input === "string" ? input
    : input?.file_path ?? input?.path ?? input?.filePath ?? input?.notebook_path;
  if (!candidate || !guardedPathHit(candidate, { cwd, env })) return null;
  const name = String(tool ?? "").toLowerCase();
  if (READ_SHAPED_TOOL.test(name)) return null;  // reading the gate's files is not an edit
  return WRITE_SHAPED_TOOL.test(name)
    ? "this file is inside the guard's own store/config/sessions — operator-only (the gate does not edit itself)"
    : "this file is inside the guard's own store/config/sessions — operator-only";
}

// The gate's own paths: the store FILES inside each rulings home (guarding the whole directory
// would brick every Write on hosts where the home is a shared tree — this repo's root is one),
// the config overrides that live outside them, and the sessions DIRECTORY (it only ever holds
// gate state). Anything under/equal to one of these is a self-modification target.
function guardedPaths(env) {
  return [...new Set([
    ...[guardHome(env), guardHome({})].flatMap((h) => [join(h, "rulings.json"), join(h, "rulings-use.jsonl"), join(h, "config.json")]),
    sessionsDir(env), sessionsDir({}), CONFIG_FILE, LEGACY_CONFIG_FILE, env.GUARD_CONFIG, env.JEV_GUARD_CONFIG,
  ].filter(Boolean).map((p) => resolve(p)))];
}

const expandHome = (p) => (p === "~" || p.startsWith("~/") ? join(homedir(), p.slice(1)) : p);

export function guardedPathHit(candidate, { cwd, env = process.env } = {}) {
  const p = resolve(cwd ?? process.cwd(), expandHome(String(candidate)));
  return guardedPaths(env).some((g) => p === g || p.startsWith(g + sep));
}

// Brain-up floor: escalate the brain's non-deny verdict when the rules deny an active-floor
// family. Approved divergences and retired families never escalate.
export function floorVerdict(tool, input) {
  const rule = ruleVerdict(tool, input);
  return rule && ACTIVE_FLOOR.includes(rule.family) && !DIVERGENCE_FAMILIES.includes(rule.family) ? rule : null;
}

// Brain-down decision. `err` is the ask() failure; the returned { level, why, degraded }
// replaces the brain verdict. An allow ruling still resolves here — matching it needs no
// brain, and it is the operator's recorded answer to exactly this ask. The self-modification
// guard runs BEFORE the ruling consult and in every fallback mode: self-protection cannot be
// delegated to the heuristic stack, and no ruling may lift a write into the gate's own files.
export function degradedGate({ tool, input, cwd, sessionId, env = process.env, warnStream }, err) {
  const name = String(tool ?? "").toLowerCase();
  const selfMod = selfModVerdict(tool, input, { cwd, env });
  if (selfMod) return { level: "deny", degraded: true, selfMod, selfModPath: pathSelfModVerdict(tool, input, { cwd, env }),
    why: `while the brain is down, this is still operator-only — ${selfMod}` };
  const ruling = resolveRuling("ask", { tool, input, cwd, sessionId, env, warnStream });
  if (ruling) return { level: "allow", degraded: true, why: `by ruling ${ruling.id} (the brain is unreachable, but the ruling needs none)` };
  const rule = ruleVerdict(tool, input);
  if (fallbackMode(env) === "closed") {
    return rule
      ? { level: "deny", degraded: true, why: `while the brain is down, the built-in offline rules block it — ${rule.reason.replace(/^secret-leak-guard: /, "")}` }
      : { level: "deny", degraded: true, why: `the brain is unreachable (${err.message}) and this host runs unjangled-guardrails as the sole gate (GUARD_FALLBACK=closed), so it fails closed` };
  }
  if (fallbackMode(env) === "rules") {
    warn("brain unreachable — the built-in offline rules are the gate until it returns", warnStream);
    if (rule)
      return { level: "deny", degraded: true, why: `while the brain is down, the built-in offline rules block it — ${rule.reason.replace(/^secret-leak-guard: /, "")}` };
    // Operator ruling 2026-10-07 (evening): the degraded rules ARE the gate — no extra
    // default-deny. If the rules don't block it, it passes. One brain outage must not brick
    // the agent. The rules catch their classes (credential files, catastrophic commands,
    // env dumps); shapes they can't judge pass through with the marker until the brain returns.
    return { level: "allow", degraded: true, why: "the brain is unreachable — the call passed the built-in offline rules (semantic review resumes when the brain returns)" };
  }
  warn("brain unreachable — deferring to the installed heuristic stack", warnStream);
  return { level: "allow", degraded: true, why: "the brain is unreachable — deferring to the installed heuristic stack" };
}
