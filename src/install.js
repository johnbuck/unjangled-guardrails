// The install step: register the guard in one agent's user config. Extracted from cli.js so
// `setup` (src/setup.js) can run the same logic in-process — one install surface, no
// re-derivation, identical output lines and idempotence semantics.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const INSTALL_TARGETS = ["claude", "codex", "copilot", "gemini", "cursor", "pi", "opencode"];

// Message spans shared with the setup chain (src/setup.js) and the CLI paths (src/cli.js) — one
// home so the wording cannot drift between copies. Pinned at fragment level by spawn tests
// (test/detect.test.js for the ACP sentence, test/calibrate.test.js for the usage errors);
// docs/messages.md does not canonically pin these — if you reword either span, update those
// fragments. They live here because this module is the one the npm tarball always ships with
// no tools/ import: every importer can load it unconditionally.
export const ACP_NOTE = "(ACP is configured in the editor: see README)";
export const KEY_HINT = "set SYSTEMONE_URL for a local service, or run `unjangled-guardrails key <key>` / `unjangled-guardrails key --local <url>`";

// What counts as this guard's own registration entry (the idempotence filter: ours is replaced,
// anything else is left alone). One fingerprint, two element shapes: hook-group objects
// (compared through their JSON) and the pi extension list's plain strings.
const GUARD_RE = /unjangled-guardrails|jev-guard/;

/** Register in the agent's user config. Throws on a bad target, the npx cache, or an un-forced
 *  cross-generation install (opencode only); returns the written path (+ note) so callers can
 *  report registration honestly from install's own output.
 *  Options: `v2` (opencode only) writes the v2 adapter — default-exports UnjangledGuardrailsV2,
 *  the {id, setup} form the v2.0.24 loader accepts — instead of the v1 named re-export, same
 *  filename (one host = one adapter; per-host content is the whole point). `home` retargets the
 *  write at an alternate HOME tree (tests and the battery target a copy of the committed
 *  fixture, never the real profile). `force` (opencode only) overrides the install-time
 *  ownership gate below — the other-generation warning still prints (epic-host-isolation).
 *  `askPermissions` (opencode only) PRINTS the opencode.json permission snippet and its
 *  tradeoff — never writes opencode.json: opt-in means the operator runs and accepts it
 *  (epic-installer ticket 7). The default install output is silent on the permission topic. */
export function installFor(target, { log = console.log, v2 = false, home: homeOpt, force = false, askPermissions = false } = {}) {
  if (ROOT.includes("/_npx/") || ROOT.includes("\\_npx\\")) throw new Error("running from the npx cache, which gets pruned; install with `npm i -g unjangled-guardrails` (or git clone) and run install from there");
  const cli = join(ROOT, "src", "cli.js");
  // Absolute node path: GUI hosts (Cursor, Zed) launched from a Dock don't have nvm/volta on PATH.
  const cmd = (extra = "") => `"${process.execPath}" "${cli}" hook${extra}`;
  const notOurs = (list) => (list ?? []).filter((g) => !GUARD_RE.test(JSON.stringify(g)));
  if (typeof homeOpt === "string" && !homeOpt.trim()) throw new Error("install: --home was given but empty; refusing to fall back to the real HOME");
  const home = homeOpt ? resolve(homeOpt) : homedir();
  let file, cfg, note = "";
  switch (target) {
    case "claude":
    case "codex": {  // same group shape; Codex has no PreToolUse "ask" yet, so the flag switches ask → warning
      file = target === "claude" ? join(home, ".claude", "settings.json") : join(home, ".codex", "hooks.json");
      cfg = readJson(file);
      cfg.hooks ??= {};
      const entry = { matcher: ".*", hooks: [{ type: "command", command: cmd(target === "codex" ? " --agent codex" : ""), timeout: 30 }] };
      const events = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", ...(target === "claude" ? ["InstructionsLoaded"] : [])];
      for (const ev of events) cfg.hooks[ev] = [...notOurs(cfg.hooks[ev]), entry];
      if (target === "codex") note = "Run /hooks inside Codex to trust them.";
      break;
    }
    case "copilot": {  // PascalCase event names give the Claude-shaped payload; output fields are top-level
      file = join(home, ".copilot", "hooks", "unjangled-guardrails.json");
      cfg = { version: 1, hooks: {} };
      for (const ev of ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"]) cfg.hooks[ev] = [{ type: "command", bash: cmd(" --agent copilot"), timeoutSec: 30 }];
      break;
    }
    case "gemini": {
      file = join(home, ".gemini", "settings.json");
      cfg = readJson(file);
      cfg.hooks ??= {};
      const entry = { hooks: [{ name: "unjangled-guardrails", type: "command", command: cmd(), timeout: 30_000 }] };
      for (const ev of ["BeforeTool", "AfterTool", "BeforeAgent", "SessionStart"]) cfg.hooks[ev] = [...notOurs(cfg.hooks[ev]), entry];
      break;
    }
    case "cursor": {  // beforeShell/MCP enforce "ask"; preToolUse only for the remaining mutating tools
      file = join(home, ".cursor", "hooks.json");
      cfg = readJson(file);
      cfg.version ??= 1;
      cfg.hooks ??= {};
      const add = (ev, extra = {}) => (cfg.hooks[ev] = [...notOurs(cfg.hooks[ev]), { command: cmd(), timeout: 30, ...extra }]);
      add("beforeShellExecution"); add("beforeMCPExecution"); add("preToolUse", { matcher: "Write|Delete" }); add("postToolUse");
      add("beforeSubmitPrompt"); add("sessionStart");
      break;
    }
    case "pi": {
      file = join(home, ".pi", "agent", "settings.json");
      cfg = readJson(file);
      const ext = join(ROOT, "extensions", "unjangled-guardrails.ts");
      cfg.extensions = [...(cfg.extensions ?? []).filter((p) => !GUARD_RE.test(p)), ext];
      break;
    }
    case "opencode":  // local plugin files are loaded as-is, so the adapter just re-exports from this checkout
      return installOpencode({ home, v2, force, askPermissions, log });
    default:
      throw new Error(`install target must be one of ${INSTALL_TARGETS.join(", ")} ${ACP_NOTE}`);
  }
  writeJson(file, cfg);
  log(`unjangled-guardrails: written to ${file}${note ? "\n" + note : ""}`);
  log("One install = the whole plugin: adapter surface + semantic brain + operator rulings + orchestrator (built-in offline rules as the degraded-mode floor). No other guard plugin is needed alongside it.");
  return { file, note };
}

// ── the opencode install: adapter write behind the generation-ownership gate ────────────────────
// The one target with a file adapter, a gate, and an opt-in note — kept out of installFor's switch
// (which stays pure per-target dispatch); it returns without the shared tail because the adapter is
// written directly and the report line carries the note inline.
function installOpencode({ home, v2, force, askPermissions, log }) {
  // Ownership gate first (epic-host-isolation): the adapter already in the target HOME names
  // its generation, and writing the other one is the exact silent mismatch the loading
  // probe proved harmful (v1 host + v2 adapter = per-boot SchemaError; v2 host + v1 adapter = the
  // gate silently lost). Detection reads only — nothing here rewrites or cleans the other
  // generation's files — and a matching-generation install behaves exactly as before.
  const want = v2 ? "v2" : "v1";
  const { owned, conflict } = detectOwnership(home);
  // Gate only on OBSERVED state: an empty HOME (conflict empty) writes as today; a
  // matching-generation adapter rewrites as today; mismatch or ambiguity is what refuses.
  if (conflict.length && owned !== want) {
    const found = conflict.map((f) => `  ${f.file} (${f.gen === "unknown" ? "unrecognized shape" : `${f.gen} adapter`})`).join("\n");
    if (force) {
      log(`unjangled-guardrails: WARNING — target HOME ${owned ? `holds ${owned} state` : "holds unattributable state"}:\n${found}\nWriting the ${want} adapter anyway (--force); the other generation's loader will misbehave until this host is reconciled.`);
    } else {
      throw new Error(`install opencode: refusing to write the ${want} adapter — the target HOME already holds:\n${found}\n` +
        (owned
          ? `Mixing generations is the silent mismatch the loading probe proved harmful: a v1 host given a v2 adapter SchemaErrors on every boot; a v2 host given a v1 adapter silently loses the gate. `
          : `Ownership is ambiguous: an unrecognized adapter shape, or both generations present, so the takeover cannot be attributed cleanly. `) +
        `Re-run \`install opencode${want === "v2" ? " --v2" : ""} --force\` to write anyway (the warning prints either way).`);
    }
  }
  const file = join(home, ".config", "opencode", "plugins", "unjangled-guardrails.js");
  mkdirSync(dirname(file), { recursive: true });
  // v1 (default): the named re-export, byte-identical to the pre-v2 adapter — v1's loader treats
  // every export as a plugin function, so no default export may appear here. v2 (--v2): the
  // default-exported {id, setup} definition the v2.0.24 loader requires (a named re-export is
  // REJECTED there: SchemaError(Missing key at ["default"])). Same filename either way; the
  // band contract the hooks behind either adapter map onto is VERDICTS in src/contract.js (AD-2)
  // — install picks the loader entry shape only, never a verdict vocabulary.
  writeFileSync(file, v2
    ? `import { UnjangledGuardrailsV2 } from ${JSON.stringify(join(ROOT, "src", "opencode.js"))};\nexport default UnjangledGuardrailsV2;\n`
    : `export { UnjangledGuardrails } from ${JSON.stringify(join(ROOT, "src", "opencode.js"))};\n`);
  // Ticket 7 (epic-installer): the permission-ask config is opt-in. --ask-permissions only
  // PRINTS the snippet with its tradeoff stated in the same breath (OpenCode then prompts
  // on EVERY bash call, not just the ones the gate flags); it never writes opencode.json —
  // the operator runs and accepts it. The default output stays silent on the permission
  // topic: a recommendation printed unprompted reads like part of the install, and the
  // tradeoff only lands when the operator asked for the feature. The auto-approve half is
  // claimed only where it exists: on the default v1 adapter the permission.ask hook is never
  // dispatched (src/opencode.js, OpenCode 1.18.31) and tool.execute.before can only veto,
  // so the note names the tradeoff alone; --v2's permission.evaluate does auto-approve the
  // safe calls, so the second half rides the --v2 print only.
  const note = askPermissions
    ? 'For approval prompts, set in opencode.json:\n{\n  "permission": { "bash": "ask" }\n}\n' +
      "Tradeoff: that asks for EVERY bash call, not just the ones unjangled-guardrails flags." +
      (v2 ? " The v2 adapter auto-approves the safe ones, so you still only answer the risky ones." : "")
    : "";
  log(`unjangled-guardrails: plugin adapter written to ${file}${note ? "\n" + note : ""}\nOne install = the whole plugin: adapter surface + semantic brain + operator rulings + orchestrator (built-in offline rules as the degraded-mode floor).`);
  return { file, note };
}

function readJson(file) { return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {}; }
function writeJson(file, obj) { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); }

// ── install-time state-ownership detection (epic-host-isolation, opencode only) ─────────────
// The adapter's export shape is the generation fingerprint (plugin-loading probe, shapes a/g):
// v1 = a named re-export with no default export; v2 = a default-exported {id, setup} definition.
// Reading the first lines of an existing adapter classifies it without executing anything.
const ADAPTER_FILE = "unjangled-guardrails.js";
// v2's loader scans BOTH plugin dirs identically (dedupe by plugin id), so a v1-owned marker can
// sit in either — both are checked under the same HOME tree the write would land in.
const OPENCODE_PLUGIN_DIRS = (home) => [join(home, ".config", "opencode", "plugins"), join(home, ".opencode", "plugins")];

// "v1" | "v2" for the two known shapes; "unknown" for anything else (unreadable, empty, foreign).
function adapterGeneration(text) {
  const head = String(text).slice(0, 2048);
  if (/^\s*export\s+default\b/m.test(head)) return "v2";
  if (/export\s*\{\s*UnjangledGuardrails\s*\}/.test(head)) return "v1";
  return "unknown";
}

// Which generation owns the target HOME: { owned: "v1"|"v2"|null, conflict: [{file, gen}] }.
// owned is null either when no adapter exists (conflict empty — free HOME, write as today) or when
// the signals are ambiguous (adapters of both generations, or a shape matching neither — conflict
// non-empty, refused like any mismatch).
function detectOwnership(home) {
  const conflict = [];
  for (const dir of OPENCODE_PLUGIN_DIRS(home)) {
    const file = join(dir, ADAPTER_FILE);
    if (!existsSync(file)) continue;
    let gen = "unknown";
    try { gen = adapterGeneration(readFileSync(file, "utf8")); } catch { /* unreadable counts as unknown */ }
    conflict.push({ file, gen });
  }
  const gens = [...new Set(conflict.map((f) => f.gen))];
  return { owned: gens.length === 1 && gens[0] !== "unknown" ? gens[0] : null, conflict };
}
