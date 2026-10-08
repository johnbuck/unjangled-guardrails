// The install step: register the guard in one agent's user config. Extracted from cli.js so
// `setup` (src/setup.js) can run the same logic in-process — one install surface, no
// re-derivation, identical output lines and idempotence semantics.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const INSTALL_TARGETS = ["claude", "codex", "copilot", "gemini", "cursor", "pi", "opencode"];

/** Register in the agent's user config. Throws on a bad target or the npx cache; returns the
 *  written path (+ note) so callers can report registration honestly from install's own output. */
export function installFor(target, { log = console.log } = {}) {
  if (ROOT.includes("/_npx/") || ROOT.includes("\\_npx\\")) throw new Error("running from the npx cache, which gets pruned; install with `npm i -g unjangled-guardrails` (or git clone) and run install from there");
  const cli = join(ROOT, "src", "cli.js");
  // Absolute node path: GUI hosts (Cursor, Zed) launched from a Dock don't have nvm/volta on PATH.
  const cmd = (extra = "") => `"${process.execPath}" "${cli}" hook${extra}`;
  const notOurs = (list) => (list ?? []).filter((g) => !/unjangled-guardrails|jev-guard/.test(JSON.stringify(g)));
  const home = homedir();
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
      cfg.extensions = [...(cfg.extensions ?? []).filter((p) => !/unjangled-guardrails|jev-guard/.test(p)), ext];
      break;
    }
    case "opencode": {  // local plugin files are loaded as-is, so the shim just re-exports from this checkout
      file = join(home, ".config", "opencode", "plugins", "unjangled-guardrails.js");
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, `export { UnjangledGuardrails } from ${JSON.stringify(join(ROOT, "src", "opencode.js"))};\n`);
      note = 'For approval prompts, set "permission": { "bash": "ask" } in opencode.json; unjangled-guardrails then auto-approves the safe calls.';
      log(`unjangled-guardrails: plugin shim written to ${file}${note ? "\n" + note : ""}\nOne install = the whole plugin: adapter surface + semantic brain + operator rulings + orchestrator (built-in offline rules as the degraded-mode floor).`);
      return { file, note };
    }
    default:
      throw new Error("install target must be one of claude, codex, copilot, gemini, cursor, pi, opencode (ACP is configured in the editor: see README)");
  }
  writeJson(file, cfg);
  log(`unjangled-guardrails: written to ${file}${note ? "\n" + note : ""}`);
  log("One install = the whole plugin: adapter surface + semantic brain + operator rulings + orchestrator (built-in offline rules as the degraded-mode floor). No other guard plugin is needed alongside it.");
  return { file, note };
}

function readJson(file) { return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {}; }
function writeJson(file, obj) { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); }
