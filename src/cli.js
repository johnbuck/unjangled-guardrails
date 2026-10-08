#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const [cmd, ...rest] = process.argv.slice(2);

const USAGE = `unjangled-guardrails — prompt-injection and dangerous-action guard for coding agents, powered by Jev

  unjangled-guardrails hook [--agent codex|copilot|hermes]  Command hook (JSON on stdin → JSON on stdout) for Claude Code, Codex, Copilot CLI,
                                                 Gemini CLI and Cursor; the host is detected from the payload, --agent overrides
  unjangled-guardrails acp -- <agent command...>            ACP proxy: unjangled-guardrails acp -- claude-agent-acp
  unjangled-guardrails check <tool> '<json input>'          Assess one tool call, e.g. check Bash '{"command":"rm -rf /"}'
  unjangled-guardrails scan [file]                          Scan a file (or stdin) for AI-directed instructions
  unjangled-guardrails scan-skills [paths...]               Sweep skills, plugins, rules and CLAUDE.md/AGENTS.md files (default: every
                                                 agent's user dirs + the current project) for instructions their installer
                                                 would not expect; cached by content hash, exit 2 if anything is flagged
  unjangled-guardrails install <agent>                      Register in that agent's user config:
                                                 claude | codex | copilot | gemini | cursor | pi | opencode
                                                 (one install = the whole plugin: brain + rulings + orchestrator)
  unjangled-guardrails verify <harness>                     Live-verify that harness's REAL surface with the battery's must-pass
                                                 safe call and must-stop destructive call (probes are scored, never
                                                 executed); appends evidence/live-verify-<harness>-<date>.jsonl.
                                                 Harnesses: opencode | claude | pi | codex | copilot | gemini | cursor
  unjangled-guardrails setup <agent>                        One commanded path from clone to a verified first session: install that
                                                 agent's hooks, create the empty operator rulings store, live-verify the
                                                 REAL surface, and print the five-section readiness report (backend /
                                                 registration / rulings / verification / calibration) with one evidence row
  unjangled-guardrails key <api key>                        Save the key to ~/.unjangled-guardrails/config.json (0600); vck_… keys are
                                                 treated as Vercel AI Gateway keys, anything else as TypeSafe
  unjangled-guardrails key --local <url> [key]              Save a local Jev-compatible backend URL (and optional bearer key)
  unjangled-guardrails ruling add|list|revoke               Operator rulings: scoped, expiring allow/deny overrides the gate
                                                 consults on ask/allow verdicts (rulings may lift denies; only genuine
                                                 user words or an operator ruling can — never untrusted content)

Credentials are read from JEV_API_KEY / AI_GATEWAY_API_KEY / VERCEL_OIDC_TOKEN first, then from that file.`;

switch (cmd) {
  case "hook": {
    const { main } = await import("./hook.js");
    await main(rest);
    break;
  }
  case "acp": {
    const args = rest[0] === "--" ? rest.slice(1) : rest;
    if (!args.length) die("acp needs an agent command after --");
    const { runProxy } = await import("./acp.js");
    runProxy(args[0], args.slice(1));
    break;
  }
  case "check": {
    if (!rest[0]) die("check needs a tool name and a JSON input argument");
    let input;
    try { input = rest[1] ? JSON.parse(rest[1]) : {}; }
    catch { die("check: the input argument is not valid JSON"); }
    const { assessAction } = await import("./guard.js");
    const r = await assessAction({ tool: rest[0], input, cwd: process.cwd() }).catch((e) => die(`${e.message} (exit 3)`, 3));
    console.log(r ? `${r.level.toUpperCase()}  ${r.message}` : "SKIPPED  read-only tool");
    process.exitCode = r?.level === "deny" ? 2 : r?.level === "ask" ? 1 : 0;
    break;
  }
  case "scan": {
    const { scanContent } = await import("./guard.js");
    const text = rest[0] ? readFileSync(rest[0], "utf8") : readFileSync(0, "utf8");
    const r = await scanContent({ text, tool: "scan", source: rest[0] }).catch((e) => die(`${e.message} (exit 3)`, 3));
    console.log(r ? `${r.flagged ? "FLAGGED" : "CLEAN"}  ${r.message}` : "SKIPPED  too short to scan");
    process.exitCode = r?.flagged ? 2 : 0;
    break;
  }
  case "scan-skills": {
    const { findInstructionFiles, projectRoots, scanFiles, userRoots } = await import("./skills.js");
    const roots = rest.length ? rest.map((r) => resolve(r)) : [...userRoots(), ...projectRoots()];
    const files = findInstructionFiles(roots);
    if (!files.length) { console.log("unjangled-guardrails: no instruction files found"); break; }
    process.stderr.write(`unjangled-guardrails: scanning ${files.length} instruction files…\n`);
    const results = await scanFiles(files);
    const flagged = results.filter((r) => r.flagged), errors = results.filter((r) => r.error);
    for (const r of flagged) console.log(`FLAGGED  ${r.file}\n         ${r.kind.replace("_", " ")} p=${r.p}${r.cached ? " (cached)" : ""}`);
    for (const r of errors) console.log(`ERROR    ${r.file}: ${r.error}`);
    console.log(`${results.length} scanned (${results.filter((r) => r.cached).length} cached), ${flagged.length} flagged, ${errors.length} errors`);
    process.exitCode = flagged.length ? 2 : errors.length ? 3 : 0;
    break;
  }
  case "install": {
    const { installFor } = await import("./install.js");
    try { installFor(rest[0]); } catch (e) { die(e.message); }
    keyHint();
    break;
  }
  case "verify": {
    // tools/ ships in the git checkout, not the npm tarball — say so plainly rather than a stack trace.
    const { runLiveVerify } = await import("../tools/verify/live-verify.mjs").catch(() => ({}));
    if (!runLiveVerify) die("verify lives in tools/, which the npm tarball does not ship; run it from a git clone of unjangled-guardrails");
    process.exitCode = await runLiveVerify(rest[0], { log: console.log });
    break;
  }
  case "setup": {
    // tools/ ships in the git checkout, not the npm tarball (same caveat as verify — the
    // setup module's own import of the live-verify runner is what fails).
    const { runSetup } = await import("./setup.js").catch(() => ({}));
    if (!runSetup) die("setup runs the live-verify step from tools/, which the npm tarball does not ship; run it from a git clone of unjangled-guardrails");
    try { process.exitCode = await runSetup(rest[0], { log: console.log }); }
    catch (err) { die(`${err.message} (exit 3)`, 3); }
    break;
  }
  case "key": {
    const { CONFIG_FILE, readConfig } = await import("./jev.js");
    const positional = rest.filter((a) => !a.startsWith("--"));
    if (rest.includes("--local")) {
      const [url, localKey] = positional;
      if (!url) die("key --local needs the backend URL as an argument");
      const cfg = { ...readConfig(), localBaseUrl: url, ...(localKey ? { localApiKey: localKey } : {}) };
      mkdirSync(dirname(CONFIG_FILE), { recursive: true, mode: 0o700 });
      writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
      console.log(`unjangled-guardrails: local backend ${url} saved to ${CONFIG_FILE}${localKey ? " (with API key)" : ""}`);
      break;
    }
    const key = positional[0];
    if (!key) die("key needs the API key as an argument");
    const gateway = rest.includes("--gateway") || key.startsWith("vck_");
    const cfg = { ...readConfig(), [gateway ? "aiGatewayApiKey" : "jevApiKey"]: key };
    mkdirSync(dirname(CONFIG_FILE), { recursive: true, mode: 0o700 });
    writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
    console.log(`unjangled-guardrails: ${gateway ? "Vercel AI Gateway" : "TypeSafe"} key saved to ${CONFIG_FILE}`);
    break;
  }
  case "ruling": {
    const [sub, ...args] = rest;
    const flag = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
    const R = await import("./rulings.js");
    if (sub === "add") {
      // Operator-only by design: an agent that can grant itself a ruling can lift every deny.
      // The authority gate lives in the library (rulings.js operatorContext) so no entry point
      // — CLI, script, or import — can skip it. Here we only keep the human-facing message.
      let ruling;
      try {
        ruling = R.addRuling({
          effect: flag("--effect"), pattern: flag("--pattern"), tool: flag("--tool"),
          scope: flag("--scope", `project:${process.cwd()}`), expiresAt: flag("--expires"), reason: flag("--reason"),
        });
      } catch (err) {
        if (/operator-only/.test(err.message)) die("ruling add is operator-only: run it from your own terminal. Agents must not self-grant rulings.", 1);
        die(`ruling add: ${err.message}`, 1);
      }
      console.log(`unjangled-guardrails: ruling ${ruling.id} saved (${ruling.effect} '${ruling.pattern}', scope ${ruling.scope}, expires ${ruling.expiresAt ?? "never"})`);
    } else if (sub === "list") {
      const now = Date.now();
      const rulings = R.listRulings();
      if (!rulings.length) console.log("no rulings");
      for (const r of rulings) console.log(`${r.id}  ${r.effect.padEnd(4)}  ${r.pattern}  tool=${r.tool ?? "any"}  scope=${r.scope}  expires=${r.expiresAt ?? "never"}${Date.parse(r.expiresAt ?? "") <= now ? "  [EXPIRED]" : ""}${r.reason ? `\n     reason: ${r.reason}` : ""}`);
    } else if (sub === "revoke") {
      if (!args[0]) die("ruling revoke needs a ruling id (see `ruling list`)", 1);
      try { R.revokeRuling(args[0]); }  // the library gate covers revoke too (plan 1.1)
      catch (err) { if (/operator-only/.test(err.message)) die("ruling revoke is operator-only: run it from your own terminal. Agents must not revoke operator rulings.", 1); die(`ruling revoke: ${err.message}`, 1); }
      console.log(`unjangled-guardrails: ruling ${args[0]} revoked`);
    } else {
      die("ruling needs a subcommand: add | list | revoke\n" +
        "  ruling add --effect allow|deny --pattern '<command glob>' [--tool Bash] [--scope global|project|project:<path>|session:<id>]\n" +
        "            [--expires <ISO date | 7d | 12h | 30m>] [--reason 'why']\n" +
        "            (global rulings require an explicit --expires; project defaults to 30d, session to 7d)");
    }
    break;
  }
  default:
    console.log(USAGE);
    process.exitCode = cmd ? 1 : 0;
}

async function keyHint() {
  const { backend } = await import("./jev.js");
  if (!backend()) console.log("No backend configured yet: set SYSTEMONE_URL for a local service, or run `unjangled-guardrails key <key>` / `unjangled-guardrails key --local <url>`. Until then the guard fails open.");
}

function die(msg, code = 1) { console.error(`Unjangled Guardrails: ${msg}${code === 1 ? `\n\n${USAGE}` : ""}`); process.exit(code); }
