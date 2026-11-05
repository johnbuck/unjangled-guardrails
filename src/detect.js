// Harness detection for targetless install/setup (epic-installer ticket 3). Answers "which
// harness am I in?" from the only signals that exist (live-probed 2026-10-09): the CLAUDECODE
// env marker, else the registration files install writes. No harness but Claude Code sets a
// detectable env var (opencode, cursor, gemini, codex, copilot, pi set none — no speculative
// env reads for them), so registration presence is their only signal. Ambiguity and unknown
// environments stay loud: the callers print the candidates and exit 1 — never a silent pick
// between registrations (this dev host itself registers several harnesses at once).
// This is NOT src/hook.js's detectAgent: that answers hook-time agent identity from the
// payload shape (a different question); this answers install-time host identity from the
// environment, before any payload exists.
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { INSTALL_TARGETS } from "./install.js";

// One registration path per INSTALL_TARGET, copied from installFor's switch cases — the only
// files detection may credit are the exact files installFor writes. test/detect.test.js pins
// writer and table together by installing every target and comparing the returned paths.
const REGISTRATIONS = {
  claude: (home) => join(home, ".claude", "settings.json"),
  codex: (home) => join(home, ".codex", "hooks.json"),
  copilot: (home) => join(home, ".copilot", "hooks", "unjangled-guardrails.json"),
  gemini: (home) => join(home, ".gemini", "settings.json"),
  cursor: (home) => join(home, ".cursor", "hooks.json"),
  pi: (home) => join(home, ".pi", "agent", "settings.json"),
  opencode: (home) => join(home, ".config", "opencode", "plugins", "unjangled-guardrails.js"),
};

/** Every target's registration path under `home`, in INSTALL_TARGETS order — the candidate
 *  table the CLI prints when detection cannot answer (ambiguous or unknown). */
export function registrations(home = homedir()) {
  return INSTALL_TARGETS.map((target) => ({ target, path: REGISTRATIONS[target](home) }));
}

/** Resolve the running harness. Returns exactly one of:
 *  {target, signal}  — decided; `signal` names what decided it (the env marker or the path)
 *  {ambiguous:[…]}   — two or more registrations and no env marker: the candidates with paths
 *  {unknown: true}   — no marker, no registration anywhere under home
 *  Explicit targets never reach this — the CLI resolves those before calling (detection is
 *  consulted only for a targetless install/setup, and the CLAUDECODE marker beats every
 *  registration: a Claude session is claude even on a machine registered everywhere). */
export function detectHarness({ env = process.env, home = homedir() } = {}) {
  if (env.CLAUDECODE) return { target: "claude", signal: "env CLAUDECODE" };
  const hits = registrations(home).filter((e) => existsSync(e.path));
  if (hits.length === 1) return { target: hits[0].target, signal: `registration ${hits[0].path}` };
  if (hits.length > 1) return { ambiguous: hits };
  return { unknown: true };
}

/** The candidate table: one "  <target>    <path>" line per candidate, INSTALL_TARGETS order. */
export function candidateTable(entries) {
  return entries.map((e) => `  ${e.target.padEnd(9)} ${e.path}`).join("\n");
}
