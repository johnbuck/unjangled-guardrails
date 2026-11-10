// Brain circuit breaker (posture-triage 5.8, operator rejected R5b): during a brain outage
// every judged call used to burn its full GUARD_TIMEOUT_MS budget. After N consecutive
// ask() timeouts (GUARD_BREAKER_THRESHOLD) the breaker opens: for a cool-down window
// (GUARD_BREAKER_COOLDOWN_MS) ask() throws immediately and guard.js's existing degrade path
// (degradedGate) resolves from the local rules floor instead of waiting out another timeout.
// Any healthy response resets the count and closes the breaker.
// The count lives in GUARD_HOME/breaker.json so it survives the one-shot hook processes —
// one process per judged tool call would reset an in-memory counter before it ever
// accumulated. Writes use rulings.js's atomic-rename pattern (R10). A state file the gate
// cannot read or write just disables the breaker — the gate itself is unchanged. A lost
// update between two concurrently timing-out processes (no lock here, unlike the rulings
// store) costs one extra counted timeout before the breaker opens; nothing else.
import { readFileSync, writeFileSync, renameSync, unlinkSync, mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { guardHome } from "./rulings.js";

export const breakerFile = (env = process.env) => join(guardHome(env), "breaker.json");

const DEFAULT_THRESHOLD = 3;
const DEFAULT_COOLDOWN_MS = 60_000;

// Out-of-range or non-numeric settings fall back to the default — a misconfigured breaker
// weakens the convenience, never the gate (same direction as the README threshold floors).
function num(v, dflt, min) {
  const n = +v;
  return Number.isFinite(n) && n >= min ? n : dflt;
}

export function breakerConfig(env = process.env) {
  return {
    threshold: num(env.GUARD_BREAKER_THRESHOLD, DEFAULT_THRESHOLD, 1),
    cooldownMs: num(env.GUARD_BREAKER_COOLDOWN_MS, DEFAULT_COOLDOWN_MS, 1),
  };
}

// Injectable closure: tests pass their own env (a temp GUARD_HOME) and a frozen `now`, or
// drive it end-to-end through ask() with a fetch stub. State shape: { timeouts, openedAt }.
export function createBreaker({ env = process.env, now = Date.now, file } = {}) {
  const path = file ?? breakerFile(env);
  const { threshold, cooldownMs } = breakerConfig(env);
  const read = () => {
    try {
      const s = JSON.parse(readFileSync(path, "utf8"));
      return { timeouts: +s.timeouts || 0, openedAt: s.openedAt == null ? null : +s.openedAt };
    } catch { return { timeouts: 0, openedAt: null }; }
  };
  const write = (s) => {
    try {
      mkdirSync(guardHome(env), { recursive: true, mode: 0o700 });
      const tmp = `${path}.tmp-${process.pid}-${randomUUID().slice(0, 8)}`;
      writeFileSync(tmp, JSON.stringify(s) + "\n", { mode: 0o600 });
      renameSync(tmp, path);
    } catch { /* unwritable GUARD_HOME: the breaker degrades to a no-op */ }
  };
  const open = (s) => s.openedAt != null && now() - s.openedAt < cooldownMs;
  return {
    // Open = inside the cool-down window. A window that has elapsed reads as closed without
    // a write; recordTimeout starts a fresh count from there.
    isOpen: () => open(read()),
    recordTimeout() {
      const s = read();
      if (open(s)) return;  // the window is already running — a skip never extends it
      const timeouts = (s.openedAt != null ? 0 : s.timeouts) + 1;  // expired window: fresh count
      write({ timeouts, openedAt: timeouts >= threshold ? now() : null });
    },
    recordHealthy() {
      const s = read();
      if (s.timeouts === 0 && s.openedAt == null) return;  // the happy path: no state, no I/O
      write({ timeouts: 0, openedAt: null });
    },
  };
}
