// Orchestrator (Story 12; consolidation 2026-10-20): one judgment order for every adapter.
// The consolidation collapsed the posture stack: layer 1 is Always-Deny (src/always-deny.js —
// both vendored cores and the self-mod guards, pre-brain, chat-blind), layer 2 is the brain
// (every non-Always-Denied call), layer 3 is the CONFIG policy (src/policy.js — effects on the
// verdict, rulings folded in as command entries). What survives HERE is the degradation
// posture: the brain-down resolution for calls Always-Deny did not claim.
//   fail-open (default) — Always-Deny gated, the call passes, semantic review resumes when
//     the brain returns (operator ruling 2026-10-07 evening: one brain outage must not brick
//     the agent).
//   fail-closed — hardenable two ways: GUARD_FALLBACK=closed (env, per-process, the sole-gate
//     posture) or the policy config option degradation: "fail-closed" (per-install).
//   layered — the explicit env opt-in pass-through to a host heuristic stack.
import { resolveRuling, warn } from "./rulings.js";
import { loadPolicyStore } from "./policy.js";

// Brain-down decision. `err` is the ask() failure; the returned { level, why, degraded }
// replaces the brain verdict. Always-Deny has already gated (it is the degradation floor and
// ran before the brain was consulted), so what resolves here is only: the operator's standing
// command entries (a recorded allow needs no brain — it is the operator's answer to exactly
// this call), then the posture for everything Always-Deny did not claim.
export function degradedVerdict({ tool, input, cwd, sessionId, env = process.env, warnStream }, err) {
  const entry = resolveRuling("ask", { tool, input, cwd, sessionId, env, warnStream });
  if (entry) return { level: "allow", degraded: true, why: `by ruling ${entry.id} (the brain is unreachable, but the ruling needs none)` };
  const mode = fallbackMode(env);
  if (mode === "closed")
    return { level: "deny", degraded: true, why: `the brain is unreachable (${err.message}) and this host runs unjangled-guardrails as the sole gate (GUARD_FALLBACK=closed), so it fails closed` };
  if (mode === "layered") {
    warn("brain unreachable — deferring to the installed heuristic stack", warnStream);
    return { level: "allow", degraded: true, why: "the brain is unreachable — deferring to the installed heuristic stack" };
  }
  // rules mode: Always-Deny IS the built-in offline rules now — they already ran. The only
  // question left is what an unmatched call does, and that is the policy config option
  // (degradation: fail-open default, operator-configurable — resolved design decision 2,
  // plan-consolidation-two-layers).
  const policy = loadPolicyStore(env, { warnStream });
  if (policy?.degradation === "fail-closed")
    return { level: "deny", degraded: true, why: `the brain is unreachable (${err.message}) and this install's policy sets degradation: fail-closed, so it fails closed` };
  warn("brain unreachable — the built-in offline rules are the gate until it returns", warnStream);
  return { level: "allow", degraded: true, why: "the brain is unreachable — the call passed the built-in offline rules (semantic review resumes when the brain returns)" };
}

// Operator ruling 2026-10-04 (final form): the env posture surface, unchanged. Default
// "rules" — brain down → Always-Deny gated, unmatched calls pass. "layered" is the explicit
// opt-in for hosts that keep an external heuristic stack installed; "closed" denies
// everything unmatched and is for sole-gate hardening. All spellings of the legacy
// fail-closed flag map to closed.
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
