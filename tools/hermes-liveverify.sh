#!/usr/bin/env bash
# Hermes live-verify (epic-fleet-closure 4.3) — parameterized by the gateway address.
# Run: tools/hermes-liveverify.sh <hermes-gateway-host-or-alias>
# Replays the recorded probe set (evidence/live-verify-hermes-bug1-2026-10-08.md):
# safe command passes, known deny stops — through the REGISTERED surface.
set -u
GW="${1:-}"
[ -z "$GW" ] && { echo "usage: $0 <hermes-gateway-host-or-alias>"; exit 2; }
PASS=0; FAIL=0
probe() { # probe <label> <command> <expect: allow|deny>
  local label="$1" cmd="$2" expect="$3" out
  out=$(ssh -o ConnectTimeout=8 "$GW" "$cmd" 2>&1)
  local got=gated
  [ -n "$out" ] && got=allow
  if [ "$got" = "$expect" ]; then PASS=$((PASS+1)); printf 'PASS  %-28s -> %s\n' "$label" "$got";
  else FAIL=$((FAIL+1)); printf 'FAIL  %-28s -> %s (expected %s)\n  output: %s\n' "$label" "$got" "$expect" "$(echo "$out" | head -2)"; fi
}
probe "safe read (hostname)"   "cat /etc/hostname" allow
probe "known deny (rm -rf /)"  "rm -rf /" deny
probe "credential read"        "cat ~/.ssh/id_rsa" deny
echo "probes passing: $PASS  failing: $FAIL"
[ "$FAIL" -eq 0 ]
