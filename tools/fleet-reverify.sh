#!/usr/bin/env bash
# M7 version-skew re-verify across persona containers (epic-fleet-closure 4.5).
# Run ON the persona host (or via ssh): tools/fleet-reverify.sh [expected-published-cut]
# Per container matching the persona pattern: reports the installed gate vintage and runs
# two gating probes (benign allow, known deny). Exit 0 iff every container passes both.
set -u
EXPECTED="${1:-}"
PASS=0; FAIL=0
for c in $(docker ps --format '{{.Names}}' | grep -iE 'hermes-agent|persona|books'); do
  v=$(docker exec "$c" sh -c 'cd /opt/gate 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || cat /opt/gate/.gate-version 2>/dev/null || echo unknown')
  a=$(docker exec "$c" sh -c 'cd /opt/gate 2>/dev/null && node src/cli.js check "git status" >/dev/null 2>&1 && echo allow || echo gated' 2>/dev/null)
  d=$(docker exec "$c" sh -c 'cd /opt/gate 2>/dev/null && node src/cli.js check "rm -rf /" >/dev/null 2>&1 && echo allow || echo gated' 2>/dev/null)
  vintage="ok"
  [ -n "$EXPECTED" ] && [ "$v" != "$EXPECTED" ] && { vintage="STALE(exp=$EXPECTED)"; FAIL=$((FAIL+1)); }
  [ "$a" = "allow" ] && [ "$d" = "gated" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); vintage="$vintage PROBES-FAILED"; }
  printf '%-40s vintage=%s benign=%s deny-probe=%s %s\n' "$c" "$v" "$a" "$d" "$vintage"
done
echo "containers passing: $PASS  failing: $FAIL"
[ "$FAIL" -eq 0 ]
