#!/usr/bin/env bash
# scripts/verify-claude-container.sh — prove the claude registration end-to-end (epic-installer ticket 6).
#
# WHAT THIS PROVES: that what `install claude` writes into ~/.claude/settings.json is what the
# REAL Claude Code harness loads and executes — the one adapter surface the in-process live-verify
# rows could not prove (they spawned the hook command directly, hence registered:false).
#
# The run, in order:
#   1. prerequisites (before anything is provisioned)
#   2. a CLEAN container comes up: node base, the checkout mounted, no operator HOME
#   3. Claude Code installs from npm inside it
#   4. `install claude` (the mounted checkout's CLI) registers the gate in the container's own
#      /root/.claude/settings.json — written by THIS run, inside THIS container
#   5. a REAL claude session (print mode) makes a real tool call, so the harness actually loads
#      that registration and fires the registered PreToolUse hook
#   6. the guard's session store proves the hook ran inside the real session (side effects)
#   7. `verify claude` runs the battery's two probes through the REGISTERED command and appends
#      evidence rows to the mounted repo asserting registered:true with the non-null hookConfig
#
# This run's evidence rows ARE the artifact (evidence/live-verify-claude-<date>.jsonl, landed in
# the mounted repo); this committed recipe is the stranger's re-run path.
#
# PREREQUISITES (each checked, named, exit 1, nothing provisioned if missing):
#   - docker, daemon up
#   - ANTHROPIC_API_KEY in the environment (the real session needs it to start and call a tool)
#   - this repo checkout (src/cli.js runs from the mounted checkout)
#   - a brain endpoint is OPTIONAL: env SYSTEMONE_URL/JEV_BASE_URL (or SYSTEMONE_KEY/JEV_API_KEY_LOCAL,
#     SYSTEMONE_MODEL/JEV_MODEL) first, else ~/.unjangled-guardrails/config.json `localBaseUrl`/
#     `localApiKey`. Without one the gate degrades to its offline floor: the registration proof
#     still runs, and the evidence records the governing layer honestly.
#
# SECRETS DISCIPLINE: the API key, brain URL, and brain key pass through `docker run -e` from the
# host environment (host-loopback URLs rewritten to host.docker.internal via host-gateway) and are
# never echoed, logged, or written to any file by this script.
#
# THE OFFLINE TEST SUITE STAYS DOCKER-FREE: `node --test test/` never needs this script. The
# recipe is the re-run path; the evidence row is the run's proof.
#
# IDEMPOTENCE: a stale container of the same name is removed first; the container is torn down on
# every exit path (success, named-step failure, interrupt).

set -euo pipefail

NAME="ug-claude-registration-proof"
IMAGE="node:22-bookworm-slim"
SESSION_TIMEOUT=300   # the real session: a tool-using print-mode run can take 30-120s

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() { echo "FAIL: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

# ── 1/7 prerequisites ────────────────────────────────────────────────────────────────────────
step "1/7 prerequisites (nothing provisioned until these pass)"
command -v docker >/dev/null 2>&1 \
  || die "prereq: docker is not on PATH — this proof runs the real harness in a clean container"
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 \
  || die "prereq: the docker daemon is not reachable — start it and re-run"
[ -n "${ANTHROPIC_API_KEY:-}" ] \
  || die "prereq: ANTHROPIC_API_KEY is not set — the real claude session needs it (passed in via -e, never printed)"
[ -f "$REPO/src/cli.js" ] \
  || die "prereq: this recipe must live in the unjangled-guardrails checkout (no src/cli.js under $REPO)"
command -v node >/dev/null 2>&1 \
  || die "prereq: node is not on PATH (the host uses it to read the operator config and assert the evidence rows)"

# Brain endpoint: env first (same precedence the gate itself reads), else the operator config file.
# Values land in shell variables and container env only — never echoed.
BRAIN_URL="" BRAIN_KEY="" BRAIN_MODEL=""
if [ -n "${SYSTEMONE_URL:-}" ]; then
  BRAIN_URL="$SYSTEMONE_URL"; BRAIN_KEY="${SYSTEMONE_KEY:-}"; BRAIN_MODEL="${SYSTEMONE_MODEL:-}"
elif [ -n "${JEV_BASE_URL:-}" ]; then
  BRAIN_URL="$JEV_BASE_URL"; BRAIN_KEY="${JEV_API_KEY_LOCAL:-}"; BRAIN_MODEL="${JEV_MODEL:-}"
elif [ -f "${HOME}/.unjangled-guardrails/config.json" ]; then
  BRAIN_URL="$(node -e 'try{const c=JSON.parse(require("fs").readFileSync(process.env.HOME+"/.unjangled-guardrails/config.json","utf8"));process.stdout.write(String(c.localBaseUrl||""))}catch{}')"
  BRAIN_KEY="$(node -e 'try{const c=JSON.parse(require("fs").readFileSync(process.env.HOME+"/.unjangled-guardrails/config.json","utf8"));process.stdout.write(String(c.localApiKey||""))}catch{}')"
fi
if [ -n "$BRAIN_URL" ]; then
  # A host-side brain is reachable from the container through the host-gateway alias.
  BRAIN_URL="${BRAIN_URL//localhost/host.docker.internal}"
  BRAIN_URL="${BRAIN_URL//127.0.0.1/host.docker.internal}"
  echo "brain: endpoint resolved from the operator config (value withheld); probes will score live"
else
  echo "brain: none resolved (env or operator config) — the gate degrades to its offline floor;"
  echo "       the registration proof still runs and the evidence records the governing layer"
fi

# ── 2/7 container up ─────────────────────────────────────────────────────────────────────────
# The checkout mounts under the project's own name (/unjangled-guardrails): the registration's
# recognition — install's, live-verify's, and step 4's — matches the checkout path carrying the
# project name, exactly as a stranger's clone directory does.
step "2/7 container up ($IMAGE, checkout mounted, no operator HOME)"
docker rm -f "$NAME" >/dev/null 2>&1 || true
RUN_ARGS=(run -d --name "$NAME" --add-host=host.docker.internal:host-gateway -v "$REPO":/unjangled-guardrails -e ANTHROPIC_API_KEY)
# Secret-class values are EXPORTED for the docker client and passed as valueless `-e NAME` forms,
# so they travel in the environment — never in this process's argv, which host ps//proc can read
# for the docker run's lifetime. The loopback→host.docker.internal rewrite lands on the exported
# value. Unset values are omitted (no -e, no export).
if [ -n "${ANTHROPIC_BASE_URL:-}" ]; then
  export ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL//localhost/host.docker.internal}"
  export ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL//127.0.0.1/host.docker.internal}"
  RUN_ARGS+=(-e ANTHROPIC_BASE_URL)
fi
if [ -n "$BRAIN_URL" ]; then
  export SYSTEMONE_URL="$BRAIN_URL"
  RUN_ARGS+=(-e SYSTEMONE_URL)
  if [ -n "$BRAIN_KEY" ]; then export SYSTEMONE_KEY="$BRAIN_KEY"; RUN_ARGS+=(-e SYSTEMONE_KEY); fi
  if [ -n "$BRAIN_MODEL" ]; then export SYSTEMONE_MODEL="$BRAIN_MODEL"; RUN_ARGS+=(-e SYSTEMONE_MODEL); fi
fi
docker "${RUN_ARGS[@]}" "$IMAGE" sleep infinity >/dev/null \
  || die "step 2: docker run failed (image pull or daemon error)"
docker exec "$NAME" mkdir -p /root/work /tmp/guard-home /tmp/guard-sessions

# ── 3/7 Claude Code from npm ─────────────────────────────────────────────────────────────────
step "3/7 install Claude Code from npm (in-container; needs network egress)"
docker exec "$NAME" npm i -g --no-fund --no-audit --loglevel=error @anthropic-ai/claude-code \
  || die "step 3: npm install of @anthropic-ai/claude-code failed in-container"
docker exec "$NAME" claude --version >/dev/null \
  || die "step 3: claude is not on PATH after the npm install"

# ── 4/7 the registration ─────────────────────────────────────────────────────────────────────
step "4/7 install claude (the mounted checkout registers the gate in the container's settings)"
docker exec "$NAME" node /unjangled-guardrails/src/cli.js install claude \
  || die "step 4: install claude failed in-container"
docker exec "$NAME" node -e '
  const s = JSON.parse(require("fs").readFileSync("/root/.claude/settings.json", "utf8"));
  const ours = /unjangled-guardrails|jev-guard/;
  let registered = false;
  for (const group of Object.values(s.hooks || {}))
    for (const e of group ?? [])
      for (const h of e?.hooks ?? []) if (ours.test(h.command ?? "")) registered = true;
  if (!registered) { console.error("no unjangled-guardrails hook entry in /root/.claude/settings.json"); process.exit(1); }
  console.log("registration written: " + Object.keys(s.hooks).sort().join(", "));' \
  || die "step 4: the registration did not land in the container's settings.json"

# ── 5/7 the real session ─────────────────────────────────────────────────────────────────────
step "5/7 real claude session (print mode; the harness loads the registration and fires the hook)"
docker exec -w /root/work -e DISABLE_AUTOUPDATER=1 "$NAME" bash -c '
  export GUARD_HOME=/tmp/guard-home GUARD_SESSIONS=/tmp/guard-sessions
  timeout '"$SESSION_TIMEOUT"' claude -p "Use the Bash tool to run exactly this command: echo guard-alive. Then reply with only that command output." --allowedTools "Bash(echo:*)" --output-format text
' || die "step 5: the real claude session failed, was blocked, or timed out (${SESSION_TIMEOUT}s)"

# ── 6/7 hook side effects inside the real session ────────────────────────────────────────────
step "6/7 assert the registered hook actually fired inside the real session"
docker exec "$NAME" node -e '
  const fs = require("fs");
  const d = "/tmp/guard-sessions";
  const files = fs.existsSync(d) ? fs.readdirSync(d).filter((f) => f.endsWith(".json")) : [];
  const withCalls = files.filter((f) => {
    try { return (JSON.parse(fs.readFileSync(d + "/" + f, "utf8")).calls ?? []).length > 0; } catch { return false; }
  });
  console.log("guard session records: " + files.length + ", with judged tool calls: " + withCalls.length);
  if (!files.length || !withCalls.length) {
    console.error("no judged tool call in the guard session store — the real session did not fire the registered hook");
    process.exit(1);
  }' \
  || die "step 6: hook side-effect check failed — the harness never fired the registered hook"

# ── 7/7 verify claude through the registered command + evidence assertions ───────────────────
# The evidence file is pre-created as the invoking user BEFORE the in-container append (the
# container writes as root; touch cannot fix ownership of an existing file), and is named in UTC:
# the driver dates files and rows with toISOString, so a local-date name would race the
# container's file near midnight in a non-UTC timezone.
EV="$REPO/evidence/live-verify-claude-$(date -u +%F).jsonl"
touch "$EV"
[ -f "$EV" ] || die "step 7: no evidence file at ${EV#"$REPO"/}"
step "7/7 verify claude (both probes through the REGISTERED command) and assert the evidence rows"
docker exec "$NAME" node /unjangled-guardrails/src/cli.js verify claude \
  || die "step 7: verify claude failed in-container (a probe did not pass through the registered command)"
node -e '
  const fs = require("fs");
  const rows = fs.readFileSync(process.argv[1], "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const today = new Date().toISOString().slice(0, 10);
  const seen = {};
  for (const r of rows) {
    if (r.harness !== "claude" || r.date !== today || !/registered in/.test(r.method ?? "")) continue;
    seen[r.probe.id] = r;
    console.log("evidence: probe " + r.probe.id + " (" + r.probe.role + ")  verdict=" + r.observedVerdict
      + "  pass=" + r.pass + "  registered=" + r.registered + "  hookConfig=" + r.hookConfig);
    console.log("  method: " + r.method);
  }
  const ok = [seen.s3, seen.d1].every((r) => r && r.registered === true && r.hookConfig && r.pass && r.containerized === true);
  if (!ok) {
    console.error("today'"'"'s rows do not carry registered:true + a non-null hookConfig + both probes passing");
    process.exit(1);
  }
  console.log("PROOF COMPLETE: the harness-loaded registration drove both probes; evidence landed in the mounted repo.");
' "$EV" || die "step 7: evidence assertions failed"

echo
echo "container $NAME removed; evidence: evidence/live-verify-claude-$(date -u +%F).jsonl"
