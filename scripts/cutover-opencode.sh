#!/bin/sh
# Story 12 (T12.6) — PILOT CUTOVER: disable the EXTERNAL Secrets Guard hook on OpenCode.
#
#  ██████  OPERATOR-ONLY  ██████  This script is PREPARED, NOT EXECUTED.
#  The operator runs it when ready to cut OpenCode over to the single
#  unjangled-guardrails plugin. Nothing in the build removes or disables any
#  external Secrets Guard or guardrail install by itself.
#
# Preconditions (all verified 2026-10-04):
#   - parity proof green: evidence/parity-vendored-2026-10-04.jsonl (92/92
#     verdict-identical; vendored core sha256-identical to ~/Projects/dotfiles/secrets-guard/core)
#   - retirement register: docs/rules-retirement.md (no active-floor families)
#   - unjangled-guardrails installed for opencode (the plugin shim at
#     ~/.config/opencode/plugins/unjangled-guardrails.js)
#   - layered posture on this host (JEV_GUARD_FAIL_CLOSED removed from ~/.profile,
#     T11.5) so a brain outage degrades to pass-through while the remaining
#     harness guardrails still gate
#
# What this does: moves the external SG plugin aside (it is a sibling plugin in
# ~/.config/opencode/plugins/). No config edit needed — OpenCode loads every .mjs
# in that directory, so renaming is the whole uninstall.
#
# ROLLBACK (one line, restores the external hook exactly as it was):
#   mv ~/.config/opencode/plugins/secrets-guard-rules.mjs.disabled ~/.config/opencode/plugins/secrets-guard-rules.mjs
#
# Verify after cutover:
#   node src/cli.js check Bash '{"command":"cat ~/.env"}'        # expect ASK/DENY from the brain
#   ls ~/.config/opencode/plugins/                               # secrets-guard-rules.mjs must be gone (renamed .disabled)

set -eu
SG_PLUGIN="${HOME}/.config/opencode/plugins/secrets-guard-rules.mjs"
DISABLED="${SG_PLUGIN}.disabled"

if [ ! -f "$SG_PLUGIN" ]; then
  if [ -f "$DISABLED" ]; then
    echo "already cut over: $DISABLED exists (rollback line is in this script's header)"
    exit 0
  fi
  echo "no external SG plugin at $SG_PLUGIN — nothing to disable" >&2
  exit 1
fi

mv "$SG_PLUGIN" "$DISABLED"
echo "external Secrets Guard disabled for OpenCode: moved to $DISABLED"
echo "rollback: mv $DISABLED $SG_PLUGIN"
