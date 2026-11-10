#!/usr/bin/env bash
# scripts/restore-brain-key.sh — restore the local brain key from Infisical through the gate's
# own chain (`key --infisical`): the machine identity is read by the gate's code, the key travels
# in-process into the 0600 config, and the key value never appears in argv or output.
#
# Usage: scripts/restore-brain-key.sh <infisical project id>
#   (project id is an identifier, not a secret — the SECRET is SYSTEM_ONE_API_KEY in env prod,
#   fetched with the machine identity from ~/.config/infisical/*.env)
#
# Prerequisites: the Infisical CLI on PATH, the machine-identity env file, and a config with
# localBaseUrl already set (the brain URL is not stored in Infisical — run
# `node src/cli.js key --local <url>` once if needed).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${1:?usage: restore-brain-key.sh <infisical project id>}"
exec node "$REPO/src/cli.js" key --infisical --project "$PROJECT"
