# unjangled-guardrails — Hermes adapter

Auto-mode gate for Hermes, judged by the local SemIf shim. All policy lives in
the unjangled-guardrails fork; this plugin only translates Hermes hook events into the
fork's Claude-shaped hook protocol and back.

## Install (operator-gated)

1. Copy this directory to the Hermes profile plugins dir, e.g.
   `~/.hermes/plugins/unjangled-guardrails/` (or `<profile>/plugins/`).
2. Enable it: `hermes plugins list` should show it; standalone plugins load via
   `plugins.enabled` if your config gates user plugins.
3. Set environment (in the Hermes service env, not per-session):

```bash
GUARD_HOME=/path/to/unjangled-guardrails-fork      # required; contains src/cli.js
SYSTEMONE_URL=http://your-shim:8090         # SemIf shim (any Jev-compatible /v1/systemone)
GUARD_FAIL_CLOSED=1                     # block when the brain is down
GUARD_MAX_STATE_CHARS=12000             # stay under shim's 4096-token ceiling
# SYSTEMONE_KEY=...                     # only if the shim enables auth
```

## Behavior

- `pre_tool_call`: deny blocks the call (`{"action":"block"}`); ask escalates
  to Hermes's human-approval gate (`{"action":"approve","message": <reason>}`)
  when this Hermes has an approval flow configured (`approvals:` in its
  config.yaml, mode not off — or set GUARD_HERMES_APPROVER=1), so the call runs
  only after a person approves; without an approver the ask becomes a deny
  whose message tells the agent to raise it in conversation. allow returns
  None. Read-only tools skip the node spawn entirely, except the file-read
  names the gate's offline read-path rules judge (`read`, `read_file`,
  `read_many_files`) — those always reach the hook, and plain reads still
  skip the backend.
- `transform_tool_result`: flagged (injection/canary) results get the
  unjangled-guardrails warning prepended to what the model sees. Scan failure never
  blocks (advisory).
- `post_tool_call`: observer only.

Failure class (node missing, timeout, bad output) follows
`GUARD_FAIL_CLOSED`: block with reason, or warn and pass (default).

## Test

`python3 test_adapter.py` (stdlib only; spawns the bundled node stub via
GUARD_HOME fixture).

## As built

2026-09-30: ran a one-shot sync script (since shredded) to mirror
`SEMIF_API_KEY` from your SemIf deployment's `router.env`
into Infisical Homelab project `48c69815…`, env `prod`, path `/`. The key
was already present there (value length 50), so no write happened and the
copy on the shim host remains the source. No secret values were printed or stored
outside chmod-600 tempfiles, which were shredded.

2026-10-05: the service was renamed `system-one` and the Infisical secret
renamed `SEMIF_API_KEY` → `SYSTEM_ONE_API_KEY` (same value, both envs);
on the shim host the key now lives in `router.env`. See
`system-one/docs/migration-system-one-2026-10-05.md`.

## One plugin, whole stack (Story 12, 2026-10-04)

Back-compat (2026-10-07): the plugin reads the renamed env vars (`GUARD_HOME`,
`SYSTEMONE_URL`, `SYSTEMONE_KEY`, `SYSTEMONE_MODEL`, `GUARD_*`) with the
pre-rename `JEV_*` spellings as fallbacks, so a deployed config that sets only
the old names keeps working.

The CLI subprocess (`node <GUARD_HOME>/src/cli.js hook --agent hermes`) now carries the
full consolidated plugin — no companion installs needed:

- the semantic brain (guard.js questions + thresholds),
- operator rulings (`$GUARD_HOME/rulings.json`; a ruling-fired allow/deny arrives in the
  hook's decision message citing `by ruling <id>` / the ruling id),
- the orchestrator (brain primary; built-in offline rules as measured floor; the
  vendored rules ARE the gate while degraded on sole-gate hosts),
- layered degraded mode (default: pass-through with a stderr marker; `GUARD_FALLBACK=closed`
  or legacy `GUARD_FAIL_CLOSED=1`: deny).

The Hermes-side failure semantics are unchanged: any subprocess failure still resolves
through this plugin's error path (node missing, timeout, non-JSON), and the degrade
decision itself is made inside the subprocess so the plugin never needs to know whether
the brain is up.
