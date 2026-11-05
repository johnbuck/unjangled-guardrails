# unjangled-guardrails — Hermes adapter

Auto-mode gate for Hermes, judged by the local SemIf brain. All policy lives in
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
SYSTEMONE_URL=http://your-brain:8090   # SemIf brain (any Jev-compatible /v1/systemone)
GUARD_FAIL_CLOSED=1                     # block when the brain is down
GUARD_MAX_STATE_CHARS=12000             # stay under the brain's 4096-token ceiling
# SYSTEMONE_KEY=...                     # only if the brain enables auth
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

Moved 2026-11-05 to `evidence/hermes-adapter-as-built-key-wiring-2026-11-05.md` —
the publishing process wants this file topology-free at source, not just
genericized at cut (this file's cut-time anchors failed once before, public cut
of 2026-10-30).

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
- degraded postures (`GUARD_FALLBACK`): `rules` is the default — the built-in offline rules
  gate and whatever they pass goes through with a stderr marker; `layered` is the explicit
  opt-in pass-through to a host heuristic stack; `closed` is deny-all for sole-gate hosts
  (legacy `GUARD_FAIL_CLOSED=1` maps there).

The Hermes-side failure semantics are unchanged: any subprocess failure still resolves
through this plugin's error path (node missing, timeout, non-JSON), and the degrade
decision itself is made inside the subprocess so the plugin never needs to know whether
the brain is up.
