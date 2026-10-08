# Rules retirement register (Story 12)

Evidence-driven retirement of the vendored Secrets Guard rule families as the semantic
brain proves closure. This is the contract behind `ACTIVE_FLOOR` in `src/orchestrate.js`:
a family may escalate the brain's verdict only while it is **active-floor** here, and only
while evidence shows the brain missing a class the rules catch. Nothing is retired by fiat —
each row cites the corpus and the probe/battery evidence that proved the brain covers it.

Statuses:

- **active-floor** — rules escalate the brain verdict (family must appear in `ACTIVE_FLOOR`).
- **retired-semantic** — the brain's questions close the class; rules no longer run in
  front of the brain. The rules engine remains the full gate while degraded — by default
  (rules mode, operator ruling 2026-10-04 final) and on sole-gate hosts
  (`GUARD_FALLBACK=closed`).
- **intended-divergence** — operator-approved behavioral difference; the floor must never
  escalate these (`DIVERGENCE_FAMILIES`).

Parity proof: `tools/parity-vendored.mjs` → `evidence/parity-vendored-2026-10-04.jsonl`
(92/92 corpus rows verdict-identical to the origin engine at
`~/Projects/dotfiles/secrets-guard/core/`, vendored files sha256-identical — see
`vendor/secrets-guard-core/README.md`). The spec's "88-case" figure was stale: the corpus
has 92 rows (78 bash + 14 read).

## Families

| Family | Corpus rows (cases.mjs) | Semantic closure evidence | Status |
|---|---|---|---|
| infisical | 15 bash rows (`infisical get/list/export/set/delete/--plain/--value` + 5 safe-form allows) | Story 8: caught since the first live re-run (battery-sg-parity, 21→37/48); still caught in evidence/battery-sg-parity-2026-10-04.jsonl | retired-semantic |
| curl-secret-api | 7 bash rows (clientSecret/secretValue `-d`, secrets/raw, universal-auth + 3 safe-form allows) | Story 8, same corpora; caught in all three live runs | retired-semantic |
| shell-tracing | 5 bash rows (`bash -x`/`set -x`/`sh -x` + `bash -x build.sh` allow) | Story 8 caught the auth-flow traces; `bash -x build.sh` allowed by BOTH engines (SG allowlists it; brain scores it low) — the residual risk is contextual, now handled by operator rulings (Story 10) not rules | retired-semantic |
| credential-file | 16 bash rows (cat-family/grep/sed/dd on env & key files + 8 safe-form allows) + 9 read rows | Story 9 `reads_credential_file` (probe trail tools/probe-closure{,2,3}.mjs); `head prod.env`, `bat secrets.yaml`, `grep PASS prod.env` all caught in the 2026-10-04 live run | retired-semantic |
| agent-config | 4 bash rows + 2 read rows (Hermes `data/config.ya?ml`) | Story 9 class D: `reads_credential_file` names agent/harness configs; caught live 2026-10-04 | retired-semantic |
| env-dump | 8 bash rows (bare `env`/`printenv` + docker exec env + printenv carve-outs) | Story 8 `leaks_secrets` v3 with the HOME/PATH/USER carve-out and counter-example (`printenv \| wc -c`); `printenv HOME` correctly allows | retired-semantic |
| docker-env | 2 bash rows (`docker exec/run` + env/printenv) | Story 8 corpora | retired-semantic |
| docker-inspect-format | 4 bash rows (bare inspect, `-f` status-only, `-f '{{.Config.Env}}'`, state+name) | brain catches the Env-selecting format (class C fix, Story 9); **status-only selects are allowed by design** — the historical over-broad rows the operator approved | intended-divergence |
| process-argv | 12 bash rows (`pgrep -a`/`--list-full`, `ps aux/-ef/-o args`, `/proc/*/environ|cmdline` + 4 safe-form allows) | Story 9 `dumps_process_argv` (class A); `ps aux`, `ps -ef`, `ps -o command` caught in the 2026-10-04 live run | retired-semantic |

## Active floor

**None.** After Story 9 the brain catches every rule family the corpus exercises (SG
deny-corpus 45/48; the three allows are the two status-only docker-inspect-format rows and
`bash -x build.sh`, both deliberate). `ACTIVE_FLOOR` in `src/orchestrate.js` is empty and is
kept as the mechanism for future regressions: add the family here with corpus + probe
evidence, mirror it in `ACTIVE_FLOOR`, and remove both when the brain proves closure again.

## Divergence register (operator-approved)

1. **docker-inspect-format, status-only selects** — `docker inspect -f '{{.State.Status}}'`
   (and state+name combos). Secrets Guard's deny corpus treats these as deny-class; jev-guard
   allows them by design (the output is one status string — the gate being better than the
   rule). The vendored engine itself has allowed non-Env format selects since its
   2026-09-17 change, so today both engines agree; the register records the historical
   corpus rows so a future parity comparison against the deny-class corpus does not
   misread them as misses. Rows: "docker inspect -f without env", "docker inspect state+name (allow)".
2. **bash -x build.sh** — allowed by both engines; listed because it appears in the Story 9
   close-out's residual three. The operator's chosen instrument for the contextual case is a
   ruling (Story 10), not a rule.

## Degraded mode inside the plugin (brain down)

- rules (default, operator ruling 2026-10-04 final): the vendored rules engine IS the gate
  (identical verdicts to the deployed external SG, per the parity proof above); bash and
  read-only calls that pass pass with the stderr marker; mutating/unknown tools deny by
  default (TR-6).
- layered (explicit opt-in, `GUARD_FALLBACK=layered`): pass-through with the stderr
  marker; the external heuristic stack — or nothing, on hosts without one — gates.
- sole-gate (`GUARD_FALLBACK=closed`): rules gate for their classes, and
  everything else denied by sole-gate fail-closed.

## Paseo guardrail layer (T12.7)

Assessed at cutover, per the spec — not blocking. The Paseo guardrails run on the operator's
session harness, not inside the coding agents' hooks; integrating them into this plugin
would need the Paseo plugin surface and is tracked as a separate item for the operator's
cutover review.
