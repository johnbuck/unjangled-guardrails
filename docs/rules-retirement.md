# Rules retirement register (Story 12; rewritten for the 2026-10-20 consolidation)

Evidence-driven retirement of the vendored Secrets Guard rule families. Since the
consolidation (plan-consolidation-two-layers) there is no active-floor escalation and no
divergence carve-out: **all nine SG families run pre-brain, in every posture, as the
Always-Deny Secrets family** (src/always-deny.js — the vendored cores are the single sources
of truth). Retirement now means one thing: removing the family's rule from the Always-Deny
guard, an operator-gated act backed by corpus + probe evidence that the brain's questions
close the class. Nothing is retired by fiat.

Statuses:

- ~~**offline-ask (escalator)** — the family asks pre-brain, without a brain call, in every
  posture~~ **RETIRED 2026-10-25 (operator doctrine): nothing deterministic reaches the ask
  band.** The 2026-10-25 ruling supersedes the FR-C3 frame this status was created under:
  the ask band is brain-only — dangerous denies naming the piece, everything else goes to
  the brain, and low-confidence brain allows are tuning work on the measured battery loop,
  never gate structure.
- **always-deny** — the family denies pre-brain in every posture (all families below, per the
  2026-10-13 operator ruling: "all of those rules were defined because they leak data into
  context" — categorical leak-blockers belong in the deny layer, always-on — carried forward
  from the active-floor era; the consolidation made it structural).
- **retired-semantic** — the brain's questions close the class and the operator has approved
  removing the rule from Always-Deny. No family holds this status today; a removal ships with
  its corpus + probe rows here, the way the Story 8/9 playbook recorded them.
- **superseded-by-doctrine** — the family's design contradicted a ratified operator decision
  and was removed with the citation recorded on its row (the indirection-escalator, 2026-10-25).
  The surviving legs of a superseded family keep their own statuses on the rows that carry them.
- **carve-out (operator-approved)** — a behavioral difference recorded so a future parity
  comparison does not misread it (the old DIVERGENCE_FAMILIES mechanism is gone; the entries
  below are documentation only).

Parity proof: `tools/parity-vendored.mjs` → `evidence/parity-vendored-2026-10-04.jsonl`
(92/92 corpus rows verdict-identical to the origin engine at
`~/Projects/dotfiles/secrets-guard/core/`, vendored files sha256-identical — see
`vendor/secrets-guard-core/README.md`), re-run post-consolidation
(`evidence/battery-sg-parity-2026-10-20.jsonl`: 78 rows, 0 mismatches against the gate).

## Families

| Family | Corpus rows (cases.mjs) | Closure evidence on record | Status |
|---|---|---|---|
| infisical | 15 bash rows (`infisical get/list/export/set/delete/--plain/--value` + 5 safe-form allows) | Story 8 corpora; caught in every live run since (battery-sg-parity 2026-10-04 and 2026-10-20) | always-deny |
| curl-secret-api | 7 bash rows (clientSecret/secretValue `-d`, secrets/raw, universal-auth + 3 safe-form allows) | Story 8 corpora; caught in all three live runs | always-deny |
| shell-tracing | 5 bash rows (`bash -x`/`set -x`/`sh -x` + `bash -x build.sh` allow) | Story 8 caught the auth-flow traces; `bash -x build.sh` allowed by BOTH engines (SG allowlists it; brain scores it low) — the contextual residual is the operator's ruling instrument, not a rule | always-deny |
| credential-file | 16 bash rows (cat-family/grep/sed/dd on env & key files + 8 safe-form allows) + 9 read rows | Story 9 `reads_credential_file` (probe trail tools/probe-closure{,2,3}.mjs); `head prod.env`, `bat secrets.yaml`, `grep PASS prod.env` all caught live | always-deny |
| agent-config | 4 bash rows + 2 read rows (Hermes `data/config.ya?ml`) | Story 9 class D; caught live 2026-10-04 | always-deny |
| env-dump | 8 bash rows (bare `env`/`printenv` + docker exec env + printenv carve-outs) | Story 8 `leaks_secrets` v3 with the HOME/PATH/USER carve-out; `printenv HOME` correctly allows | always-deny |
| docker-env | 2 bash rows (`docker exec/run` + env/printenv) | Story 8 corpora | always-deny |
| docker-inspect-format | 4 bash rows (bare inspect, `-f` status-only, `-f '{{.Config.Env}}'`, state+name) | the vendored engine allows non-Env format selects since its 2026-09-17 change; status-only selects pass both engines by design | always-deny |
| process-argv | 12 bash rows (`pgrep -a`/`--list-full`, `ps aux/-ef/-o args`, `/proc/*/environ|cmdline` + 4 safe-form allows) | Story 9 `dumps_process_argv` (class A); caught live | always-deny |
| credential-source (command floor: operand, remote-fetch, secret-print, remote-extraction, credential-env sourcing, guard-config display/sink; argument-text leg quote-stripped, vendored call site per-segment — ticket 15, 2026-11-09) | walkthrough + fleet-incident shapes (2026-10-12/13, 2026-10-16) + the GitHub-issue-15 compound/quoted-payload corpus (ticket 15, 2026-11-09: presence-safe grep in compounds, sed/head cross-segment conjunctions, quoted description text and quoted grep patterns as must-pass; true reads in compounds and unquoted argv mentions as must-deny) | operator doctrine 2026-10-12 ("100% blocked"); sanctioned shapes exempt (stdin rotation, silent in-place repair, presence/count checks); PER-SEGMENT RE-DECISION (ticket 15, 2026-11-09 — the third documented parity re-decision, recorded at SEGMENT_SPLIT in src/always-deny.js): the vendored checkBash runs per quote-aware top-level pipeline segment (splitPipelines; the vendor file untouched — whole-string scanning is its own documented limitation) and the argument-text leg strips quoted spans (quoted payloads are the brain's); closure evidence: evidence/battery-secrets-2026-11-10.jsonl (zero SAFE_FALSE_DENIES on the new c-rows; the y4/y5 false-denies and the brain-dependent x-rows' degraded allows are the recorded pre-existing conditions — y4/y5 since the 2026-10-25 battery, the x-rows brain-side by design, this run taken with the brain unreachable); pinned in test/write-floor.test.js, test/credential-source-compound.test.js, test/deny-policy.test.js, test/orchestrate.test.js | always-deny |
| indirection-escalator | pinned in test/indirection.test.js (context-body floor rows: substitution-wrapped credential reads deny; quote-aware extractor cases) | FR-C3 registration 2026-10-24; **SUPERSEDED-BY-DOCTRINE 2026-10-25** — the operator ruled nothing deterministic reaches the ask band ("inscrutable interpreter strings must never ask" — ask-band posture epic, 2026-10-11 decision, reinforced 2026-10-25): the ask path retired, the surviving leg is the deny-layer context-body floor (executing command-context bodies run under the full offline floor — secrets, self-mod, catastrophic; live-measured asking on benign substitutions, `$(mktemp)` and read-only pipelines, was the regression that surfaced it). The measured indirection brain-holes (variant battery confidence releases) become recorded tuning work on the brain, never gate structure. | superseded-by-doctrine |

Recorded v1 boundaries of the indirection-escalator (executing shapes NOT yet covered — each is a follow-up candidate, none hidden):

- dot-sourcing and `source` (file-content execution, same trust class as `| sh` — natural next leg)
- direct script execution (`bash script.sh` — currently the brain's judgment alone)
- process substitution `<( )`
- non-shell interpreters (`python -c`, `node -e`) — spec scope is shell
- shell aliases (`alias e=sh; e -c x` — resolution requires shell state)
- positional and special params in command position (`$1`, `$?`, `$@`) — named variables only at v1
- `\$`-escaped literals over-match in the context-body extractor (the escaped dollar is text, but pre-fix recordings and the surviving deny floor treat the body as live — accepted over-broad direction; the extractor now skips unquoted escapes, so new extractions are exact)
- quoted parens inside a substitution truncate the extracted body (`$(echo "a) b")`) — span() counts parens without quote state; harmless direction for the deny floor (over-extraction), recorded for the next extractor touch

## What the consolidation changed (2026-10-20)

- The `ACTIVE_FLOOR` escalation and `DIVERGENCE_FAMILIES` veto are gone with the skip stack:
  the rules moved from "escalate the brain's non-deny verdict" to "deny pre-brain, absolute".
  The docker-inspect-format divergence no longer has a mechanism — the vendored engine itself
  allows non-Env format selects, so status-only inspects still pass.
- The rules are the degradation floor by construction: brain-down needs no special mode,
  because layer 1 already gated. The brain-down posture question is only what an
  **unmatched** call does (fail-open default; `policy set --degradation fail-closed` or
  `GUARD_FALLBACK=closed` to harden).
- Retirement procedure, going forward: prove closure on the corpus + probes, record the rows
  in the table above with a date, then remove the family's rule from the Always-Deny guard in
  src/always-deny.js (operator-gated — the vendored sources themselves stay untouched, so a
  family removal is a decision about which imported checks the gate calls).

## Carve-outs recorded (operator-approved, documentation only)

1. **docker-inspect-format, status-only selects** — `docker inspect -f '{{.State.Status}}'`
   (and state+name combos). SG's deny corpus treats these as deny-class; both engines allow
   non-Env format selects today. The register keeps the historical corpus rows so a future
   parity comparison against the deny-class corpus does not misread them as misses. Rows:
   "docker inspect -f without env", "docker inspect state+name (allow)".
2. **bash -x build.sh** — allowed by both engines; listed because it appears in the Story 9
   close-out's residual three. The operator's chosen instrument for the contextual case is a
   ruling (now a policy command entry), not a rule.
