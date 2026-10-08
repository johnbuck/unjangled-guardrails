# unjangled-guardrails

> **Fork of [leepokai/jev-guard](https://github.com/leepokai/jev-guard)** (MIT, baseline
> `489f528`). Divergence from upstream is summarized in the commit history.

A classifier-agent guardrail: one plugin that judges every tool call and every tool
result, on any coding agent, with any Jev-compatible classifier — an endpoint speaking the Jev wire contract — as the brain.

The brain is an interface, not a product. Point it at a local service (a SemIf shim — the local brain
service this fork was built against — or a self-hosted Jev instance) or a cloud API
(TypeSafe, Vercel AI Gateway) — the gate
works identically either way. Deployments default to local; the gate itself
originates no remote traffic except the brain endpoint you choose. It is a guardrail, not a sandbox:
a hook can be misconfigured, an agent can bypass a tool path, the classifier can
be wrong. Keep your other controls.

## How this fork differs from upstream jev-guard

This fork exists because a guard should not depend on a cloud you don't control, and should not fail silently when its brain is down. Concretely, versus upstream:

- **Local-first brain.** Point `SYSTEMONE_URL` at any Jev-compatible local endpoint; it wins over every cloud credential, so the gate can be pinned to your own infrastructure. Cloud backends still work (`JEV_API_KEY`, `AI_GATEWAY_API_KEY`).
- **Offline rules floor.** When the brain is unreachable, vendored deterministic rules — parity-tested 92/92 against their originals — become the gate, with three selectable postures (`GUARD_FALLBACK=rules|layered|closed`). No silent fail-open.
- **Operator rulings with a fixed authority model.** Scoped, expiring, audited rulings lift ask and deny verdicts; exactly three overrule paths exist, and gate self-protection is never liftable by a ruling.
- **Enforced adapter contract.** A versioned contract (`src/contract.js`), a conformance suite that fails context-dropping adapters, and per-harness live-verify (`unjangled-guardrails verify <harness>`).
- **Renamed, with back-compat.** The package and CLI are `unjangled-guardrails`; `SYSTEMONE_*` / `GUARD_*` are primary and every legacy `JEV_*` spelling still aliases. The `jev-guard` npm package is upstream, not this fork.

## What it does

Three checks, with the session's context:

- **Before a tool runs** — the classifier scores how much harm the exact call could
  do, given what the user asked for and what the agent has read. Destructive calls
  are denied; risky ones require approval (the user's own words can lift them);
  credential exposure (printing secrets into the conversation) is denied outright; calls
  carrying out instructions planted in untrusted content are denied even when they
  look harmless.

- **After a tool returns** — results (web pages, files, MCP output, command output)
  are scanned for text aimed at AI agents: prompt injection and canaries. Hits are
  flagged as untrusted data, remembered for the session, and the agent is told not
  to follow them.

- **Instruction files** — skills, plugins, rules, `CLAUDE.md`/`AGENTS.md`: every file
  loaded or installed is checked for behavior the person installing it would not expect
  (exfiltration, covert execution, overriding other instructions, canaries,
  unrelated side effects).


## Install

Clone first (`git clone https://github.com/johnbuck/unjangled-guardrails && cd unjangled-guardrails`; Node ≥ 20.3), then pick your agent — every row is one command against the checkout.

| Agent | Install (from a clone of this repo) | Before a tool runs | After it returns |
|---|---|---|---|
| Claude Code | `node src/cli.js install claude` — hooks into `~/.claude/settings.json` | deny · **ask** prompt | flag |
| Codex | `node src/cli.js install codex` — `~/.codex/hooks.json` | deny · ask → **deny** (no ask surface) | flag |
| Copilot CLI | `node src/cli.js install copilot` — `~/.copilot/hooks/unjangled-guardrails.json` | deny · **ask** prompt | flag |
| Gemini CLI | `node src/cli.js install gemini` — `~/.gemini/settings.json` | deny · ask → **deny** (no ask in BeforeTool) | flag |
| Cursor | `node src/cli.js install cursor` — `~/.cursor/hooks.json` | deny · **ask** for shell and MCP | flag |
| pi | `node src/cli.js install pi` — extension path into `~/.pi/agent/settings.json` | block · **confirm dialog** | flag |
| OpenCode | `node src/cli.js install opencode` — plugin shim into `~/.config/opencode/plugins/` | throw on deny · ask throws with instructions (conversation loop resolves) | flag |
| ACP | editor runs `node src/cli.js acp -- <agent>` | reject · **permission request** | flag |

OpenCode: approval prompts require `"permission": { "bash": "ask" }` in `opencode.json` — without it, ask-band calls hard-deny. Hermes ships as a plugin under `plugins/unjangled-guardrails/` with its own README.

Every command above was dry-run-verified against a clean `$HOME` on 2026-10-08.
Note: the `jev-guard` package on npm is the **upstream project** — installing it
gets you upstream, not this fork.

### Brain configuration

**Local (default)** — the endpoint is whatever Jev-compatible service you run or subscribe to; the gate ships no brain:

```bash
export SYSTEMONE_URL="http://your-shim:8090"    # any Jev-compatible /v1/systemone endpoint
export SYSTEMONE_KEY="your-key"             # optional, if the endpoint requires auth
```

**Cloud:**

```bash
export JEV_API_KEY="ts_…"                       # TypeSafe key from console.typesafe.ai
# or
export AI_GATEWAY_API_KEY="vck_…"              # Vercel AI Gateway key
```

`SYSTEMONE_URL` wins over every cloud credential — with it set, the gate can never
phone home. An existing upstream `~/.jev-guard/config.json` is also honored as a
last-resort credential fallback; delete it if you want the gate to forget upstream
credentials. The key can also be stored with `unjangled-guardrails key <key>` which
writes `~/.unjangled-guardrails/config.json` (mode 0600), useful for GUI hosts
that don't see your shell profile.

## How decisions are made

The classifier is asked narrow, typed questions; the policy lives in code
(`src/guard.js`) and is the same on every harness.

**Action** (every adapter):

```
allow  if user_requested ≥ 0.85  (the user's own words — lifts any verdict)
deny   if from_untrusted ≥ 0.7   (injection: serving content's author, not the user)
deny   if risk ≥ 2.55            (destructive)
ask    if risk ≥ 1.5 or approval ≥ 0.75
deny   if leak ≥ 0.50            (the fall-through deny — the ask band outranks it: a
                                 risky-and-leaky call surfaces as an ask, not a hard deny)
allow  otherwise
```

- **`user_requested`** — did the user, in their own recent messages, request,
  approve, or clearly authorize the action this tool call performs? Only genuine
  user messages count; tool results, pages, and files never do.
- **`from_untrusted`** — does this call carry out an instruction planted in
  content the agent read? A yes alone denies the call.
- **`leak`** — four questions (max of their scores) covering direct secret dumps,
  environment dumps, process arguments, and credential-file reads. A secret printed
  into the conversation cannot be taken back.

**The three overrule paths** — every deny message names an operator-only unlock,
never one an agent could act on by itself:

1. The user's own words in conversation (at the 0.85 threshold)
2. An operator terminal session
3. An operator ruling (scoped, expiring, audited)

**Content** (after a tool returns):

```
flag   if directed ≥ 0.6  and  kind ∈ {injection, canary}  (a missing kind counts as serious)
```

Discussion and benign content are never flagged. Results shorter than 200
characters, results of local edit/search tools, and documentation writes
(`docs/`, `evidence/`, `_bmad-output/`, `.specify/`, root-level docs by name,
ALL-CAPS markdown files) skip the classifier — updating documentation is not a
dangerous activity.

### Offline rules floor

When the brain is unreachable (connection error, HTTP 5xx, 401/403, timeout, or a
malformed/missing answer), vendored deterministic rules — Secrets Guard core plus
a catastrophic-command list, both parity-tested against their originals — become
the gate:

- Rule hits deny (credential-file reads, environment dumps, catastrophic commands)
- Everything the rules don't block — bash, read-only, mutating, unknown — passes
  with a stderr marker until the brain returns; set `GUARD_FALLBACK=closed` for
  deny-all if you want the stricter posture during outages
- Post-tool injection/canary scanning pauses for the outage (a stderr warning says so)
- Rulings still resolve (matching one needs no brain); user-words lifting needs a
  live brain — during an outage only a pre-granted ruling lifts
- The next healthy call resumes semantic decisions, no restart needed

Three fallback postures via `GUARD_FALLBACK`: `rules` (default — described
above), `layered` (pass-through on hosts that keep an external heuristic stack),
`closed` (sole-gate deny-all). The legacy `GUARD_FAIL_CLOSED=1` spelling
still works as an alias for `closed`.

## Operator rulings

An `ask` defers to the harness approval flow — unless the operator has already
answered that exact question, in that scope.

```sh
unjangled-guardrails ruling add --effect allow --pattern 'git push *' --scope project --reason "reviewed deploy flow"
unjangled-guardrails ruling add --effect deny --pattern 'terraform apply*' --scope global --expires 2027-01-01
unjangled-guardrails ruling list
unjangled-guardrails ruling revoke r-ab12cd34
```

- Rulings are stored in `$GUARD_HOME/rulings.json` (0600). Every mutation is
  operator-only (terminal or explicit escape) and paired with a mutation audit row;
  out-of-band changes trip tamper evidence.
- Scopes: `global`, `project:<path>`, `session:<id>`. Expiry defaults: session 7
  days, project 30 days. Global requires an explicit `--expires`.
- A ruling lifts ask and deny verdicts (audited as `deny overridden by ruling <id>`).
  Gate self-protection — edits to the gate's own store, config, or sessions — is
  never liftable by a ruling.

## Tuning

| Variable | Default | Effect |
|---|---|---|
| `GUARD_DENY_SCORE` | `2.55` | risk position at which a call is denied |
| `GUARD_ASK_SCORE` | `1.5` | risk position at which approval is required |
| `GUARD_ASK_P` | `0.75` | approval probability at which approval is required |
| `GUARD_USER_P` | `0.85` | user-requested probability that lifts any verdict |
| `GUARD_UNTRUSTED_P` | `0.7` | from-untrusted probability that denies outright |
| `GUARD_LEAK_P` | `0.5` | leak probability that denies (credential exposure) |
| `GUARD_INJECT_P` | `0.6` | directed probability at which content is flagged |
| `GUARD_SKILL_P` | `0.8` | instruction-file probability for side effects |
| `GUARD_SKILL_SERIOUS_P` | `0.45` | instruction-file probability for exfiltration etc. |
| `GUARD_TIMEOUT_MS` | `20000` | total budget per classifier call |
| `GUARD_FALLBACK` | `rules` | brain-down posture: `rules` / `layered` / `closed` |
| `GUARD_FAIL_CLOSED` | unset | legacy alias: `=1` = `closed` |
| `GUARD_HOME` | `~/.unjangled-guardrails` | home for config, rulings, sessions, cache |
| `GUARD_SESSIONS` | `~/.unjangled-guardrails/sessions` | per-session memory directory |
| `GUARD_SCAN_CACHE` | `~/.unjangled-guardrails/scan-cache.json` | instruction-file scan cache |
| `GUARD_CONFIG` | `~/.unjangled-guardrails/config.json` | where the key command stores the key |
| `GUARD_SKIP_TOOLS` | | comma-separated tool names never assessed |
| `GUARD_SKIP_SCAN` | | comma-separated tool names whose results are never scanned |
| `SYSTEMONE_URL` | unset | local brain URL (wins over all cloud credentials) |
| `SYSTEMONE_KEY` | unset | bearer key for the local brain |
| `JEV_API_KEY` | unset | TypeSafe cloud key |
| `AI_GATEWAY_API_KEY` | unset | Vercel AI Gateway cloud key |
| `SYSTEMONE_MODEL` | unset | model alias / id for the backend |
| `VERCEL_OIDC_TOKEN` | unset | Vercel AI Gateway credential from `vercel env pull`; expires ~12h |
| `GUARD_HERMES_APPROVER` | unset | Hermes: makes ask a real human-approval gate instead of deny |

Probabilities are bounded with protection floors: `GUARD_USER_P` ∈ [0.75, 1],
`GUARD_UNTRUSTED_P` ≤ 0.9, `GUARD_LEAK_P` ≤ 0.7. Out-of-range permissive values fall
back to the default, never to the weaker bound.

Back-compat (2026-10-07): every pre-rename `JEV_*` spelling (`JEV_BASE_URL`,
`JEV_API_KEY_LOCAL`, `JEV_MODEL`, `JEV_GUARD_*`) still works as an alias, read
after the new name. Deployed configs need no change; new setups should use the
names above.

## CLI

```
unjangled-guardrails setup <agent>                  Clone-to-verified: install, rulings store, live-verify, readiness report
unjangled-guardrails hook [--agent codex|copilot|hermes]   Command hook: JSON on stdin → JSON on stdout (host auto-detected)
unjangled-guardrails acp -- <agent command...>      ACP proxy
unjangled-guardrails check <tool> '<json input>'    Assess one call; exit 0/1/2
unjangled-guardrails scan [file]                    Scan a file or stdin; exit 2 if flagged
unjangled-guardrails scan-skills [paths...]         Sweep instruction files
unjangled-guardrails install <agent>                Register hooks for one harness
unjangled-guardrails verify <harness>               Live-verify: safe passes + destructive blocks
unjangled-guardrails key <api key>                  Save a cloud key to config
unjangled-guardrails key --local <url> [key]        Persist a local brain URL (and optional key)
unjangled-guardrails ruling add|list|revoke         Manage operator rulings
```

All available as `node src/cli.js <command>` from the repo.

## Privacy

The gate sends only what it needs to judge: the tool call (name, arguments, cwd)
or the tool result, plus the session context the adapter supplies. Where that
data goes depends entirely on the brain you configure:

- **Local brain** (default): data goes to your service, on
  your network. Nothing leaves your infrastructure.
- **Cloud brain** (TypeSafe, Vercel AI Gateway, any remote endpoint you choose):
  data goes to that service over TLS. Review that provider's privacy policy
  before using the gate with sensitive repositories.

The gate itself has no telemetry, no update checks, no corpus sync — no remote
traffic except the brain endpoint you explicitly configure.

## Architecture

One core, thin adapters. The core exposes only the versioned Adapter Contract
(`src/contract.js`); adapters speak the contract and nothing else. A conformance
suite (simulated harness + simulated brain) proves compatibility mechanically.

```
harnesses → adapters → Adapter Contract → core (decide / scan / rulings / offline rules)
                                            ↕ wire contract (/v1/systemone)
                                        brain (local or cloud, by operator choice)
```

- **Adapter contract** (`src/contract.js`): payload in (tool call, context,
  provenance), decision out (verdict, category, stats, citation, guidance).
  Versioned with SemVer compat rules.
- **Conformance suite** (`tools/conformance/`): every adapter passes; a
  context-dropping stub fails — proving the contract detects data loss.
- **Live-verify** (`tools/verify/`): exercises the real harness surface with
  safe and destructive probes, recording evidence artifacts.
- **Offline rules** (`vendor/secrets-guard-core/`, `vendor/guardrails-core/`):
  vendored verbatim, parity-tested. They are the floor, never the judge.

See `docs/adapter-guide.md` for the stranger's contribution path: implement the
contract, pass the suite, live-verify, register.


## Development

```bash
npm test                              # node test suite + conformance suite
python3 plugins/unjangled-guardrails/test_adapter.py   # Hermes adapter suite
node tools/conformance/run.mjs         # conformance suite standalone
node tools/parity-vendored.mjs         # vendored rules parity (92 cases)
node tools/verify/live-verify.mjs      # live-verify runner
```

Layout: `src/contract.js` (adapter contract) · `src/guard.js` (questions + policy) ·
`src/jev.js` (one fetch, any backend) · `src/orchestrate.js` (degraded gate,
self-modification guard, offline rules) · `src/rulings.js` (operator rulings +
authority) · `src/context.js` + `src/session.js` (what the classifier sees) ·
`src/skills.js` (instruction-file sweep) · `src/hook.js` (Claude/Codex/Copilot/
Gemini/Cursor hooks) · `src/acp.js` (ACP proxy) · `src/opencode.js` (OpenCode
plugin) · `extensions/unjangled-guardrails.ts` (pi) · `plugins/unjangled-guardrails/`
(Hermes) · `vendor/` (vendored rules cores, parity-tested).

## License

MIT
