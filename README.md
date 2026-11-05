# unjangled-guardrails

> **Fork of [leepokai/jev-guard](https://github.com/leepokai/jev-guard)** (MIT, baseline
> `489f528`). The divergence record (`CHANGELOG-fork.md`) and the operator-rulings
> governance (`.specify/`) live in the development tree; public cuts carry neither.

A classifier-agent guardrail: one plugin that judges every tool call and every tool
result, on any coding agent, with any Jev-compatible classifier — an endpoint speaking
the Jev wire contract — as the brain.

The brain is an interface, not a product. Point it at a local service (a SemIf
deployment — the local brain service this fork was built against — or a self-hosted
Jev instance) or a cloud API (TypeSafe, Vercel AI Gateway) — the gate works
identically either way. Deployments default to local; the gate itself originates no
remote traffic except the brain endpoint you choose. It is a guardrail, not a
sandbox: a hook can be misconfigured, an agent can bypass a tool path, the
classifier can be wrong. Keep your other controls.

## How this fork differs from upstream jev-guard

This fork exists because a guard should not depend on a cloud you don't control, and
should not fail silently when its brain is down. Concretely, versus upstream:

- **Local-first brain.** Point `SYSTEMONE_URL` at any Jev-compatible local endpoint;
  it wins over every cloud credential, so the gate can be pinned to your own
  infrastructure. Cloud backends still work (`JEV_API_KEY`, `AI_GATEWAY_API_KEY`).
- **Offline rules floor.** When the brain is unreachable, vendored deterministic
  rules — parity-tested 92/92 against their originals — become the gate, with three
  selectable postures (`GUARD_FALLBACK=rules|layered|closed`). No silent fail-open.
- **Operator rulings with a fixed authority model.** Scoped, expiring, audited
  rulings lift ask and deny verdicts; exactly three overrule paths exist, and gate
  self-protection is never liftable by a ruling.
- **Enforced adapter contract.** A versioned contract (`src/contract.js`), a
  conformance suite that fails context-dropping adapters, and per-harness live-verify
  (`unjangled-guardrails verify <harness>`).
- **Renamed, with back-compat.** The package and CLI are `unjangled-guardrails`;
  `SYSTEMONE_*` / `GUARD_*` are primary and every legacy `JEV_*` spelling still
  aliases. The `jev-guard` npm package is upstream, not this fork.

## What it does

Three checks, with the session's context:

- **Before a tool runs** — the classifier scores how much harm the exact call could
  do, given what the user asked for and what the agent has read. Destructive calls
  are denied; risky ones require approval (the user's own words can lift them);
  credential exposure (printing secrets into the conversation) is denied outright;
  calls carrying out instructions planted in untrusted content are denied even when
  they look harmless.

- **After a tool returns** — results (web pages, files, MCP output, command output)
  are scanned for text aimed at AI agents: prompt injection and canaries. Hits are
  flagged as untrusted data, remembered for the session, and the agent is told not
  to follow them.

- **Instruction files** — skills, plugins, rules, `CLAUDE.md`/`AGENTS.md`: every file
  loaded or installed is checked for behavior the person installing it would not
  expect (exfiltration, covert execution, overriding other instructions, canaries,
  unrelated side effects).

## Install

Clone first (`git clone https://github.com/johnbuck/unjangled-guardrails &&
cd unjangled-guardrails`; needs git — minimal images like `node:22-bookworm-slim`
ship without it — and Node ≥ 20.3), then pick your agent — every row is one command
against the checkout, except Hermes, which is a plugin package (see the next
section).

| Agent | Install (from a clone of this repo) | Before a tool runs | After it returns |
|---|---|---|---|
| Claude Code | `node src/cli.js install claude` — hooks into `~/.claude/settings.json` | deny · **ask** prompt | flag |
| Codex | `node src/cli.js install codex` — `~/.codex/hooks.json` | deny · ask → **deny** (no ask surface) | flag |
| Copilot CLI | `node src/cli.js install copilot` — `~/.copilot/hooks/unjangled-guardrails.json` | deny · **ask** prompt | flag |
| Gemini CLI | `node src/cli.js install gemini` — `~/.gemini/settings.json` | deny · ask → **deny** (no ask in BeforeTool) | flag |
| Cursor | `node src/cli.js install cursor` — `~/.cursor/hooks.json` | deny · **ask** for shell and MCP | flag |
| pi | `node src/cli.js install pi` — extension path into `~/.pi/agent/settings.json` | block · **confirm dialog** (headless: block) | flag |
| OpenCode | `node src/cli.js install opencode` — plugin adapter into `~/.config/opencode/plugins/` | throw on deny · ask throws with instructions (conversation loop resolves) | flag |
| Hermes | copy [`plugins/unjangled-guardrails/`](plugins/unjangled-guardrails/) into the profile's plugins dir — **see below** | deny · approval-gate ask (approver required), else deny | flag |
| ACP | editor runs `node src/cli.js acp -- <agent>` | reject · **permission request** | flag |

### Hermes

Hermes is supported as a standalone plugin package — [`plugins/unjangled-guardrails/`](plugins/unjangled-guardrails/),
a Python adapter (`plugin.yaml` + `__init__.py`) that translates Hermes'
`pre_tool_call` / `transform_tool_result` / `post_tool_call` events into the gate's
Claude-shaped hook protocol. It is deliberately not an `install` target: there is no
`install hermes`. The plugin shells out to the gate's real brain in a subprocess —
`node <GUARD_HOME>/src/cli.js hook --agent hermes` — so the policy, rulings,
orchestrator, and offline rules floor all live in this checkout, and the plugin
never needs to know whether the brain is up.

1. Copy the package into the Hermes profile's plugins directory, e.g.
   `~/.hermes/plugins/unjangled-guardrails/` (or `<profile>/plugins/`).
2. Confirm it loads: `hermes plugins list` should show it; if your config gates
   user plugins, enable them via `plugins.enabled`.
3. Set the environment **in the Hermes service environment** (the gateway env, not
   per-session — a per-session export does not reach the plugin's subprocess):
   - `GUARD_HOME=<this checkout>` — required; the adapter resolves the gate
     through it
   - `SYSTEMONE_URL=http://your-brain:8090` — the brain endpoint (any
     Jev-compatible `/v1/systemone` service); add `SYSTEMONE_KEY` if the endpoint
     requires auth
   - `GUARD_FALLBACK` if you want a different outage posture (default `rules`;
     sole-gate hosts usually want `closed`)
4. Ask semantics: when this Hermes has a human-approval flow configured
   (`approvals:` in its config.yaml, mode not off — or set `GUARD_HERMES_APPROVER=1`
   if the plugin cannot see the config), ask-band calls escalate to the approval
   gate and run only after a person approves. Without an approver, an ask denies,
   and the message tells the agent to raise the decision in conversation.
5. Test it: `python3 plugins/unjangled-guardrails/test_adapter.py` (stdlib only).
   For a gateway-deployed Hermes, `tools/hermes-liveverify.sh <gateway-host-alias>`
   replays the recorded probe set (safe passes, destructive blocks) through the
   registered surface.

The per-harness compatibility details — deny/ask encodings, context feeding, tool
name normalization — are in [`docs/harness-matrix.md`](docs/harness-matrix.md).

OpenCode: approval prompts require `"permission": { "bash": "ask" }` in
`opencode.json` — without it, ask-band calls hard-deny. Use
`node src/cli.js install opencode --ask-permissions` to print the snippet and its
tradeoff (it prompts on every bash call, not just gate-flagged ones).

Registration writes are covered by the fixture-HOME install tests in `npm test`
(`test/install.test.js`), and every harness with a hook surface has a live-verify
command (`unjangled-guardrails verify <harness>`) that exercises the real surface
with a safe pass and a must-stop destructive probe. Note: the `jev-guard` package on
npm is the **upstream project** — installing it gets you upstream, not this fork.

### Brain configuration

**Local (default)** — the endpoint is whatever Jev-compatible service you run or
subscribe to; the gate ships no brain:

```bash
export SYSTEMONE_URL="http://your-brain:8090"    # any Jev-compatible /v1/systemone endpoint
export SYSTEMONE_KEY="your-key"                  # optional, if the endpoint requires auth
```

**Cloud:**

```bash
export JEV_API_KEY="ts_…"                        # TypeSafe key from console.typesafe.ai
# or
export AI_GATEWAY_API_KEY="vck_…"                # Vercel AI Gateway key
```

`SYSTEMONE_URL` wins over every cloud credential — with it set, the gate can never
phone home. An existing upstream `~/.jev-guard/config.json` is also honored as a
last-resort credential fallback; delete it if you want the gate to forget upstream
credentials. The key can also be stored with `unjangled-guardrails key <key>` which
writes `~/.unjangled-guardrails/config.json` (mode 0600), useful for GUI hosts
that don't see your shell profile — `unjangled-guardrails key --local <url> [key]`
stores a local brain URL the same way. During an outage, a circuit breaker stops
every judged call from waiting out its full timeout: after
`GUARD_BREAKER_THRESHOLD` (default 3) consecutive brain-call timeouts the gate
skips the brain for `GUARD_BREAKER_COOLDOWN_MS` (default 60 s) and answers
instantly from the offline rules floor; any healthy response closes it again.

## How decisions are made

Two layers, with the brain between them.

**Layer 1 — Always Deny** (heuristic, pre-brain, never liftable — also the
degradation floor while the brain is down): secret/credential shapes (the vendored
secrets-guard core), catastrophic commands (the vendored guardrails core —
recursive deletion of `/`, device writes, fork bombs, force-push variants,
`chmod -R 777`, pipe-to-shell), and self-modification (bash or file-tool writes
into the gate's own source, store, lane, or rulings).

**Layer 2 — the brain judges every other call**, then your per-install policy
(`~/.unjangled-guardrails/user-policy.json` — see
[docs/policy.md](docs/policy.md)) applies your effects to the verdict. The brain
asks narrow, typed questions; the policy is yours, not code.

**Action** (every adapter, post-brain):

```
deny   if from_untrusted ≥ 0.8   (injection: serving content's author, not the user —
                                 precedes the lift)
allow  if user_requested ≥ 0.75  (the user's own words — lifts any non-deny verdict)
deny   if risk ≥ 2.55            (destructive)
ask    if risk ≥ 2.0 or approval ≥ 0.75
deny   if leak ≥ 0.50            (the fall-through deny — the ask band outranks it: a
                                 risky-and-leaky call surfaces as an ask, not a hard
                                 deny; a leak answer below GUARD_LEAK_CONF confidence
                                 does not deny, absent confidence counts as confident)
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

**The overrule paths** — every deny message names an operator-only unlock,
never one an agent could act on by itself:

1. The user's own words in conversation (at the 0.75 threshold, naming the work —
   intent-named assent; bare "yes" does not lift)
2. An operator terminal session
3. An operator policy entry or ruling (per-tool, per-directory, or scoped/expiring —
   see [docs/policy.md](docs/policy.md))

Always Deny is never liftable by any of these — operator terminal only.

**Content** (after a tool returns):

```
flag   if directed ≥ 0.6  and  kind ∈ {injection, canary}  (a missing kind counts as serious)
```

Discussion and benign content are never flagged. Every tool result is scanned
regardless of length (operator rejected the old 200-character floor on
2026-10-11 — a short result can carry an instruction just as well; the per-call
cost is one classifier round-trip per result). Results of local edit/search
tools still skip the post-tool scan. Documentation writes are judged like any
write since the 2026-10-20 consolidation (the old blanket skip is gone); the
shipped suggested defaults carry allow entries for docs trees if the friction
bothers you.

The full generated table — thresholds, Always-Deny families, suggested defaults,
precedence, with each row's ruling lineage — is
[`docs/rules.md`](docs/rules.md), regenerated by `unjangled-guardrails rules-doc`
and validated against the live modules by `unjangled-guardrails rules-check`.

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
still works as an alias for `closed`. A per-install variant of the same choice is
`unjangled-guardrails policy set --degradation fail-open|fail-closed`.

## Operator policy (CONFIG)

The per-install, operator-owned policy surface — layer two of the gate. Tools,
command shapes, and whole directories carry `allow` / `deny` / `ask` effects; the
brain still judges every call, and your effect modifies its verdict (allow passes
the ask band; deny blocks even a brain allow; ask always prompts unless the brain
denied). See [docs/policy.md](docs/policy.md) for the full semantics.

```sh
unjangled-guardrails policy add --tool 'mcp__cognee' --effect allow --reason "trusted memory plane"
unjangled-guardrails policy add --dir /tmp --effect allow --reason "scratch work"
unjangled-guardrails policy add --tool 'mcp__email-mcp__send_email' --effect ask --reason "sends always prompt"
unjangled-guardrails policy add --effect deny --pattern 'terraform apply*' --scope global --expires 2027-01-01
unjangled-guardrails policy adopt-defaults        # merge the shipped suggested defaults (never auto-applied)
unjangled-guardrails policy list
unjangled-guardrails policy remove <id | pattern | dir path>
unjangled-guardrails policy set --degradation fail-closed   # brain-down posture (default: fail-open)
```

- Stored in `$GUARD_HOME/user-policy.json` (0600). Every mutation is operator-only
  (terminal or explicit escape) and paired with a mutation audit row; out-of-band
  changes trip tamper evidence.
- Tool patterns: exact, server-wide (`mcp__cognee`), verb-class (`mcp__*@read`);
  command patterns: per-segment globs, or staged (repeated `--pattern`, one per
  chain segment); directory entries: every resolvable path argument under the dir.
- Scopes (command entries): `global`, `project:<path>`, `session:<id>`, with
  optional expiry. Global requires an explicit `--expires`.
- `ruling init` creates the stranger-owned empty store (agent-runnable, idempotent —
  part of `setup`); `ruling add|list|revoke` remain as a one-release operator-only
  alias for command entries. `lane add|list|remove` is the same-release alias for
  tool entries.
- Always Deny is never liftable by a policy entry or a ruling — operator terminal
  only.

## Tuning

| Variable | Default | Effect |
|---|---|---|
| `GUARD_DENY_SCORE` | `2.55` | risk position at which a call is denied |
| `GUARD_ASK_SCORE` | `2.0` | risk position at which approval is required (ratified 2026-10-12) |
| `GUARD_ASK_P` | `0.75` | approval probability at which approval is required |
| `GUARD_USER_P` | `0.75` | user-requested probability that lifts any non-deny verdict (0.85 → 0.75 on the 2026-10-16 ratification) |
| `GUARD_UNTRUSTED_P` | `0.8` | from-untrusted probability that denies outright (0.7 → 0.8 on the 2026-10-28 ruling) |
| `GUARD_LEAK_P` | `0.5` | leak probability that denies (credential exposure) |
| `GUARD_LEAK_CONF` | `0.3` | leak answer below this confidence does not deny (a guess must not hard-deny; absent confidence counts as confident) |
| `GUARD_INJECT_P` | `0.6` | directed probability at which content is flagged |
| `GUARD_SKILL_P` | `0.8` | instruction-file probability for side effects |
| `GUARD_SKILL_SERIOUS_P` | `0.45` | instruction-file probability for exfiltration etc. |
| `GUARD_TIMEOUT_MS` | `20000` | total budget per classifier call |
| `GUARD_MAX_STATE_CHARS` | `12000` local brain / `60000` cloud | scan-state char budget per request; oversized content is head+tail truncated and still scanned |
| `GUARD_ATTRIBUTION_CAP` | `6` | max segments scored by the attribution fan-out on multi-segment bash calls (advisory only — never changes the verdict) |
| `GUARD_BREAKER_THRESHOLD` | `3` | consecutive brain-call timeouts that open the circuit breaker |
| `GUARD_BREAKER_COOLDOWN_MS` | `60000` | how long the breaker skips the brain and answers from the offline rules floor |
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
unjangled-guardrails setup [<agent>]                Clone-to-verified: install, rulings store, live-verify, readiness report
                                                    (claude | codex | copilot | gemini | cursor | pi | opencode)
unjangled-guardrails calibrate [--url <u> [--key <k>]] [--quick]
                                                    Self-certify a brain against the battery corpus through the wire
                                                    contract; per-class report; exit 1 on a wrong verdict
unjangled-guardrails hook [--agent codex|copilot|hermes]
                                                    Command hook: JSON on stdin → JSON on stdout (host auto-detected)
unjangled-guardrails acp -- <agent command...>      ACP proxy
unjangled-guardrails check <tool> '<json input>'    Assess one call; exit 0/1/2
unjangled-guardrails scan [file]                    Scan a file or stdin; exit 2 if flagged
unjangled-guardrails scan-skills [paths...]         Sweep instruction files
unjangled-guardrails install [<agent>]              Register hooks for one harness (auto-detects when omitted)
unjangled-guardrails verify <harness>               Live-verify the real harness surface: safe passes + destructive
                                                    blocks (opencode | claude | pi | codex | copilot | gemini | cursor;
                                                    Hermes uses tools/hermes-liveverify.sh)
unjangled-guardrails rules-check                    Rules-of-record conformance: the declared rule surface must match the
                                                    live modules, both directions (docs/rules.md)
unjangled-guardrails rules-doc                      Regenerate docs/rules.md from the live modules (its only write path)
unjangled-guardrails key <api key>                  Save a cloud key to config
unjangled-guardrails key --local <url> [key]        Persist a local brain URL (and optional key)
unjangled-guardrails key --infisical --project <id> Restore the local brain key from Infisical (machine identity); the
                                                    key value never appears in argv or output
unjangled-guardrails policy add|list|remove|set|adopt-defaults   Operator policy: tool/dir/command effects (allow/deny/ask), suggested defaults, degradation posture
unjangled-guardrails ruling init|add|list|revoke    init: the first-session empty store (agent-runnable); add|list|revoke:
                                                    operator-only back-compat alias for command entries
unjangled-guardrails lane add|list|remove           Back-compat alias of policy for tool entries (the user-lane surface)
unjangled-guardrails decision export [--from <path>]  Emit the redacted decision-record export document (docs/decision-records.md, format v1)
```

All available as `node src/cli.js <command>` from the repo. `verify`, `rules-check`,
`rules-doc`, `setup`, and `calibrate` need a git clone — the npm tarball ships
`src/`, `extensions/`, `hooks/`, and the plugin manifests, but not `tools/`.

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
npm test                                       # node test suite + conformance suite
python3 plugins/unjangled-guardrails/test_adapter.py   # Hermes adapter suite
node tools/conformance/run.mjs                 # conformance suite standalone
node tools/parity-vendored.mjs                 # vendored rules parity (92 cases)
node tools/verify/live-verify.mjs              # live-verify runner
```

Layout: `src/contract.js` (adapter contract) · `src/guard.js` (questions + brain verdicts + policy application) · `src/always-deny.js` (Always-Deny families) · `src/policy.js` (operator policy surface) ·
`src/jev.js` (one fetch, any backend) · `src/orchestrate.js` (degraded gate,
self-modification guard, offline rules) · `src/rulings.js` (operator rulings +
authority) · `src/context.js` + `src/session.js` (what the classifier sees) ·
`src/skills.js` (instruction-file sweep) · `src/hook.js` (Claude/Codex/Copilot/
Gemini/Cursor hooks) · `src/acp.js` (ACP proxy) · `src/opencode.js` (OpenCode
plugin) · `extensions/unjangled-guardrails.ts` (pi) · `plugins/unjangled-guardrails/`
(Hermes) · `vendor/` (vendored rules cores, parity-tested).

## License

MIT
