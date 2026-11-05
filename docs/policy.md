# The policy (CONFIG)

The per-install, operator-owned configuration layer — layer 3 of the consolidated gate
(2026-10-20; the user lane it absorbs shipped 2026-10-17, effects 2026-10-19). The gate reads
it in one order: **Always-Deny → the brain → this policy → the surfaced verdict**. Tools named
here still go through the brain — an entry applies its effect to the brain's verdict.
Deterministic: effects hold in every posture, brain down included. Harness-agnostic — every
adapter on this install inherits the policy.

## The three bands, one paragraph

**ALWAYS DENY** (src/always-deny.js, both vendored cores): secret shapes, catastrophic
commands, gate self-modification — heuristic, pre-brain, chat-blind, absolute; the only thing
that gates while the brain is down. **THE BRAIN** (decide()): every call not Always-Denied —
including allow-listed tools; universal injection checking is the point and the ~2s is the
accepted cost. **CONFIG** (this file's store): the operator's effects on the verdict.

## Effects (tool entries)

| effect | meaning |
|---|---|
| `allow` (default) | the ask band passes: a brain hesitate on this tool is the operator's pre-decided pass |
| `deny` | always blocks, even over a brain allow |
| `ask` | always prompts, even over a brain allow, even degraded — unless the brain's deny line fires (dangerous is dangerous) |

Only three things stop a covered tool regardless of effect: the Always-Deny layer, the brain's
deny line, and an operator ruling that deliberately overrides.

## Command entries (the rulings, folded in)

Command-glob entries carry the rulings semantics: an **allow** entry lifts asks AND denies
(the deliberate, audited operator act), a **deny** entry hard-blocks a brain allow. That
includes the brain's leak denies: a command allow entry lifts brain denies for its shape —
ship them only for shapes you vouch for. Optional
`scope` (`global | project[:path] | session:<id>`) and `expires` (ISO or 7d/12h/30m) ride
along; a command entry without an expiry stands (the config surface is the per-install
standing posture, adopted deliberately). The old `rulings.json` and `user-lane.json` migrate
into the one store on first run.

## Directory entries (the confined-work surface)

`policy add --dir <absolute path> --effect allow|deny|ask` — "calls whose argument paths ALL
resolve under this directory take this effect" — within the covered tool families below: v1
ENUMERATES the path-carrying shapes, and a tool outside them contributes no path arguments
and takes the plain verdict. Directory entries are **post-brain verdict
modifiers only**: every call still goes through the brain (an entry never replaces judgment),
and Always-Deny is unchanged — pre-brain, absolute, outranking every entry (a credential shape
under /tmp still Always-Denies before any of this is consulted).

| effect | meaning |
|---|---|
| `allow` | a brain ask on covered work becomes allow — the hesitation passes for in-dir work; a brain allow stays allow |
| `deny` | the verdict becomes deny, even over a brain allow (rulings may still deliberately override) |
| `ask` | the verdict becomes ask, even over a brain allow — unless the brain's deny line fired (dangerous is dangerous) |

The brain's deny line stays deny under every effect — "not dangerous" means the brain did not
deny. A call is covered when it has at least one resolvable path argument and **every**
resolvable path argument resolves under the directory (`path === dir`, or starts with
`dir` + separator). The covered families, fixed by v1: the file-shaped read/view/cat/read_file/
read_many_files/glob/grep/ls/list/find/search_files and write/edit/delete spellings (bare
names or an mcp `__` final segment) contribute their `path`/`file_path`/`filePath`/`PATH`/
`notebook_path` arguments; bash commands contribute their absolute and `~/`-rooted tokens per
sub-command segment, redirect targets (`>`, `>>`, `2>`, `<`) included. An UNLISTED
path-carrying tool — an MCP `move_file` (`source`/`dest`), `directory_tree`, anything else
with its own arg spelling — contributes none and takes the plain verdict: a dir **deny does
not bind it**, so treat the enumeration as part of the entry's trust decision. Bare relative
names are not path arguments either. Most-specific directory wins (longest path).
Deterministic: effects hold in every posture, brain down included. One entry per directory —
changing an effect is remove + re-add.

## Specificity

Tool entries: **most-specific pattern wins** (exact > longest prefix > verb-class >
server-wide), equal-specificity ties resolve deny > ask > allow. Command entries: the rulings
matcher — every segment of a compound command must match the entry's glob. Directory entries:
the **longest covering path wins** (same-path ties resolve deny > ask > allow).

## Managing it (operator terminal only — agents cannot edit the policy)

```bash
unjangled-guardrails policy add --tool 'mcp__server' --tool 'mcp__other' \
  --reason 'trusted planes'
unjangled-guardrails policy add --tool 'mcp__mail__send_email' --effect ask \
  --reason 'sends always prompt'
unjangled-guardrails policy add --effect deny --pattern 'terraform *' --scope project:/prod
unjangled-guardrails policy add --effect allow --pattern 'git push origin *' \
  --reason 'plain pushes; force variants die at Always-Deny'
unjangled-guardrails policy add --dir /tmp --effect allow \
  --reason 'transient scratch work'
unjangled-guardrails policy set --degradation fail-closed   # brain-down: unmatched calls deny
unjangled-guardrails policy adopt-defaults                  # merge the suggested defaults
unjangled-guardrails policy list
unjangled-guardrails policy remove <id | pattern | dir path>
```

`ruling` and `lane` remain as one-release aliases of `policy`. On hosts without the bin on
PATH: `node <plugin-root>/src/cli.js policy …`.

## Pattern forms (tool entries)

| form | example | matches |
|---|---|---|
| exact | `mcp__server__send_email` | that one tool |
| server-wide | `mcp__server` | every tool on the server (prefix ends at a `__` segment boundary — never a partial segment) |
| server-wide star | `mcp__server*` | every tool whose name starts with the prefix |
| verb-class | `mcp__*@read` | any server, any tool whose final segment starts with `read` (read, read_file, read_many_files — but not recall) |

## Suggested defaults

`examples/user-policy.default.json` ships the operator shapes that left src/ in the
de-identity pass (agent-management planes, trusted read planes, workflow bookkeeping, doc-tree
writes, everyday git, throwaway build trees). **Never auto-applied**: `policy adopt-defaults`
merges it on explicit command, skipping what is already present. Review before adopting — an
allow command entry lifts the brain's denies for its shapes. Nothing in it can touch the
Always-Deny layer.

## Degradation posture

Brain down: Always-Deny gates; unmatched calls **pass** (fail-open, the default). An operator
can harden the install with `policy set --degradation fail-closed` (unmatched calls deny), or
per-process with `GUARD_FALLBACK=closed` (env wins over the policy option). The `layered`
env posture (defer to a host heuristic stack) stays env-only.

Store: `~/.unjangled-guardrails/user-policy.json` (0600). Audit:
`~/.unjangled-guardrails/rulings-use.jsonl` (one audit file for policy and ruling mutations
alike). Bash writes to either file are gate-self-modification (operator-only, chat-blind).
