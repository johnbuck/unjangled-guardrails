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

Flag applicability: a tool entry takes `--tool` (repeatable — the pattern itself), `--effect`,
`--reason`. It takes NEITHER `--scope` NOR `--expires` — the CLI refuses both with one line
naming the command-entry surface (the flag matrix below states all three kinds).

## Command entries (the rulings, folded in)

Command-glob entries carry the rulings semantics: an **allow** entry lifts asks AND denies
(the deliberate, audited operator act), a **deny** entry hard-blocks a brain allow. That
includes the brain's leak denies: a command allow entry lifts brain denies for its shape —
ship them only for shapes you vouch for. Optional
`scope` (`global | project[:path] | session:<id>`) and `expires` (ISO, 7d/12h/30m, or
never — `never` = no expiry at all, the spelling `policy list` renders for every
expiry-less entry) ride
along; a command entry without an expiry stands (the config surface is the per-install
standing posture, adopted deliberately). `--scope` and `--expires` belong to command
entries alone — on tool and directory entries the CLI refuses them with one clean line
naming this surface, never a silent drop (the flag matrix below). A `project:` scope matches the directory the tool
call **runs in**: for terminal/shell calls the call's own workdir/cwd argument when it
carries one (the core derives it — the adapter-supplied session cwd is the fallback), so a
folder-scoped entry covers every repo under the prefix however the harness homes itself —
never the harness install directory. The old `rulings.json` and `user-lane.json` migrate
into the one store on first run.

### Prompt-captured rulings (provenance)

An ask prompt the harness owns can mint these entries in-process
(`capturePromptRuling` through the adapter contract, 1.2.0): the chosen session/always
option becomes an **allow** entry carrying `prompt:<harness>` provenance on both the entry
and its audit rows. That provenance has exactly one constructor — the capture export
called with a human's choice on a live ask; no env var or CLI argv mints it, and the
`GUARD_OPERATOR_CLI` escape still records `env-escape`. The tier knob
`GUARD_PROMPT_RULINGS` governs what may persist: `off` (the default — choices consume as
allow-once, nothing persists), `session` (captures mint `session:<id>` with a **24h**
expiry, shorter than the 7d operator-minted default), `project` (an "always" capture
mints `project:<cwd>`; a "session" capture still mints session scope). Patterns are exact
segments derived from the asked call under the capture surface's own constraints (≤3
segments, no quote or glob characters in a segment); the copy-paste hint generalizes its
patterns (CAP-7) while the mint deliberately does not — the human approved that one call;
allow-effect only, never global scope, never deny-effect. A
per-session write cap (`GUARD_PROMPT_RULINGS_CAP`, default 20) bounds forged prompt
answers, every write pairs a `prompt:<harness>` mutation row in the audit file, and a
capture failure never changes the ask outcome — an allow-once stays once. Both list
surfaces make the provenance visible: `ruling list` and `policy list` render a
`(prompt:<harness>)` tag at the end of each prompt-captured entry's line (the stored
via verbatim — operator-minted rows carry no tag), and `policy list` shows the
effective capture tier as a `prompt-capture: off|session|project` line beside the
degradation posture — always printed, off default included, read through the same
parse the mint honors (an unknown knob value reads `off`).

Lifetime (operator ruling 2026-11-06): prompt-captured session grants die two ways —
the **24h mint-time cap** (every session-scope capture carries an explicit now+24h
expiry at mint, never the 7d operator default) and **death at session end**: when the
harness announces a session ended (`expirePromptSession` through the adapter contract,
1.3.0), that session's prompt-captured session-scope allow entries are removed. The
cleanup's scope discipline is hard — only `prompt:<harness>`-provenance session-scope
allow entries for that one session id; operator-minted 7d session rulings are NEVER
cleaned by session end, project captures are cross-session by design and survive, and
deny entries and other sessions are untouched. It never mints, so it needs no
operator authority (like `initStore`); one `policy-remove`/
`expire-prompt-session` audit row (`via: "session-end:<harness>"`) lands per
effective cleanup, and a cleanup that removes nothing writes nothing (repeated end
signals are idempotent). A corrupt store refuses the mutation like every other — the
grants then die by the 24h cap. One re-mint edge: a repeat capture whose matching
prompt entry has expired supersedes (dead entry removed, fresh 24h clock, the cap
applies); an expired operator-minted match keeps the inherited dedupe — accepted
residual, fail-safe direction.

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
Deterministic: effects hold in every posture, brain down included.

Optional expiry (operator ruling 5, 2026-11-09): a directory entry carries `--expires`
like a command entry's — ISO, 7d/12h/30m, or `never`; **absent = permanent** (no default
span: dir entries have no scope dimension). A lapsed statement stops covering at consult
time and lists as `[EXPIRED]`; it is never auto-purged — like command entries, expired rows
stay on the record. One statement per **(directory, expiry)**: widening is **add the new
expiry and let the old lapse** — nothing deleted by hand; changing an effect is still
remove + re-add (`policy remove <id>` — or the dir path, which removes every entry at
that path).

## The flag matrix (per entry kind)

Which flags each entry kind takes (GitHub issue 17 / CAP-14). `policy --help` and
`policy add --help` print this matrix; a flag on a kind that does not take it refuses with
ONE line naming where the flag belongs — never a silent drop, never the full help dump.

| flag | tool entry (`--tool`) | command entry (`--pattern`) | directory entry (`--dir`) |
|---|---|---|---|
| `--effect` | allow \| deny \| ask (default allow) | allow \| deny (default allow) | allow \| deny \| ask (default allow) |
| `--tool` (binding) | it IS the pattern (repeatable) | optional — binds the entry to one tool | no (mixing kinds refuses) |
| `--scope` | no — refused | global \| project[:path] \| session:<id> (default `project:<cwd>`) | no — refused |
| `--expires` | no — refused | ISO \| 7d \| 12h \| 30m \| never (absent → project 30d / session 7d defaults) | ISO \| 7d \| 12h \| 30m \| never (absent = permanent) |
| `--reason` | yes | yes | yes |

Widening a directory entry (ruling 5): `policy add --dir <path> --effect allow --expires 30d`
after an earlier `--expires 7d` on the same path — both statements stand, coverage is
continuous, the old row lapses on its own. `--expires never` is the explicit permanent
spelling on both kinds that take an expiry.

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
unjangled-guardrails policy add --dir /srv/scratch --effect allow --expires 7d \
  --reason 'confined scratch, one week'   # ruling 5: widen later by adding a new expiry
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

Posture (operator rulings 2026-11-09): the defaults carry no push entries and no
leak-lifting read entries. `git push` and `git push origin *` live only in the opt-in
example `examples/user-policy.git-work.json`, adopted deliberately by name (`policy
adopt-defaults examples/user-policy.git-work.json` — the same command, the file named); that
file also carries commit allows scoped to a projects folder, and its `~/projects` scope is a
placeholder — substitute your absolute folder (e.g. `project:/home/you/projects`) before or
after adopting, or those entries never match (scope matching is a literal prefix on the call's
working directory). The read utilities `cat`, `grep` and `echo` ship nowhere as entries:
routine reads stay quiet through leak-guard precision, not blanket allows (`ls`, `head`,
`tail`, `wc`, `find` keep their listing-utility entries). A store that adopted the
pre-rework defaults keeps those entries until removed by hand (`policy remove`) — adoption is
additive and never deletes.

## Degradation posture

Brain down: Always-Deny gates; unmatched calls **pass** (fail-open, the default). An operator
can harden the install with `policy set --degradation fail-closed` (unmatched calls deny), or
per-process with `GUARD_FALLBACK=closed` (env wins over the policy option). The `layered`
env posture (defer to a host heuristic stack) stays env-only.

## Store visibility (which user-policy.json a command or harness actually touched)

The store root resolves from the environment — `GUARD_HOME`/`JEV_GUARD_HOME`, else
`~/.unjangled-guardrails` — and a harness deployment can legitimately set `GUARD_HOME` to a
different tree (the Hermes adapter must: it points at the fork root so the plugin can spawn
the hook). That used to split silently: operator-terminal commands wrote one store while the
harness read another (GitHub issue 5). Three surfaces make the split visible:

- **The echo** — every `policy`/`ruling`/`lane` command prints one footer line naming the
  store file it touched, and warns on stderr for every harness recorded at a different
  root. `ruling init` has always named the path; the footer makes it uniform.
- **The harness store registry** — `<default home>/harness-stores.json` records, per
  harness, the store root a real gate call actually resolved (`{ home, spell, at }`). Gate
  processes that SERVE a harness record at their entry (the hook's `main`, the ACP proxy,
  the opencode plugin entries) — never per call, never from library code. Guards keep it
  honest: an env without `PATH`/`HOME` (probes, tests) records nothing, and a store root
  under the OS tmpdir (scratch fixtures) records nothing; a missing registry reads empty,
  a corrupt one is regenerated by the next recording.
- **`policy where`** — read-only and not operator-gated (an agent may run it): prints this
  terminal's store, the default store, every recorded harness's store (divergences marked
  `[diverges]`), and every registered install with no runtime record yet. An unrun
  install's store is never guessed — it is whatever its harness env resolves at run time.

Residuals: the pi extension's in-process entry does not record yet (the hook, ACP and
opencode surfaces do; `where` still lists a registered pi install); a harness whose gate
has never run shows no record until it does. The registry is a map, not a sync — stores are
never merged or copied; the operator decides which store is real (`GUARD_HOME` in the right
env, or `policy` run from the terminal whose store the harness should share).

Store: `~/.unjangled-guardrails/user-policy.json` (0600). Audit:
`~/.unjangled-guardrails/rulings-use.jsonl` (one audit file for policy and ruling mutations
alike). Bash writes to either file are gate-self-modification (operator-only, chat-blind).
