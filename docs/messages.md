# Every message, exit code, and return shape

Complete inventory, re-sourced from code 2026-10-25 (the deny/ask message registry:
plan-message-registry, operator-ratified). Three return surfaces: CLI exit codes, hook
JSON (per harness dialect), and adapter behaviors (OpenCode plugin / Hermes plugin).
Decision messages are shared — one string, three transports. Governance truth: the
Always-Deny floor is absolute; everything else is the brain's verdict with the operator's
policy effects applied.

## 0. The gate, in one paragraph

**Layer 1 — ALWAYS DENY** (src/always-deny.js): heuristic, pre-brain, chat-blind, absolute.
Three families, both vendored cores: Secrets (secret-leak-guard checkBash/checkRead/isSecretFile
+ SECRET_SHAPE write-content detection + the credential-source command legs + the gate's own
config leg), Catastrophic (the vendored 11-shape list: recursive rm of /, device writes, fork
bomb, force push, chmod -R 777, pipe-to-shell), Self-modification (bash + path guards over the
gate's own source/store/config). Nothing lifts it — no brain verdict, no user words, no policy
entry. It is the ONLY pre-brain layer and the ONLY thing that gates while the brain is down.
**Layer 2 — THE BRAIN**: every call not Always-Denied pays the round trip (allow-listed tools
included — universal injection checking, resolved design decision 1). **Layer 3 — CONFIG**
(src/policy.js, docs/policy.md): tool entries apply effects (deny → deny; ask → prompt unless
the brain denied; allow → the ask band passes), then the command-entry consult (allow entries
lift asks and denies; deny entries hard-block allows). The old fifteen-layer pipeline (skip
classes, safe lanes, doc-write skips, the active-floor escalation, workflow bookkeeping) is
gone; its operator shapes live in examples/user-policy.default.json, adoptable per install.

## 1. The message registry (src/guard.js `assessAction`)

**The header rule.** Every deny — hard-rule hit, brain deny, degraded, ask→deny — renders the
same header with the FIXED authority:

```
Permission for this action was denied by the Unjangled Guardrails classifier. Reason: [<Family>] (<parens>): <what>.
```

No variant, no layer claim: "offline rules" appears in no message text. The `<parens>` carry
posture and layer only:

- hard rules → the plain rule name + specifics: `read-path gate: SSH private key`,
  `leak-guard rule: environment dump`, `write-content floor: credential read staged with
  network egress`, `write-content floor: credential-shaped value`,
  `credential-source floor: <pattern name>`, `catastrophic command`, `policy store write`,
  `policy store access`, `gate source write`, `guard's own store/config/sessions`, or
  `agent-config gate: gate config holds a stored API key`.
- the brain → the score stats: `risk X.X/3, approval p=0.XX` (+ `user-asked p`,
  `from-untrusted p` when session context exists) + `confidence 0.XX` + `leak p` (when any
  leak answer exists) + `user lane` / `dir policy` (when an entry matched).
- degraded → `brain down, rules mode; fail-closed`.
- operator rules → the ruling why (unchanged behavior).
- asks keep their existing sentence and header form (`This action needs the user's approval,
  per the Unjangled Guardrails classifier.`), allow keeps `Unjangled Guardrails: ok, <why>
  (<stats>)`. A brain-held compound releases to that allow when no segment alone justifies
  the hold — read-only text utilities (`cut`/`sort`/`uniq`/`wc`/`head`/`tail`, presence-only
  greps) score at the floor without a brain call, and a held compound's `Segment scores:`
  sentence names the segment that drove the hold with its driver (`risk ≥ …`,
  `approval p=…`, `leak p=…`) — CAP-8, entry 8; operator ask entries never release, and
  segments beyond the attribution cap are named in the suffix, never silent. A message-only
  local commit (`git commit -m …`, flag analysis per the house default's own vouched shape:
  `-a`/`--all`/`--amend` and every other flag stay brain-side) rides the safe local VCS band:
  its approval driver cannot hold it, solo or in a compound, while the brain's risk and leak
  say stays full force — a held commit-shaped verdict carries a `Commit verdict:` sentence
  naming the driver and, for out-of-band shapes, the element that kept it out of the band —
  CAP-9, entry 9. A solo cleanup of the session's own untracked output (`rm`/`rmdir` of paths
  the session's allowed calls created, strictly inside the project's git work tree, with git
  reporting nothing tracked under them) releases the same way — the generated-output cleanup
  release (CAP-11, entry 12), fed by a per-session `created` list the adapters record on
  allowed creator calls (write-family tools, `mkdir`, `touch`, redirect targets); a held
  cleanup carries a `Cleanup verdict:` sentence naming the driver and, when the shape did
  not verify, the noun-phrase reason that kept it out (a tracked path, content the session
  did not create, a path outside the work tree) — tracked and operator-owned paths are
  unaffected in every direction.

**The seven messages.** One guidance text per bracket family, byte-identical across hard-rule
hits, brain hits, and brain-down hits. The `(matched: …)` slot is per-trigger:

| Family | Fires on | (matched: …) clause |
|---|---|---|
| [Credential Exposure] | credential-source floor, read-path gate, agent-config gate, leak-guard bash rules, write-secret-shape, brain leak deny, brain-down fail-closed | per trigger — see below |
| [Credential Exfiltration] | the write-then-run floor | `line N reads a credential file / carries a secret-shaped value, line M sends its value over the network` |
| [Dangerous Action] | catastrophic shapes AND the brain's risk deny line | — |
| [Gate Self-Protection] | bash store/source writes, exec-payload writes, AND the path guard | per trigger — see below |
| [Injected Instruction] | the untrusted veto | — |
| Operator rule | user lane / dir policy denies, ruling hard-blocks | — (the header's [<Family>] slot carries the ruling why) |
| No-prompt-host ask→deny | an ask on a host with no approval surface | — |

The full texts live verbatim in src/guard.js (`FAMILY_GUIDANCE` and `ASK_BLOCKED_GUIDANCE`);
docs do not duplicate them. Per-trigger matched clauses for [Credential Exposure] and
[Gate Self-Protection]:

- credential-source floor → `the command's shape matched: <pattern name>, <redacted preview
  of the matching operand>` (pattern names per leg: credential file operand, git credential
  staging, runtime environment dump, remote credential fetch, guard config read /
  redirect read / evaluator, credential variable print, remote credential extraction, remote
  env file source, credential-printing tool output, display-duplicator pipe, credential
  encoding, secret object display, system credential file grep, credential marker filter,
  credential-source argument text).
- read-path gate → `SSH private key, <path>` / `credential file, <path>` (the kind derives
  from the vendored isSecretFile classes).
- agent-config gate → `the gate's own config file, which stores the backend API key` (the
  vendored harness-config family: `an agent config file, which embeds inline secrets`).
- leak-guard bash rules → the vendored rule's reason, e.g. `environment dump, prints every
  variable's value and secrets may be among them`.
- brain leak deny → per LEAK_KEYS (src/guard.js `LEAK_MATCHED_CLAUSES`): the command's output
  would print secret or credential values / the command echoes environment variable values /
  the command prints other processes' full command lines, whose arguments often carry tokens /
  the command reads a credential file's contents into its output.
- brain-down fail-closed → the brain was unreachable, so the fail-closed posture denied this
  call with no pattern matched.

Per-trigger matched clauses for [Gate Self-Protection] (every deny names exactly what it
matched — the legs are target-keyed, never command-text-keyed). Operator rulings 2026-11-09,
recorded at ticket 14: these denials are ABSOLUTE on gate writes — no chat approval, policy,
or ruling lifts them (approving in chat is the doctrine's own non-event; the GHI-14 repro
denied twice after chat approval and that is the ruled behavior) — and an outward-facing
remote post (a `gh issue create` to the public tracker, a release, a comment) is normal
content the brain judges, not a gate write: only operands that resolve into the protected
roots fire, and the operator's route for a genuinely needed protected action is their own
terminal.

- the policy-CLI leg → `the gate policy-CLI invocation '<entry> <family> <subcommand>'` (the
  mutating subcommands at command position; `policy list`/`where` and `ruling init` pass).
- the operator-env leg → `the operator-context env assignment '<GUARD|JEV_GUARD>_OPERATOR_CLI=…'`
  (command position only — a quoted mention is prose).
- a store-file write (redirect target, mutation verb) → `the redirect target <resolved path>` /
  `the write target <resolved path>`.
- a store-file read (any other resolved touch, bash plane or read-shaped file tool) →
  `the private store path <resolved path>` / `the store file <resolved path>` — the GHI-10 read
  split: docs and source read forever, the policy store operator-private. File operands of
  outward posters resolve too (ticket 14): `--body-file`/`--input`/`--notes-file` and the
  `@<file>` read-from-file spelling of `gh api`/`curl` fill the request by READING the file
  (an `@`-prefixed scratch path and `@-` never resolve).
- gate-source writes → `the write shape '<offending segment>'` (the verb×target segment) /
  `the gate-source write target <resolved path>` (an executing payload's literal target).
- the path guard → `the guard path <resolved path>` / `the guard path <guard root> inside an
  executing payload`.
- executing payloads (`execute_code`-class code/script fields) → the literal write target,
  resolved against the call cwd: `the write target <resolved path> inside an executing
  payload` (store write), `the store path <resolved path> inside an executing payload`
  (store read — the read split's exec plane), or the gate-source/path clauses above. Content
  embedded in the payload (triple-quoted and template spans) is stripped before extraction —
  discussion never fires; variable targets never resolve and ride the brain.

**Matched-display discipline** (operator ruling 2026-10-25, amending the 2026-10-12
preview-discipline ruling): matched PATTERN, PATH and LINE structure displays — the
credential-source `what` is `<tool> <redacted-values preview> (matched: <pattern name>)`, the
write floors' matched-lines block is titled `Matched lines (values masked):`, and read-path
matched clauses carry the path. Secret VALUES stay masked: every preview and matched line runs
the redactSecretShapes/redactCredentialSpans pipeline — never a raw token, key, or credential
value in any message.

Deny `why` values (structured result field, unchanged — the whys are not message text), in
the gate's order:

**Layer 1 (Always-Deny — pre-brain, absolute, no lifter):**

1. `the built-in offline rules block it — a credential file was staged for commit (shape redacted) — secrets never enter git history` / `— a command operand names credential material (shape redacted) …` / `— the command reaches a remote host for credential material …` / `— the gate's own credential-bearing config …` / `— the command prints a credential-named variable's value …` / `— the command extracts credential values from a remote host …` / `— the command sources a remote credential env file …` / `— the command carries credential-source text in its arguments (redacted) …` — the credential-source command floor (family `credential-source`, category `Credential Exposure`)
2. `the built-in offline rules block it — this write stages credential-source material together with executable network egress (write-then-run; shapes redacted)` — the write-content floor (family `write-credential-egress`, category `Credential Exfiltration`)
3. `the built-in offline rules block it — the written content carries a credential-shaped value (shape redacted) …` — the SECRET_SHAPE write leg (family `write-secret-shape`, category `Credential Exposure`; a credential-shaped write target is exempt — keys belong in env files)
4. `the built-in offline rules block it — <checkRead reason>` and `— displaying the gate's own config would print its stored backend credential (shape redacted)` — the read-path credential gate (TR-3) on read-shaped tools, every posture (families `credential-file` / `agent-config`)
5. `the built-in offline rules block it — <vendored checkBash reason>` — the secret-leak-guard bash rules (env dumps, docker inspect env, process argv, the secret-manager flows), every posture, pre-brain (category `Credential Exposure`)
6. `this command modifies the gate's own policy or rulings store — operator-only (run it from your own terminal)` — bash store mutations: the policy/ruling/lane CLI at command position with a mutating subcommand, the operator escape env assignment, or a real write into a store file (redirect, mutation verb — keyed on the resolved target)
6a. `this command reads the gate's own policy store from agent context — the store is operator-only (reads run from your own terminal too)` — the GHI-10 read split: any other resolved touch on a store file denies as private-store access (bash plane and read-shaped file tools; docs, source, and sessions stay readable)
7. `this command writes the gate's own source — operator-only (run it from your own terminal; edit the checkout via the project's reviewed dev flow)` — the verb×target rule: a write shape (redirect target, in-place editor, language writer, destination copy, tee, dd) and a gate-source path sharing a command segment
8. `this file is inside the guard's own store/config/sessions — operator-only (the gate does not edit itself)` / `… — operator-only` — the path guard: Write/Edit/NotebookEdit/MCP file tools over the store, audit, policy, config, or sessions paths (layer 1 is absolute — self-mod precedent)
8a. `this file is the gate's own policy store — operator-only (reads run from your own terminal too)` — the path branch of the GHI-10 read split: read-shaped tools over a guarded STORE file (the policy/rulings/lane names; sessions reads and the config files' own credential-family split stay as they were)
9. `the built-in offline rules block it — a catastrophic-command rule matched (mass deletion, device overwrite, force push, recursive 777, or pipe-to-shell)` — the vendored CATASTROPHIC list (family `catastrophic`, category `Dangerous Action`)

**Layer 2 (the brain's decide(), in order):**

10. `it looks like it carries out an instruction from untrusted content, not the user's request` — from_untrusted p ≥ 0.80 (GUARD_UNTRUSTED_P; ruling 2026-10-28 raised the default 0.7 → 0.8 for the H2O calibration); operator-ruling-only, NOT liftable by user words
11. user_requested ≥ 0.75 → **allow** (lifter, not reached as a deny) — only the user's own messages count, never tool results/pages/files; requires the user's own naming of what is approved
12. (bare deny, category `Dangerous Action`) — risk ≥ 2.55 (GUARD_DENY_SCORE)
13. `this command's output would print secret or credential material (API keys, tokens, passwords, private keys, credential-file contents) into the conversation — once printed, it cannot be taken back` — leak p ≥ 0.50 with confidence ≥ GUARD_LEAK_CONF below the ask band (TR-5; confidence gate per operator rulings 2026-10-20 and 2026-10-28 — an absent noul confidence is derived as 1 − H(noul)/ln 2, never read as fully confident; category `Credential Exposure`)

**Layer 3 (CONFIG, on the brain's verdict):**

14. `user lane: denied by operator rule (<pattern>)` — a tool entry with effect deny, over any brain verdict
15. `dir policy: denied by operator rule (<path>)` — a directory entry with effect deny
16. `the operator ruling <id> hard-blocks it (<reason>)` — a deny command entry over a brain allow

**Degraded (brain down):** Always-Deny has already gated; what remains resolves by posture —
fail-open (default): `the brain is unreachable — the call passed the built-in offline rules
(semantic review resumes when the brain returns)`; fail-closed (GUARD_FALLBACK=closed or the
policy `degradation: "fail-closed"` option): the deny renders the registry header with parens
`brain down, rules mode; fail-closed` and the [Credential Exposure] family text; an allow
command entry still lifts: `by ruling <id> (the brain is unreachable, but the ruling needs none)`.

The leak deny requires some leak answer at `leak p >= GUARD_LEAK_P` WITH confidence
`>= GUARD_LEAK_CONF` — an unconfident leak guess falls through to the normal bands instead of
denying (operator ruling 2026-10-20, evidence/leak-confidence-2026-10-20.md). Since operator
ruling 2026-10-28 a noul answer without a confidence on the wire gets one derived as
`1 - H(noul)/ln 2` (the shim's own formula, system_one/translate.py), so the gate reads the
same number on every backend and the decision rides the noul probability either way; a
confidence absent at decide() itself (direct callers, test stubs) still counts as confident.
A structured `category` rides the result so adapters
can tell a leak from an approval ask; `family` is the structured classification set at verdict
time — the guidance lookup keys on it, never on the why prose.

## 2. The operator unblock block (ask band only)

Copy-paste policy hints ride ask messages only (ticket 7.4; rebuilt CAP-7, 2026-11-10 —
additive, the message copy extended per the operator's direction): one line per command
segment under `Operator unblock (run in your own terminal, not here — the gate blocks
agent-run ruling changes):`, each line the current, paste-runnable operator command —

`GUARD_HOME='<store home>' node '<install root>/src/cli.js' policy add --effect allow --pattern '<generalized pattern>' --scope 'project:<resolved call workdir>' --reason 'operator unblock'`

— followed by one trailing comment naming the exact store the pasted rule lands in:
`# policy store: <file>`. The four fixes the field report demanded (GitHub issue 4): the
pattern is generalized — verb + subcommand pinned, a following flag run kept, the variable
tail wildcarded (`git push origin release` suggests `git push *`; `git commit -m 'ship it'`
suggests `git commit -m *`; a fully-concrete segment stays exact); the invocation is the
install's own `src/cli.js` — a clone install has no bin on PATH, so the hint never names a
bare binary; the subcommand is the current `policy add`, never the retired `ruling` alias;
and the `GUARD_HOME` prefix points the operator's terminal at the store this gate consults
(the issue-5 split — without it the paste writes a store nothing reads), with the trailing
comment and the CLI's own store footer naming the same file. The scope is the resolved call
workdir (ticket 1.6), never the harness home. The prompt-capture mint deliberately stays
exact-segment — a human approved that one call; the hint's generalization is the operator's
own reviewed act at their terminal. Denies never carry a hint. `askBlockedDeny` preserves
the hint through the ask→deny conversion on no-prompt hosts.

## 3. Exit codes (src/cli.js)

| code | meaning |
|---|---|
| 0 | allow / clean / success |
| 1 | ask (check), usage errors, flagged scan-skills, refused mutations |
| 2 | deny (check), flagged scan, install takeover refusal |
| 3 | check crash / setup failure / scan-skills errors |

## 4. Degrade marker (stderr)

`unjangled-guardrails: brain unreachable — the built-in offline rules are the gate until it returns`
(fail-open) · `brain unreachable — deferring to the installed heuristic stack` (layered) ·
`store changed without an operator action (<file>) — possible tampering` · migration:
`migrated N ruling(s) and M lane entr(ies) into <store>`.
