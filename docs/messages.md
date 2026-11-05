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
  `gate source write`, `guard's own store/config/sessions`, or
  `agent-config gate: gate config holds a stored API key`.
- the brain → the score stats: `risk X.X/3, approval p=0.XX` (+ `user-asked p`,
  `from-untrusted p` when session context exists) + `confidence 0.XX` + `leak p` (when any
  leak answer exists) + `user lane` / `dir policy` (when an entry matched).
- degraded → `brain down, rules mode; fail-closed`.
- operator rules → the ruling why (unchanged behavior).
- asks keep their existing sentence and header form (`This action needs the user's approval,
  per the Unjangled Guardrails classifier.`), allow keeps `Unjangled Guardrails: ok, <why>
  (<stats>)`.

**The seven messages.** One guidance text per bracket family, byte-identical across hard-rule
hits, brain hits, and brain-down hits. The `(matched: …)` slot is per-trigger:

| Family | Fires on | (matched: …) clause |
|---|---|---|
| [Credential Exposure] | credential-source floor, read-path gate, agent-config gate, leak-guard bash rules, write-secret-shape, brain leak deny, brain-down fail-closed | per trigger — see below |
| [Credential Exfiltration] | the write-then-run floor | `line N reads a credential file / carries a secret-shaped value, line M sends its value over the network` |
| [Dangerous Action] | catastrophic shapes AND the brain's risk deny line | — |
| [Gate Self-Protection] | bash store/source writes AND the path guard | — |
| [Injected Instruction] | the untrusted veto | — |
| Operator rule | user lane / dir policy denies, ruling hard-blocks | — (the header's [<Family>] slot carries the ruling why) |
| No-prompt-host ask→deny | an ask on a host with no approval surface | — |

The full texts live verbatim in src/guard.js (`FAMILY_GUIDANCE` and `ASK_BLOCKED_GUIDANCE`);
docs do not duplicate them. Per-trigger matched clauses for [Credential Exposure]:

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
6. `this command modifies the gate's own policy or rulings store — operator-only (run it from your own terminal)` — bash store mutations (policy/ruling/lane CLI names, the store files, the operator escape env)
7. `this command writes the gate's own source — operator-only (run it from your own terminal; edit the checkout via the project's reviewed dev flow)` — the verb×target rule: a write shape (redirect target, in-place editor, language writer, destination copy, tee, dd) and a gate-source path sharing a command segment
8. `this file is inside the guard's own store/config/sessions — operator-only (the gate does not edit itself)` / `… — operator-only` — the path guard: Write/Edit/NotebookEdit/MCP file tools over the store, audit, policy, config, or sessions paths (layer 1 is absolute — self-mod precedent)
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

Copy-paste ruling hints ride ask messages only (ticket 7.4): the exact
`unjangled-guardrails ruling add --effect allow --pattern '<segment>' --scope 'project:<cwd>'
--reason 'operator unblock'` line(s), one per command segment, under
`Operator unblock (run in your own terminal, not here — the gate blocks agent-run ruling
changes):`. Denies never carry one. `askBlockedDeny` preserves the hint through the ask→deny
conversion on no-prompt hosts.

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
