# AGENTS.md — unjangled-guardrails

Working rules for any agent (or human) committing in this repository. Read before your first commit.

## Operational notice — brain key (2026-10-12, current)

The brain API key is managed in Infisical (secret `SYSTEM_ONE_API_KEY`, Homelab project). If your session sees "brain unreachable" or HTTP 403 on brain calls, that is a stale or missing key — **the brain is up**; do not report it as downtime. Restore in one command from the repo root:

```
bash scripts/restore-brain-key.sh 48c69815-4553-4588-bb45-06cdfc3767c3
```

The gate's own chain: the key value never appears in argv, output, or any file it shouldn't. If the credential floor blocks that shape, the restore is operator-terminal-only — say so to the operator and continue degraded. Gotcha: a `SYSTEMONE_URL`/`JEV_BASE_URL` env var **shadows** the config file — an env-carried URL without the matching key stays degraded even after a config restore; carry the key alongside it (`JEV_API_KEY_LOCAL`) or drop the env URL. Verify with `node src/cli.js calibrate` (green-or-pending is a pass).

## Repository model — two remotes, two different trees

- **`origin` — private Gitea** (address genericized on public cuts; the system of record: full history, `evidence/`, `_bmad-output/`, internal references). Default push target.
- **`github` — public GitHub** (`github.com/johnbuck/unjangled-guardrails`). Receives **clean cuts only**: scrubbed trees built by the re-cut procedure in `docs/publishing.md`. The private history NEVER goes to `github`. Public cuts carry no homelab topology and no operator-internal detail.

**Push discipline.** `git push` (no args) pushes private main to `origin` — keep it that way. NEVER `git push github` from private main. Public updates happen only through the re-cut procedure, run deliberately, with the leak scan green (see `docs/publishing.md`). If you are about to type `git push github`, stop and re-read that document first.

## The no-topology rule (binding)

No RFC1918 addresses, no `.lan`/`.local`/homelab hostnames, no homelab usernames, no private-host URLs, and no secret values may enter any tracked file destined for the public tree — and where possible, not new private-side content either (prefer generic names in code comments; `evidence/` is the sanctioned home for internal specifics). Exception: files listed in the accepted-residuals allowlist maintained with `docs/publishing.md`, each carrying a dated accepted-with-reason record.

**Enforcement.** `git config core.hooksPath .githooks`, then `node tools/topology-rules.mjs --init` (config is gitignored and never commits). The pre-commit hook blocks staged added lines matching the rule; `evidence/` and `_bmad-output/` are exempt; the families and the residuals process live in `docs/publishing.md` ("Operator topology config").

## Working conventions

- The gate hardens itself: expect it to deny commands whose text contains dangerous patterns — route payload strings through files written with file tools, never heredocs.
- Atomic commits per logical change; push to `origin` after each; concurrent sessions may commit here — never revert another session's work, commit around it.
- Evidence discipline: claims ship with artifacts (`evidence/`, batteries, registers). No claim without its artifact.
- Operator rulings recorded in `.specify/` and the `_bmad-output/` memlogs are binding history — append, never rewrite.
