# AGENTS.md — unjangled-guardrails

Working rules for any agent (or human) committing in this repository. Read before your first commit.

## Repository model — two remotes, two different trees

- **`origin` — private Gitea** (system of record; internal). The system of record: full history, `evidence/`, `_bmad-output/`, internal references. Default push target.
- **`github` — public GitHub** (`github.com/johnbuck/unjangled-guardrails`). Receives **clean cuts only**: scrubbed trees built by the re-cut procedure in `docs/publishing.md`. The private history NEVER goes to `github`. Public cuts carry no homelab topology and no operator-internal detail.

**Push discipline.** `git push` (no args) pushes private main to `origin` — keep it that way. NEVER `git push github` from private main. Public updates happen only through the re-cut procedure, run deliberately, with the leak scan green (see `docs/publishing.md`). If you are about to type `git push github`, stop and re-read that document first.

## The no-topology rule (binding)

No RFC1918 addresses, no `.lan`/`.local`/homelab hostnames, no homelab usernames, no private service URLs, and no secret values may enter any tracked file destined for the public tree — and where possible, not new private-side content either (prefer generic names in code comments; `evidence/` is the sanctioned home for internal specifics). Exception: files listed in the accepted-residuals allowlist maintained with `docs/publishing.md`, each carrying a dated accepted-with-reason record.

**Enforcement.** `git config core.hooksPath .githooks`, then `node tools/topology-rules.mjs --init` (config is gitignored and never commits). The pre-commit hook blocks staged added lines matching the rule; `evidence/` and `_bmad-output/` are exempt; the families and the residuals process live in `docs/publishing.md` ("Operator topology config").

## Working conventions

- The gate hardens itself: expect it to deny commands whose text contains dangerous patterns — route payload strings through files written with file tools, never heredocs.
- Atomic commits per logical change; push to `origin` after each; concurrent sessions may commit here — never revert another session's work, commit around it.
- Evidence discipline: claims ship with artifacts (`evidence/`, batteries, registers). No claim without its artifact.
- Operator rulings recorded in `.specify/` and the `_bmad-output/` memlogs are binding history — append, never rewrite.
