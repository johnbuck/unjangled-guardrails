# Publishing to the public GitHub repo

The dual-remote model, the re-cut procedure, and the residuals process. Read together with `AGENTS.md`.

## Model

| Remote | What | History |
|---|---|---|
| `origin` (Gitea, private) | The working repo: full history, `evidence/`, `_bmad-output/`, internal references, homelab specifics | continuous, never rewritten |
| `github` (GitHub, public) | Clean cuts of the product: code, docs, vendor cores — no homelab topology, no operator-internal detail | one squash-like cut commit per release; **never** a push of private history |

The public repo exists for the stranger (see the product brief's success criteria): everything a competent homelab operator needs to install the gate against their own brain, and nothing about ours. Test: *would this line work on a stranger's laptop with no knowledge of our homelab?* If not, it does not ship.

## Re-cut procedure (run from a clean private main)

1. **Prepare.** `git -C <private> fetch origin && git checkout main && git pull`. Confirm suites green (`node --test test/`, python adapter suite, parity tools).
2. **Cut.** Create the public tree: `git checkout -B public-cut` from main, then remove or scrub private-only content: `_bmad-output/` (internal), private evidence with homelab detail (per the scan below), and any file on the residuals list marked *genericize* rather than *accept*.
3. **Scrub.** Sweep the cut for the scan terms (below). Replace internals with generic names (`the local shim host`, `your Gitea`) or delete. The README on the cut must carry the **public install table**: clone-from-GitHub instructions, the upstream-npm warning, and no reference to our Gitea.
4. **Scan gate.** Run the leak scan across the cut tree (the terms below), then the executable gate: `node tools/topology-rules.mjs --scan-tree` (see "Operator topology config" below). Expected result: zero hits outside the accepted-residuals allowlist; the command exits 0 only then. Any new hit is either scrubbed or goes through the residuals process — never waved through.
4b. **Orphanize.** The cut must be a SINGLE-ROOT commit — a normal commit on a branch of private main would ship the entire private lineage to github (this happened once, 2026-10-08, and was force-replaced the same day). After committing the scrubbed tree: `git checkout --orphan cut-root && git commit -m "chore: public cut <date> from private <short-sha>" && git branch -D public-cut && git branch -m public-cut`. Before pushing, assert `git rev-list --count HEAD` prints `1`. Never push a cut whose history count is anything else.
5. **Commit and push.** `git commit -m "chore: public re-cut <date> from private <short-sha>"` on the cut branch, then `git push github HEAD:main --force-with-lease` — this is the ONLY sanctioned `git push github` invocation, and only from the cut branch, never from private main. The push will be non-fast-forward against the previous release's lineage; that is the model (one replacement cut per release), and `--force-with-lease` is what makes it safe — it fails if anything landed on public main since your last fetch. Building the cut in a temporary worktree (`git worktree add <dir> && git -C <dir> checkout -b public-cut <sha>`) is an approved variant when the shared checkout has a concurrent session in it.
6. **Record** (private repo only). Append the publish record to the BMAD publish record (`_bmad-output/initiative-v1-harden-share/epic-public-publish/publish-record.md` — a private-side path, not present on the public tree): date, source sha, publish sha, scan result, decisions made.

## Scan terms

RFC1918 ranges, the Tailscale CGNAT range, hostname-shaped `.lan`/`.local` names, homelab hostnames and usernames (from your operator config), private service domains, fleet aliases, the shim port, Infisical project names, and every secret shape (`sk-`-class, `ghp_`, `AKIA`, `vck_`, `xai-`).

## Operator topology config

`tools/topology-rules.mjs` is the single source for the no-topology families, and the executable form of the scan terms above. Two layers:

- **Universal families (built in, always enforced):** RFC1918 addresses, Tailscale CGNAT addresses, hostname-shaped `.lan`/`.local` names, and secret-shaped tokens (`sk-`-class, `ghp_`, `AKIA`, `vck_`, `xai-`).
- **Operator values (gitignored local config):** real hostnames, usernames, private URL fragments, and ports live in `.githooks/topology.local.mjs` — never in any tracked file. The tracked tree, and every public cut of it, stays free of operator topology by construction.

Setup, once per checkout:

1. `git config core.hooksPath .githooks` — arms the pre-commit topology guard.
2. `node tools/topology-rules.mjs --init` — scaffolds the operator config (the file is gitignored and never commits).
3. Fill the scaffold's patterns in with real values, then `node tools/topology-rules.mjs --status` — prints configured families and names what is unchecked.

Enforcement shape: the pre-commit hook scans **staged added lines only** (`git diff --cached -U0`), so pre-existing topology in untouched files never blocks unrelated commits, and deletions never block. `evidence/**` and `_bmad-output/**` are exempt — the two sanctioned homes for internal specifics, both excluded from every public cut. Block messages name file, line, and pattern family; they never echo the matched text. A missing operator config still enforces the universal families and says so when a block fires; a broken one fails closed.

`--scan-tree` (no arguments: every git-tracked file) is the runbook gate in step 4 above: it exits non-zero on any non-exempt hit. The `RESIDUALS` array in `tools/topology-rules.mjs` mirrors the "Accepted residuals" record below entry for entry — the two lists move together, every entry dated, dispositioned, and reasoned, and operator values appear in neither. The pins are structural (line shapes), so value-level acceptances (the battery fixture path, the SemIf/Ornith project names) are carried by this record and the operator config rather than by named module pins; if an operator family that would match them is ever configured, add the pin in the same commit as the config change. On divergence, fix both in one commit.

## Accepted residuals

Each item below is deliberately present — on the private tree always, and on the public tree where marked **keep public** — with its line shape, date, disposition, and reason. This record mirrors the `RESIDUALS` array in `tools/topology-rules.mjs` entry for entry; change both in one commit.

| Path | Accepted lines | Date | Disposition | Reason |
|---|---|---|---|---|
| `docs/publishing.md` | scan-terms inventory (names the families it guards) | 2026-10-07 | private-side; genericize at cut | the process doc must name its threat families; on public cuts the named hostnames become generic labels |
| `AGENTS.md` | origin-remote line + the rule paragraph naming the private host domain | 2026-10-07 | private-side; genericize at cut | system-of-record agent rules; scrubbed on public cuts |
| `test/topology-rules.test.js` | lines marked "canary" | 2026-10-07 | **keep public** | documented fake canaries exercising the universal families on purpose |
| `test/local.test.js` | local-backend fixtures naming the shim port on generic/operator hosts | 2026-10-07 | private-side; genericize at cut | fixtures must hit a local shim; the cut ships loopback equivalents |
| `tools/battery.mjs` | safe-case battery row curling the operator shim | 2026-10-07 | private-side; genericize at cut | battery evidence runs against the operator's real shim |
| `tools/demo-dryrun.mjs` | degraded-mode demo pointing at a dead shim address | 2026-10-07 | private-side; genericize at cut | the demo needs a guaranteed-dead address |
| `tools/battery-secrets.mjs` | synthetic secret-shaped fixtures (`sk-`-class bodies, `~/.config/gitea/credentials` path) | 2026-10-07 | **keep public — ACCEPTED 2026-10-08** | names the software category, not any host or network; bodies are synthetic; genericizing would desync the battery from the vendored case set |
| `package.json`, `plugin.json`, `gemini-extension.json`, `*marketplace.json` | metadata fields naming the private origin and homelab brand | 2026-10-07 | private-side; genericize at cut | metadata points somewhere real on the private side |
| `plugins/unjangled-guardrails/**` | install notes naming operator hosts, shim port, key locations | 2026-10-07 | private-side; genericize at cut | operator install notes; strangers get the generic install table |
| `README.md` | example env line naming the shim port on a generic placeholder host | 2026-10-07 | private-side; genericize at cut | host is already a generic placeholder |
| `VENDORED.md` | provenance notes naming the brain project and operator hosts | 2026-10-07 | private-side; genericize at cut | fork provenance; internal project names (SemIf, Ornith) accepted as non-identifying |
| `CHANGELOG-fork.md` | entire file (path-level) | 2026-10-07 | private-side; excluded at cut | append-only fork history saturated with pre-existing identifiers; history is never rewritten |
| `.specify/**` | entire tree (path-level) | 2026-10-07 | private-side; excluded at cut | binding operator-ruling and planning history; append-only per AGENTS.md |

Delegated calls, recorded 2026-10-08 on the operator's standing instruction to finish the epic and revisitable at any time: the `battery-secrets` fixture is **ACCEPTED** (keep public, reason above — genericizing would break battery parity with the vendored cases); SemIf and Ornith project names are **ACCEPTED** (internal project names, non-identifying; first recorded 2026-10-06).

## History

- 2026-10-06 — first clean cut `ccaffd8` shipped to github.com/johnbuck/unjangled-guardrails (one-off, performed with a topology audit; 17 lines scrubbed). Known gap at cut time: the public README's install table still carried upstream marketplace commands; corrected in the follow-up public patch.
