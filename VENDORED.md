# Vendored: jev-guard (2026-09-25)

For the operator's assignment: stand up jev-guard (the Jev-style auto-mode gate).

| | |
|---|---|
| Source | github.com/leepokai/jev-guard |
| Commit | `489f528` (2026-09-25) — same-day active |
| License | MIT (verify LICENSE file at build time) |
| Size after prune | 7.0 MB |
| Pruned | `.git/` |
| Role | Multi-harness security gate: pre-tool Jev-style questions (risk/approval/from_untrusted) → deny/ask/allow; post-tool injection+canary scanning; skill/plugin load-time scanning. Adapters: Claude Code, Codex, Copilot CLI, Gemini CLI, Cursor, pi, OpenCode, ACP/Zed. Hermes adapter = the new work. |

## Audit record (2026-09-25)

Single network/exec signal in `src/`: `child_process.spawn` imported in `src/acp.js` — the ACP adapter doing its documented job (spawning hooks). No beacons, no telemetry, no obfuscation. The mp3/svg payloads are UI assets. Known from the pre-fork research pass: backend URLs are hardcoded to typesafe/vercel with no base-url override — the fork adds a backend kind/env for our local Jev-class brain.

## Consolidation provenance (2026-10-20)

The consolidation (plan-consolidation-two-layers) made both cores the single sources of truth
for layer 1 of the gate: `src/always-deny.js` imports checkBash/checkRead/isSecretFile from
secrets-guard-core and CATASTROPHIC/checkCatastrophic/SECRET_SHAPE from guardrails-core.
Nothing re-implements a vendored regex; the cores stay UNTOUCHED as vendored sources. Provenance
discipline carried through: both attributed, MIT-compatible, upstream-identifiable. The guard
that never touches them: `git status --short vendor/` must stay empty in every commit.

## Backend brain (operator rulings, 2026-09-22)

The brain is **SemIf's pinned Qwen3.5-4B** (no Ornith, no untested models). SemIf runs CPU-only (Jev-compatible `/v1/systemone` brain service; the deployment record lives in the operator's evidence tree). jev-guard's fork speaks to that. The pre-fork research pass holds the full design: fork `src/jev.js` → new backend kind; thresholds tuned on our traffic, fail-closed in the middle band.
