# Vendored: jev-guard (2026-09-25)

For Themis's assignment: stand up jev-guard (the Jev-style auto-mode gate).

| | |
|---|---|
| Source | github.com/leepokai/jev-guard |
| Commit | `489f528` (2026-09-25) — same-day active |
| License | MIT (verify LICENSE file at build time) |
| Size after prune | 7.0 MB |
| Pruned | `.git/` |
| Role | Multi-harness security gate: pre-tool Jev-style questions (risk/approval/from_untrusted) → deny/ask/allow; post-tool injection+canary scanning; skill/plugin load-time scanning. Adapters: Claude Code, Codex, Copilot CLI, Gemini CLI, Cursor, pi, OpenCode, ACP/Zed. Hermes adapter = the new work. |

## Audit record (2026-09-25)

Single network/exec signal in `src/`: `child_process.spawn` imported in `src/acp.js` — the ACP adapter doing its documented job (spawning hooks). No beacons, no telemetry, no obfuscation. The mp3/svg payloads are UI assets. Known from Lily's research: backend URLs are hardcoded to typesafe/vercel with no base-url override — the fork adds a backend kind/env for our local Jev-class brain.

## Backend brain (operator rulings, 2026-09-22)

The brain is **SemIf's pinned Qwen3.5-4B** (no Ornith, no untested models). SemIf runs CPU-only (Jev-compatible `/v1/systemone` shim; complete API contract in its PILOT.md). jev-guard's fork speaks to that. Lily's handoff (`backlog/2026-09-21-jev-auto-mode-gate-research.md`) has the full design: fork `src/jev.js` → new backend kind; thresholds tuned on our traffic, fail-closed in the middle band.
