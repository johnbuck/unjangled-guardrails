# Fleet manifest

The authoritative inventory of harness surfaces the gate targets (spec CAP-4). Every entry is
gated and live-verified, or carries its documented exception. Evidence pointers are relative to
`evidence/`. Status vocabulary: **gated+verified** (registered, probes passed through the
registered surface), **gated** (registered, live verification pending), **external-by-choice**
(deliberately ungated, reason recorded), **blocked-external** (requires hardware or access this
install does not control).

| # | Harness surface | Install surface | Status | Evidence |
|---|---|---|---|---|
| 1 | Claude Code (CLI hook) | this install | gated+verified | live-verify-claude-2026-10-07.jsonl, live-verify-claude-2026-10-09.jsonl, live-verify-claude-2026-10-12.jsonl |
| 2 | OpenCode v1 plugin | this install | gated+verified | live-verify-opencode-2026-10-07.jsonl; rules-verification-2026-10-13.md |
| 3 | OpenCode v2 adapter | this install | gated+verified | opencode-v2-gating-probe-2026-10-09.md, opencode-v2-hook-semantics-probe-2026-10-09.md, opencode-v2-evaluate-probe-2026-10-11.md, installer ticket-6 container proof |
| 4 | pi extension | this install | gated+verified | live-verify-pi-2026-10-07.jsonl |
| 5 | Paseo-hosted ACP sessions (orchestrator + workers) | this install | gated+verified | live-verify-opencode-paseo-2026-10-07.md; opencode-v2-dual-entry-probe-2026-10-08.md |
| 6 | Persona containers (6, fleet wiring) | fleet containers | gated+verified (in-container) | fleet-brain-key-wiring-2026-10-11.md: key present, cred-read offline deny, real-brain assess answered per container; stranger-run-2026-10-12 (clean-container install) |
| 7 | Hermes | fleet, behind gateway | blocked-external (gateway repair prerequisite, recorded epic-installer history) | hermes env-passthrough gaps: live-verify-hermes-bug1-2026-10-08.md |
| 8 | Fleet Macs (legacy-layer cutover) | fleet hardware | gated+verified (v1 generation; offline-rules floor until brain reach lands) | fleet-cutover-2026-10-15.md |
| 9 | Gemini CLI / Codex / Cursor / Copilot CLI dialects | adapter-supported, not installed here | external-by-choice | hook dialects pinned by test/hook.test.js; adapters ship, install is per-operator |

## Scheduled rows

- M7 fleet version skew (Paseo layer build + secrets-guard vintage): resolved for the v2
  adapter surface by the opencode-v2-adapter lands (2026-10-11/12); the persona containers'
  vintage is tracked by the fleet wiring record — re-verified per container on update.
- Published-cut lag (stranger-run finding 6): the public cut carries older readiness behavior;
  publish cadence is a publishing-epic concern, not a gating gap.
- Brain reach from fleet hosts (2026-10-15): the persona containers AND both fleet Macs
  score 000 against the brain URL while the M7 host itself reaches it — source-IP egress
  filtering at the brain host; repair owned by the concurrent session
  (hermes-brain-reach-2026-10-15.md). Semantic review goes live per surface when it opens.

## Rules of this manifest

- An entry moves to gated+verified only with a live probe through the REGISTERED surface
  (safe passes, known deny stops), recorded as evidence.
- De-identity applies to every row: no hostname, key value, or topology in this file —
  evidence files carry status words and counts only.
- Additions require an epic-level decision row; removals require a dated Decision line.
