# Vendored Secrets Guard core

Vendored **unmodified** from `~/Projects/dotfiles/secrets-guard/core/` on 2026-10-04:

- `rules.mjs` — the deterministic deny rules engine (`checkBash`, `checkRead`), copied
  byte-identical (sha256 `377e4a9c529b3fd5dfecd5db4b44cc01f2d25c929b58b63155b4c1c6e61302d9`).
- `cases.mjs` — the shared deny/allow case corpus (`bashCases` 78 rows, `readCases` 14 rows),
  copied byte-identical (sha256 `db1e1b2e3e1451bfbab6f2e4a54c2b77083c08d4dcd9ecea32d3225803fa97b0`).

Origin upstream of that: the dotfiles tree is itself the deployed source of the live
Secrets Guard hooks (`~/.claude/hooks/secrets-guard-rules.mjs`,
`~/.config/opencode/plugins/secrets-guard-rules.mjs`).

**Do not edit these files.** Any divergence from the deployed engine would break the parity
proof (`tools/parity-vendored.mjs`) and the brain-down fallback gate. Desired changes go to
the dotfiles repo first, then are re-vendored with a new hash recorded here.

Role in unjangled-guardrails (operator ruling 2026-10-04, Story 12 consolidation): the rules
engine is the **internal fallback gate** while the brain is unreachable on sole-gate hosts
(`JEV_GUARD_FALLBACK=closed`), and a **measured floor** for rule families the semantic brain
has not yet proven closed — see `docs/rules-retirement.md` and `src/orchestrate.js`.
