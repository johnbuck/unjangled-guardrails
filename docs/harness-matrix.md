# Harness compatibility matrix (audited 2026-10-04, `7f440bf`+; ask semantics amended 2026-10-05, TR-5)

How Unjangled Guardrails composes with each harness's own systems, the
idiosyncrasies each one carries, and what was verified where. Since the
2026-10-05 adversarial remediation, an **ask on a host with no prompt surface
denies** (askBlockedDeny) instead of proceeding — see the Ask row.

| | Claude Code | OpenCode | pi | Hermes |
|---|---|---|---|---|
| Surface | PreToolUse/PostToolUse hooks (JSON on stdin) | plugin: tool.execute.before/after, permission.ask, event | extension API: pi.on("tool_call"/"tool_result") | native plugin: pre_tool_call, transform_tool_result, post_tool_call |
| Deny | `behavior:"deny"` / permissionDecision deny | thrown error (blocks tool) | `{block: true, reason}` | `{"action":"block","message"}` |
| Ask | `permissionDecision:"ask"` → their prompt | **deny (ask-blocked)** on plain tool.execute.before (TR-5); real prompt only via `permission.ask`, i.e. the tool set to "ask" in opencode.json | `ctx.ui.confirm` dialog; **headless (no UI): ask blocks** — sensible default | escalates via Hermes' approve directive to its human-approval gate **when an approver is configured** (its `approvals:` block, `GUARD_HERMES_APPROVER` override); else **denies** (TR-5; backlog bug 1 — the old silent deferral let an ask run without a person) |
| Context (user words → user_requested) | transcript_path JSONL tail | client.session.messages via SDK | sessionManager.getBranch() | session store fed by its own hooks |
| Tool names | PascalCase ("Bash") — lowercased on entry ✓ | lowercase ("bash") ✓ | event.toolName ✓ lowercased | arbitrary (MCP names) — own _READ_ONLY mirror set ✓ |
| Post-tool scan | PostToolUse tool_response | output.output | event.content via collectText | transform_tool_result string result ✓ |
| Env needed | hook command env (profile) | plugin host env | pi process env | GUARD_HOME + SYSTEMONE_URL in gateway env (STALE PATH on themis — parked with gateway repair) |
| Verified | live stdin simulation (ask JSON w/ new message ✓) + unit dialect tests | live all session (this agent runs under it) | static + upstream design; re-verify on next live pi session | 15/15 unit tests; live blocked by gateway outage |

Idiosyncrasies and how they're handled:
- **pi headless ask→block**: with no UI there is nobody to confirm; ask blocks rather
  than silently runs. Same philosophy as closed-mode.
- **OpenCode ask visibility**: an ask-band call on plain tool.execute.before now
  **denies** with the ask-blocked message (toast says the knob); the operator sets the
  tool to "ask" in opencode.json to route it through `permission.ask`, where safe calls
  auto-approve and the rest get a real interactive prompt.
- **Claude transcript tail**: read-only 256KB tail of the session JSONL; tool results
  never count as user words.
- **Hermes subprocess**: node per call (~2s brain p50); result strings under 200 chars
  skip the scan (MIN_SCAN_CHARS mirror in Python).
- **Gemini/Cursor/Copilot/Codex hook dialects** ship in hook.js (unit-tested); Gemini's
  BeforeTool has no ask — an ask **denies** via askBlockedDeny (TR-5), as do Codex and
  Cursor preToolUse.

Fixes made during this audit: pi extension carried three `jev-guard:` message
prefixes and a stale load comment (now "Unjangled Guardrails:"); Hermes logger
strings lowercase-hyphen (swapped). Suites: 48/48 node, OK python.
