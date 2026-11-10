# Harness compatibility matrix (audited 2026-10-04, `7f440bf`+; ask semantics amended 2026-10-05, TR-5)

How Unjangled Guardrails composes with each harness's own systems, the
idiosyncrasies each one carries, and what was verified where. Since the
2026-10-05 adversarial remediation, an **ask on a host with no prompt surface
denies** (askBlockedDeny) instead of proceeding — see the Ask row.

| | Claude Code | OpenCode | pi | Hermes |
|---|---|---|---|---|
| Surface | PreToolUse/PostToolUse hooks (JSON on stdin) | plugin: tool.execute.before/after, permission.ask, event | extension API: pi.on("tool_call"/"tool_result") | native plugin: pre_tool_call, transform_tool_result, post_tool_call |
| Deny | `behavior:"deny"` / permissionDecision deny | thrown error (blocks tool) | `{block: true, reason}` | `{"action":"block","message"}` |
| Ask | `permissionDecision:"ask"` → their prompt | **deny (ask-blocked)** on plain tool.execute.before (TR-5); real prompt only via `permission.ask`, i.e. the tool set to "ask" in opencode.json | `ctx.ui.confirm` dialog with tier off (the default); **with a capture tier on (GUARD_PROMPT_RULINGS session/project): `ctx.ui.select` four options** (Allow once / Allow for this session / Allow always / Reject — the choice feeds prompt capture, adapter-guide §7); **headless (no UI): ask blocks** — sensible default | escalates via Hermes' approve directive to its human-approval gate **when an approver is configured** (its `approvals:` block, `GUARD_HERMES_APPROVER` override); else **denies** (TR-5; backlog bug 1 — the old silent deferral let an ask run without a person) |
| Context (user words → user_requested) | transcript_path JSONL tail | client.session.messages via SDK | sessionManager.getBranch() **+ the sub-agent context relay: children spawned by pi-subagents carry PI_SUBAGENT_ORCHESTRATOR_SESSION_ID in env, and the extension passes it as parentSessionId — the parent session's operator words (prompts bucket only) join the child's user-words lane, live and read-only, informing verdicts and minting nothing (CAP-4, adapter-guide §10); Task children on Claude Code share the parent session_id so the store is already shared; Hermes children have no parent link and keep the ruled policy mitigation** | session store fed by its own hooks |
| Tool names | PascalCase ("Bash") — lowercased on entry ✓ | lowercase ("bash") ✓ | event.toolName ✓ lowercased | arbitrary (MCP names) — own _READ_ONLY mirror set ✓ |
| Post-tool scan | PostToolUse tool_response | output.output | event.content via collectText | transform_tool_result string result ✓ |
| Env needed | hook command env (profile) | plugin host env | pi process env | GUARD_HOME + SYSTEMONE_URL in gateway env (stale path on the gateway host — parked with gateway repair) |
| Verified | live stdin simulation (ask JSON w/ new message ✓) + unit dialect tests | live all session (this agent runs under it) | static + upstream design; re-verify on next live pi session | 15/15 unit tests; live blocked by gateway outage |

Idiosyncrasies and how they're handled:
- **pi headless ask→block**: with no UI there is nobody to confirm; ask blocks rather
  than silently runs. Same philosophy as closed-mode.
- **ACP proxy ask options**: the proxy (src/acp.js) owns the
  `session/request_permission` options array, and with a capture tier on
  (GUARD_PROMPT_RULINGS session/project) it grows beyond Allow once / Reject —
  tier session adds "Allow for this session", tier project also "Allow always"
  (both ACP kind allow_always, scope named in the option; adapter-guide §7); tier
  off (the default) keeps the exact two-option shape. A cancelled or unknown
  answer is reject-once; the agent-child forge vector is bounded by the capture
  core's per-session cap, not the surface. No ACP column above: the proxy composes
  behind any ACP client (Zed, JetBrains, Paseo), so it is documented here and in
  the fleet manifest's Paseo row rather than per-client columns.
- **OpenCode ask visibility**: an ask-band call on plain tool.execute.before now
  **denies** with the ask-blocked message (toast says the knob); the operator sets the
  tool to "ask" in opencode.json to route it through `permission.ask`, where safe calls
  auto-approve and the rest get a real interactive prompt.
- **Claude transcript tail**: read-only 256KB tail of the session JSONL; tool results
  never count as user words.
- **Hermes subprocess**: node per call (~2s brain p50); every result is scanned regardless
  of length since 5.7 — no MIN_SCAN_CHARS floor (the Python mirror was removed with it), so
  the per-result cost is one classifier round-trip per tool result — except the ask-user
  family (`clarify` et al.), whose results are the operator's own words: never scanned,
  recorded into the gate's user-words store instead (entry 2).
- **Gemini/Cursor/Copilot/Codex hook dialects** ship in hook.js (unit-tested); Gemini's
  BeforeTool has no ask — an ask **denies** via askBlockedDeny (TR-5), as do Codex and
  Cursor preToolUse.

Fixes made during this audit: pi extension carried three `jev-guard:` message
prefixes and a stale load comment (now "Unjangled Guardrails:"); Hermes logger
strings lowercase-hyphen (swapped). Suites: 48/48 node, OK python.
