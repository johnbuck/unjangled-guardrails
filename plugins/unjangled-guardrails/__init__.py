"""unjangled-guardrails — Hermes adapter for the unjangled-guardrails auto-mode gate.

Wires three behaviours (all judgment delegated to the unjangled-guardrails fork via
`node <GUARD_HOME>/src/cli.js hook --agent hermes`; this plugin implements
NO policy of its own):

* ``pre_tool_call``      — runs the guard's PreToolUse assessment. ``deny``
                           blocks the tool call ({"action": "block", ...}).
                           ``ask`` escalates: with an approval flow configured
                           (its ``approvals:`` config block, mode not off —
                           GUARD_HERMES_APPROVER overrides the detection) the
                           plugin returns Hermes's approve directive
                           ({"action": "approve", "message": reason}), which
                           routes the call to Hermes's human-approval gate, so it
                           runs only after a person approves it; without an
                           approver the hook itself answers deny with the
                           ask-blocked message (the decision goes through the
                           user in conversation), and a stray ask is denied here
                           too. ``allow`` returns None.
* ``transform_tool_result`` — runs the PostToolUse scan; when content is flagged
                           as AI-directed (injection/canary), the unjangled-guardrails
                           warning is PREPENDED to the result string the model
                           sees, mirroring the OpenCode adapter.
* ``post_tool_call``     — observer only (logging); unjangled-guardrails's own session
                           memory (its JSON session store) is authoritative.

Failure semantics: node missing, spawn errors, timeouts, and non-JSON output are
all one failure class decided by GUARD_FAIL_CLOSED — block with a reason
(fail-closed) or log-and-pass (fail-open, upstream unjangled-guardrails default).

Environment:
  GUARD_HOME            fork root (contains src/cli.js). Required — no default
                        guess; unset disables the plugin with one warning.
  SYSTEMONE_URL         local backend URL, e.g. http://your-shim:8090
  SYSTEMONE_KEY         optional bearer key for the local backend
  SYSTEMONE_MODEL       model alias override (unset -> the shim's SYSTEM_ONE_DEFAULT_MODEL answers)
  GUARD_FAIL_CLOSED     when set: backend-down blocks instead of passes
  GUARD_TIMEOUT_MS      passed through; spawn timeout clamped to <= 25s
  GUARD_MAX_STATE_CHARS scan-content budget (SemIf deployments: ~12000)

Back-compat (operator ruling 2026-10-07): every pre-rename JEV_* spelling still
works and is read after the new name (JEV_GUARD_HOME, JEV_BASE_URL, JEV_API_KEY_LOCAL,
JEV_MODEL, JEV_GUARD_FAIL_CLOSED, …).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_HOOK_TIMEOUT_S = 25.0

# Hermes tool names the core skips brain-side anyway (READ_ONLY ∪ Hermes aliases, src/orchestrate.js);
# checking locally avoids a pointless node spawn. The read-path names the core's read-path gate
# judges offline (read, view, cat, read_file, read_many_files) are deliberately absent: a local
# skip here used to let a credential-file read through Hermes's own read tool unjudged (backlog
# bug 1). Anything NOT here is assessed by the hook.
_READ_ONLY = frozenset({
    "glob", "grep", "ls", "list", "find", "webfetch", "websearch",
    "todowrite", "todoread", "askuserquestion", "exitplanmode", "notebookread",
    "listmcpresourcestool", "readmcpresourcetool", "toolsearch", "skill", "task",
    "agent", "read_page", "get_page_text",
    "list_directory", "search_file_content", "grep_search", "google_web_search",
    "web_fetch", "write_todos", "search_files", "web_search", "web_extract",
    "session_search", "skill_view", "skills_list", "todo", "vision_analyze",
    "delegate_task",
})

# Result text of these tools is local by construction — no external content to
# scan (mirrors unjangled-guardrails's NEVER_EXTERNAL + Hermes aliases).
_NEVER_EXTERNAL = frozenset({
    "edit", "write", "multiedit", "notebookedit", "apply_patch", "patch",
    "delete", "glob", "grep", "ls", "list", "find", "todowrite", "todoread",
    "askuserquestion", "exitplanmode", "write_file", "replace", "write_todos",
    "search_files", "session_search", "skill_view", "skills_list", "todo",
    "vision_analyze",
})

_PASSTHROUGH_ENV = (
    # New names (operator ruling 2026-10-07)…
    "SYSTEMONE_URL", "SYSTEMONE_KEY", "SYSTEMONE_MODEL", "GUARD_FAIL_CLOSED",
    "GUARD_TIMEOUT_MS", "GUARD_MAX_STATE_CHARS", "GUARD_DENY_SCORE",
    "GUARD_ASK_SCORE", "GUARD_ASK_P", "GUARD_INJECT_P",
    "GUARD_UNTRUSTED_P", "GUARD_USER_P", "GUARD_SKILL_P",
    "GUARD_SKILL_SERIOUS_P", "GUARD_SKIP_TOOLS", "GUARD_SKIP_SCAN",
    "GUARD_SESSIONS", "GUARD_SCAN_CACHE", "GUARD_CONFIG",
    "GUARD_HERMES_APPROVER",
    # M3 (TR-6): the subprocess must see the same policy env as the operator CLI —
    # the store home, the fallback posture, and the leak threshold. Omitting the home
    # used to split the brain: the child resolved the store while the CLI used another.
    "GUARD_HOME", "GUARD_FALLBACK", "GUARD_LEAK_P",
    # …and the pre-rename spellings, which the hook still honours via back-compat,
    # so a deployed config that sets only the old names keeps working.
    "JEV_BASE_URL", "JEV_API_KEY_LOCAL", "JEV_MODEL", "JEV_GUARD_FAIL_CLOSED",
    "JEV_GUARD_TIMEOUT_MS", "JEV_GUARD_MAX_STATE_CHARS", "JEV_GUARD_DENY_SCORE",
    "JEV_GUARD_ASK_SCORE", "JEV_GUARD_ASK_P", "JEV_GUARD_INJECT_P",
    "JEV_GUARD_UNTRUSTED_P", "JEV_GUARD_USER_P", "JEV_GUARD_SKILL_P",
    "JEV_GUARD_SKILL_SERIOUS_P", "JEV_GUARD_SKIP_TOOLS", "JEV_GUARD_SKIP_SCAN",
    "JEV_GUARD_SESSIONS", "JEV_GUARD_SCAN_CACHE", "JEV_GUARD_CONFIG",
    "JEV_GUARD_HERMES_APPROVER", "JEV_GUARD_HOME", "JEV_GUARD_FALLBACK",
    "JEV_GUARD_LEAK_P",
    "PATH", "HOME",
)

# Pre-rename names of every renamed variable: _getenv falls back to these
# (operator ruling 2026-10-07 — the rename must not break deployed configs).
_LEGACY_ENV = {
    "SYSTEMONE_URL": "JEV_BASE_URL",
    "SYSTEMONE_KEY": "JEV_API_KEY_LOCAL",
    "SYSTEMONE_MODEL": "JEV_MODEL",
    **{f"GUARD_{n}": f"JEV_GUARD_{n}" for n in (
        "FAIL_CLOSED", "TIMEOUT_MS", "MAX_STATE_CHARS", "DENY_SCORE", "ASK_SCORE",
        "ASK_P", "INJECT_P", "UNTRUSTED_P", "USER_P", "SKILL_P", "SKILL_SERIOUS_P",
        "SKIP_TOOLS", "SKIP_SCAN", "SESSIONS", "SCAN_CACHE", "CONFIG",
        "HERMES_APPROVER", "HOME", "FALLBACK", "LEAK_P", "OPERATOR_CLI",
    )},
}


def _getenv(name: str, default: str = "") -> str:
    """Read a policy env var: new name first, pre-rename JEV_* spelling as fallback."""
    v = os.environ.get(name)
    if v not in (None, ""):
        return v
    return os.environ.get(_LEGACY_ENV.get(name, name), default)


def _guard_home() -> Optional[str]:
    home = _getenv("GUARD_HOME").strip()
    if not home:
        return None
    return home if os.path.isfile(os.path.join(home, "src", "cli.js")) else None


def _node() -> Optional[str]:
    return shutil.which("node")


def _fail_closed() -> bool:
    # One truthiness parser for the fail-closed flag (M4/TR-6), matching the JS
    # failClosed() in src/orchestrate.js: "1"/"true" (any case) close; "0"/"false"/unset stay
    # open — bool("0") used to close! — and any other spelling is ambiguous and closes.
    v = _getenv("GUARD_FAIL_CLOSED").strip().lower()
    return not (v == "" or v == "0" or v == "false")


# Modes of Hermes' `approvals.mode` that mean no approval prompt exists (YAML 1.1 parses bare
# off/yes/no as booleans, so the false-y spellings all count).
_APPROVALS_OFF = frozenset({"off", "false", "none", "no", "0", "yolo"})


def _approver_configured() -> bool:
    """TR-5: does this Hermes have an approval flow to escalate asks to?

    Hermes gates its dangerous-command approval prompts on the top-level ``approvals:`` block of
    its own config (``mode: manual`` by default; ``mode: off`` disables them). The block is looked
    up in $HERMES_CONFIG, then ~/.hermes/config.yaml, then the container's /opt/data/config.yaml.
    GUARD_HERMES_APPROVER overrides the detection; no config at all means no approver.
    """
    override = _getenv("GUARD_HERMES_APPROVER").strip().lower()
    if override:
        return override not in ("0", "false", "no", "off")
    candidates = [
        os.environ.get("HERMES_CONFIG", ""),
        os.path.join(os.path.expanduser("~"), ".hermes", "config.yaml"),
        "/opt/data/config.yaml",  # the harness data dir's path inside its container
    ]
    for path in [p for p in candidates if p]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        # the indented body ends at the first unindented line, so nested mode: keys elsewhere stay out
        block = re.search(r"(?ms)^approvals:[ \t]*(?:#.*)?\n((?:[ \t]+[^\n]*\n?)*)", text)
        if not block:
            continue
        mode = re.search(r"(?m)^[ \t]+mode:[ \t]*\"?'?([^\"'\n#]*?)\"?'?[ \t]*(?:#.*)?$", block.group(1))
        if not mode:
            return True  # approvals block present, no mode key: Hermes prompts by default
        return mode.group(1).strip().lower() not in _APPROVALS_OFF
    return False


def _spawn_env() -> Dict[str, str]:
    env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}
    env["GUARD_NO_INSTALL_HINT"] = "1"
    # TR-5: tell the hook whether an approver exists — it answers ask only then, and deny (with
    # the ask-blocked message) otherwise, so the message prose lives in one place (src/guard.js).
    if _approver_configured():
        env["GUARD_HERMES_APPROVER"] = "1"
    else:
        env.pop("GUARD_HERMES_APPROVER", None)
        env.pop("JEV_GUARD_HERMES_APPROVER", None)  # stale parent-set legacy spelling must not leak in
    return env


def _run_hook(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Run `node cli.js hook --agent hermes` with a Claude-shaped payload.

    Returns the parsed stdout JSON, None for empty stdout (= allow/no opinion),
    or raises _GuardError on any failure (missing node/home, timeout, bad JSON).
    """
    home = _guard_home()
    if not home:
        raise _GuardError("GUARD_HOME unset or does not contain src/cli.js")
    node = _node()
    if not node:
        raise _GuardError("node binary not found on PATH")
    try:
        timeout_ms = int(float(_getenv("GUARD_TIMEOUT_MS", "20000")))
    except ValueError:
        timeout_ms = 20000
    timeout_s = min(max(timeout_ms / 1000.0, 1.0), _HOOK_TIMEOUT_S)
    try:
        proc = subprocess.run(
            [node, os.path.join(home, "src", "cli.js"), "hook", "--agent", "hermes"],
            input=json.dumps(payload).encode(),
            capture_output=True,
            timeout=timeout_s,
            env=_spawn_env(),
        )
    except subprocess.TimeoutExpired:
        raise _GuardError(f"unjangled-guardrails hook timed out after {timeout_s:.0f}s")
    except OSError as exc:
        raise _GuardError(f"failed to spawn node: {exc}")
    out = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        detail = (proc.stderr.decode("utf-8", "replace").strip() or out or f"exit {proc.returncode}").splitlines()[-1][:300]
        raise _GuardError(f"unjangled-guardrails hook failed: {detail}")
    if not out:
        return None  # upstream hook prints nothing for allow
    try:
        parsed = json.loads(out)
    except ValueError:
        raise _GuardError(f"unparseable hook output: {out[:200]!r}")
    return parsed if isinstance(parsed, dict) else None


class _GuardError(Exception):
    pass


def _pre_tool_call(tool_name: str = "", args: Optional[Dict[str, Any]] = None,
                   session_id: str = "", **_: Any) -> Optional[Dict[str, str]]:
    name = (tool_name or "").lower()
    if name in _READ_ONLY:
        return None
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": args if isinstance(args, dict) else {},
        "cwd": os.getcwd(),
    }
    if session_id:
        payload["session_id"] = session_id
    try:
        out = _run_hook(payload)
    except _GuardError as exc:
        if _fail_closed():
            return {"action": "block", "message": f"Unjangled Guardrails unavailable ({exc}); failing closed. Fix the backend or unset GUARD_FAIL_CLOSED to pass on failure."}
        logger.warning("Unjangled Guardrails: %s; passing (fail-open)", exc)
        return None
    if not out:
        return None
    decision = (out.get("hookSpecificOutput") or {}).get("permissionDecision") or out.get("permissionDecision")
    reason = (out.get("hookSpecificOutput") or {}).get("permissionDecisionReason") or out.get("permissionDecisionReason") or ""
    if decision == "deny":
        return {"action": "block", "message": reason or "unjangled-guardrails denied this tool call"}
    if decision == "ask":
        # With no approver configured the hook itself answers deny (GUARD_HERMES_APPROVER is
        # unset in the spawn env), so this branch only fires when one exists — or, belt-and-braces,
        # if the two checks ever desync. Either way an ask without an approver must not pass.
        if _approver_configured():
            # An ask must reach a person. Hermes's approve directive escalates the call to its
            # human-approval gate (hermes agent/shell_hooks.py: block > approve > none), so the
            # call runs only after a person approves. Silently deferring (returning None) used
            # to let it run unapproved — Hermes's own dangerous-command detector only flags the
            # calls its own rules match, which is not the gate's ask band (backlog bug 1).
            logger.info("unjangled-guardrails: ask on %s — escalating to Hermes approval gate: %s", tool_name, reason)
            return {"action": "approve", "message": reason}
        return {"action": "block",
                "message": "unjangled-guardrails denied this tool call: no approval prompt is configured on this Hermes, "
                "so the call was not held for approval. Ask the user in conversation to run it or grant a ruling."}
    return None


def _transform_tool_result(tool_name: str = "", args: Any = None,
                           result: Any = None, **_: Any) -> Optional[str]:
    if not isinstance(result, str):
        return None
    name = (tool_name or "").lower()
    if name in _NEVER_EXTERNAL:
        return None
    if len(result) < 200:  # unjangled-guardrails MIN_SCAN_CHARS
        return None
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": tool_name,
        "tool_input": args if isinstance(args, dict) else {},
        "tool_response": result,
        "cwd": os.getcwd(),
    }
    try:
        out = _run_hook(payload)
    except _GuardError as exc:
        logger.warning("Unjangled Guardrails: post-scan unavailable (%s); result passed through", exc)
        return None  # scanning is advisory: never block on scan failure
    if not out:
        return None
    message = out.get("systemMessage") or out.get("reason") or (out.get("hookSpecificOutput") or {}).get("additionalContext") or ""
    if not message:
        return None
    return f"[{message}]\n\n{result}"


def _post_tool_call(tool_name: str = "", args: Any = None, result: Any = None,
                    duration_ms: Any = None, session_id: str = "", **_: Any) -> None:
    # Observer only: feeds nothing, decides nothing. Useful for debug logging.
    logger.debug("unjangled-guardrails observed %s (%sms)", tool_name, duration_ms)


def register(ctx) -> None:
    if not _guard_home():
        logger.warning(
            "unjangled-guardrails: GUARD_HOME unset or invalid — plugin disabled "
            "(set it to the unjangled-guardrails fork root containing src/cli.js)"
        )
        return
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("transform_tool_result", _transform_tool_result)
    ctx.register_hook("post_tool_call", _post_tool_call)

