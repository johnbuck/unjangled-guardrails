#!/usr/bin/env python3
"""Stub-based tests for the unjangled-guardrails Hermes plugin.

GUARD_HOME is pointed at a fixture containing a fake src/cli.js whose
behavior is scripted per-test via a mode file. Run: python3 test_adapter.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

STUB_CLI = r"""#!/usr/bin/env node
const fs = require("fs");
const mode = (fs.existsSync(require("path").join(__dirname, "..", "..", "mode")) && fs.readFileSync(require("path").join(__dirname, "..", "..", "mode"), "utf8").trim()) || "allow";
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const out = (obj) => process.stdout.write(JSON.stringify(obj));
switch (mode) {
  case "deny":
    out({ hookSpecificOutput: { hookEventName: input.hook_event_name, permissionDecision: "deny", permissionDecisionReason: "unjangled-guardrails blocked this call because it looks destructive (risk 2.9/3)" } });
    break;
  case "ask":
    out({ hookSpecificOutput: { hookEventName: input.hook_event_name, permissionDecision: "ask", permissionDecisionReason: "unjangled-guardrails: needs approval (risk 2.0/3)" } });
    break;
  case "flag":
    out({ decision: "block", reason: "unjangled-guardrails: the result contains text aimed at AI agents (injection, p=0.93)", systemMessage: "unjangled-guardrails: the result contains text aimed at AI agents (injection, p=0.93)" });
    break;
  case "hang":
    setTimeout(() => {}, 60000);
    break;
  case "garbage":
    process.stdout.write("this is not json\n");
    break;
  case "crash":
    process.stderr.write("boom\n");
    process.exit(3);
    break;
  default: // allow
    // upstream prints nothing for allow
}
"""

MODES = {}


class AdapterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="jgg-test-")
        cls.home = os.path.join(cls.root, "guard-home")
        os.makedirs(os.path.join(cls.home, "src"))
        with open(os.path.join(cls.home, "src", "cli.js"), "w") as f:
            f.write(STUB_CLI)
        cls.mode_file = os.path.join(cls.root, "mode")
        cls.base_env = {
            "GUARD_HOME": cls.home,
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": cls.root,
        }
        sys.path.insert(0, HERE)
        import __init__ as plugin
        cls.plugin = plugin

    def set_mode(self, mode):
        with open(self.mode_file, "w") as f:
            f.write(mode)

    def with_env(self, **extra):
        env = dict(os.environ)
        env.update(self.base_env)
        for k, v in extra.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
        return env

    def call_pre(self, mode, tool="terminal", args=None, env_extra=None):
        self.set_mode(mode)
        old = dict(os.environ)
        try:
            os.environ.clear(); os.environ.update(env_extra or self.with_env())
            return self.plugin._pre_tool_call(tool_name=tool, args=args or {"command": "rm -rf /"})
        finally:
            os.environ.clear(); os.environ.update(old)

    def call_transform(self, mode, result="x" * 300, tool="web_fetch", env_extra=None):
        self.set_mode(mode)
        old = dict(os.environ)
        try:
            os.environ.clear(); os.environ.update(env_extra or self.with_env())
            return self.plugin._transform_tool_result(tool_name=tool, args={"urls": ["http://x"]}, result=result)
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_deny_blocks(self):
        r = self.call_pre("deny")
        self.assertEqual(r["action"], "block")
        self.assertIn("destructive", r["message"])

    def test_allow_passes(self):
        self.assertIsNone(self.call_pre("allow"))

    def test_ask_without_approver_blocks(self):
        # TR-5: no approvals config in HOME -> no approver -> the hook answers deny and the
        # plugin blocks instead of letting an unapprovable ask pass.
        r = self.call_pre("ask")
        self.assertEqual(r["action"], "block")
        self.assertIn("no approval prompt", r["message"])

    def test_ask_escalates_with_approver_env(self):
        # backlog bug 1: an ask must reach a person — the plugin returns Hermes's approve
        # directive, which routes the call to its human-approval gate, with the gate's reason.
        r = self.call_pre("ask", env_extra=self.with_env(GUARD_HERMES_APPROVER="1"))
        self.assertEqual(r["action"], "approve")
        self.assertIn("needs approval", r["message"])

    def test_ask_escalates_with_approvals_config(self):
        # detection from Hermes' own config surface: approvals.mode not off -> escalate
        cfg_dir = os.path.join(self.root, ".hermes")
        os.makedirs(cfg_dir, exist_ok=True)
        cfg = os.path.join(cfg_dir, "config.yaml")
        with open(cfg, "w") as f:
            f.write("model:\n  provider: auto\napprovals:\n  mode: manual\n  timeout: 60\n")
        try:
            r = self.call_pre("ask")
            self.assertEqual(r["action"], "approve")
            self.assertIn("needs approval", r["message"])
            # mode: off (or a false-y spelling) means no prompt: block again
            with open(cfg, "w") as f:
                f.write("approvals:\n  mode: off\n")
            r = self.call_pre("ask")
            self.assertEqual(r["action"], "block")
            # approvals block absent entirely: no approver
            with open(cfg, "w") as f:
                f.write("model:\n  provider: auto\n")
            self.assertEqual(self.call_pre("ask")["action"], "block")
        finally:
            os.remove(cfg)

    def test_readonly_fast_path_skips_spawn(self):
        # a tool the core skips brain-side anyway never spawns (mode crash would fail if it did)
        self.set_mode("crash")
        old = dict(os.environ)
        try:
            os.environ.clear(); os.environ.update(self.with_env())
            self.assertIsNone(self.plugin._pre_tool_call(tool_name="grep", args={"path": "/x"}))
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_read_path_names_reach_the_hook(self):
        # backlog bug 1: read_file/read_many_files are no longer skipped locally — the hook
        # judges them (repro step 6). A deny verdict from the hook blocks the read; a hook
        # crash under fail-closed blocks too, proving the spawn actually happened.
        r = self.call_pre("deny", tool="read_file", args={"path": "/x/.env"})
        self.assertEqual(r["action"], "block")
        r = self.call_pre("crash", tool="read_many_files", args={"paths": ["/x"]},
                          env_extra=self.with_env(GUARD_FAIL_CLOSED="1"))
        self.assertEqual(r["action"], "block")
        self.assertIn("failing closed", r["message"])

    def test_error_fail_closed_blocks(self):
        r = self.call_pre("crash", env_extra=self.with_env(GUARD_FAIL_CLOSED="1"))
        self.assertEqual(r["action"], "block")
        self.assertIn("failing closed", r["message"])

    def test_error_fail_open_passes(self):
        self.assertIsNone(self.call_pre("crash"))

    def test_fail_closed_parsing(self):
        # M4 (TR-6): one truthiness parser, matching failClosed() in src/orchestrate.js —
        # "0"/"false"/unset stay open (bool("0") used to close!), "1"/"true"/anything else close.
        old = dict(os.environ)
        try:
            for v, want in [("0", False), ("false", False), ("", False), ("1", True), ("true", True), ("TRUE", True), ("yes", True)]:
                os.environ["GUARD_FAIL_CLOSED"] = v
                self.assertEqual(self.plugin._fail_closed(), want, f"GUARD_FAIL_CLOSED={v!r}")
            os.environ.pop("GUARD_FAIL_CLOSED", None)
            self.assertFalse(self.plugin._fail_closed())
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_error_fail_closed_zero_stays_open(self):
        # the off-switch spelling behaves identically to unset: crash passes
        self.assertIsNone(self.call_pre("crash", env_extra=self.with_env(GUARD_FAIL_CLOSED="0")))

    def test_error_fail_closed_true_spelling_blocks(self):
        r = self.call_pre("crash", env_extra=self.with_env(GUARD_FAIL_CLOSED="true"))
        self.assertEqual(r["action"], "block")

    def test_policy_env_passthrough(self):
        # M3 (TR-6): the subprocess sees the same policy env as the operator CLI — the split-brain
        # finding (child resolved one store, the CLI another; fallback and leak threshold drifted).
        old = dict(os.environ)
        try:
            os.environ["GUARD_HOME"] = self.home
            os.environ["GUARD_FALLBACK"] = "closed"
            os.environ["GUARD_LEAK_P"] = "0.6"
            env = self.plugin._spawn_env()
            self.assertEqual(env["GUARD_HOME"], self.home)
            self.assertEqual(env["GUARD_FALLBACK"], "closed")
            self.assertEqual(env["GUARD_LEAK_P"], "0.6")
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_garbage_fail_closed_blocks(self):
        r = self.call_pre("garbage", env_extra=self.with_env(GUARD_FAIL_CLOSED="1"))
        self.assertEqual(r["action"], "block")

    def test_timeout_fail_closed_blocks(self):
        r = self.call_pre("hang", env_extra=self.with_env(GUARD_FAIL_CLOSED="1", GUARD_TIMEOUT_MS="1000"))
        self.assertEqual(r["action"], "block")
        self.assertIn("timed out", r["message"])

    def test_timeout_bounded_25s(self):
        import time
        self.set_mode("hang")
        old = dict(os.environ)
        t0 = time.monotonic()
        try:
            os.environ.clear(); os.environ.update(self.with_env(GUARD_FAIL_CLOSED="1", GUARD_TIMEOUT_MS="600000"))
            r = self.plugin._pre_tool_call(tool_name="terminal", args={"command": "ls"})
            dt = time.monotonic() - t0
            self.assertEqual(r["action"], "block")
            self.assertLess(dt, 30.0)
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_flag_prepends_warning(self):
        out = self.call_transform("flag")
        self.assertTrue(out.startswith("[unjangled-guardrails:"))
        self.assertIn("injection", out)
        self.assertTrue(out.endswith("x" * 300))

    def test_transform_never_external_skips(self):
        self.set_mode("flag")  # would flag if scanned
        old = dict(os.environ)
        try:
            os.environ.clear(); os.environ.update(self.with_env())
            self.assertIsNone(self.plugin._transform_tool_result(tool_name="write_file", args={"path": "/x"}, result="y" * 300))
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_transform_short_result_skips(self):
        self.assertIsNone(self.call_transform("flag", result="short"))

    def test_scan_failure_never_blocks(self):
        self.assertIsNone(self.call_transform("crash"))  # fail-open regardless

    def test_plugin_disabled_without_home(self):
        old = dict(os.environ)
        try:
            os.environ.clear(); os.environ.update(self.with_env(GUARD_HOME=None))
            registered = []
            ctx = type("Ctx", (), {"register_hook": staticmethod(lambda n, f: registered.append((n, f)))})()
            self.plugin.register(ctx)
            self.assertEqual(registered, [])  # disabled, nothing registered
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_register_binds_three_hooks(self):
        old = dict(os.environ)
        try:
            os.environ.clear(); os.environ.update(self.with_env())
            registered = []
            ctx = type("Ctx", (), {"register_hook": staticmethod(lambda n, f: registered.append((n, f)))})()
            self.plugin.register(ctx)
            self.assertEqual(sorted(n for n, _ in registered), ["post_tool_call", "pre_tool_call", "transform_tool_result"])
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_backcompat_legacy_env_names(self):
        # Operator ruling 2026-10-07: the pre-rename JEV_* spellings still work, read after
        # the new names. with_env() sets the fixture home under the new name.
        old = dict(os.environ)
        try:
            os.environ.clear(); os.environ.update(self.with_env())
            # legacy spelling alone resolves home and fail-closed
            os.environ["JEV_GUARD_HOME"] = self.home
            os.environ.pop("GUARD_HOME", None)
            os.environ["JEV_GUARD_FAIL_CLOSED"] = "1"
            os.environ.pop("GUARD_FAIL_CLOSED", None)
            self.assertEqual(self.plugin._guard_home(), self.home)
            self.assertTrue(self.plugin._fail_closed())
            r = self.plugin._pre_tool_call(tool_name="terminal", args={"command": "ls"})
            self.assertEqual(r["action"], "block")  # legacy spelling still fail-closes on error
            # legacy policy env still passes through to the subprocess
            os.environ["JEV_GUARD_FALLBACK"] = "closed"
            self.assertEqual(self.plugin._spawn_env().get("JEV_GUARD_FALLBACK"), "closed")
            # the new name wins when both spellings are set (invalid path -> disabled, not the legacy one)
            os.environ["GUARD_HOME"] = "/elsewhere"
            self.assertIsNone(self.plugin._guard_home())
        finally:
            os.environ.clear(); os.environ.update(old)


if __name__ == "__main__":
    unittest.main(verbosity=2)

