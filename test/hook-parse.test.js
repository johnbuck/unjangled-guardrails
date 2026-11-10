// posture-triage 5.3 R9: the hook's stdin JSON.parse used to sit OUTSIDE the catch — a malformed
// payload crashed the hook with a nonzero exit, and hosts that ignore a failed hook then proceed
// (fail-open). Now a parse failure answers the safe deny shape on stdout and exits 0, so no host
// ever sees a crashed hook. (New file: test/hook.test.js carries another session's in-flight work.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import { main } from "../src/hook.js";

const streamOf = (s) => { const r = new Readable(); r.push(s); r.push(null); return r; };
const capture = () => {
  const chunks = [];
  const w = new Writable({ write(c, _e, cb) { chunks.push(c); cb(); } });
  return [w, () => Buffer.concat(chunks).toString()];
};

test("5.3 R9: malformed stdin yields the safe deny JSON and exit 0 — never a crashed hook", async () => {
  const saved = process.exitCode;
  try {
    for (const garbage of ["{oops", "", "not json at all", '{"hook_event_name": "PreToolUse", "tool_name":']) {
      const [out, text] = capture();
      process.exitCode = 1;  // prove the hook resets the exit status to 0
      await main([], streamOf(garbage), out, {});
      assert.equal(process.exitCode, 0, JSON.stringify(garbage));
      const response = JSON.parse(text());  // valid JSON on stdout, whatever the payload was
      assert.equal(response.hookSpecificOutput.permissionDecision, "deny");
      assert.equal(response.hookSpecificOutput.permissionDecisionReason, "unparseable payload — fail-safe");
    }
  } finally { process.exitCode = saved; }
});

test("5.3 R9: a well-formed payload with an unhandled event still flows through the normal path", async () => {
  const [out, text] = capture();
  await main([], streamOf(JSON.stringify({ hook_event_name: "SomeOtherEvent", tool_name: "Bash" })), out, {});
  assert.equal(text(), "");  // no crash, no output — the event simply isn't handled
});
