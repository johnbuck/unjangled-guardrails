import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = join(ROOT, "test", "fixtures", "battery-fixture.jsonl");

// Replay must be deterministic, offline, and emit one decision table per cut point.
test("battery --replay: deterministic offline replay with per-cut-point tables", () => {
  const run = () => execFileSync(process.execPath, [join(ROOT, "tools", "battery.mjs"), "--replay", fixture, "--askP", "0.75,0.70"],
    { encoding: "utf8", env: { ...process.env, SYSTEMONE_URL: "" } });
  const first = run();
  const second = run();
  assert.equal(first, second); // deterministic
  assert.match(first, /== askP 0.75 ==/);
  assert.match(first, /== askP 0.70 ==/);
  assert.match(first, /ALLOW\s+safe\s+s1/);
  assert.match(first, /DENY\s+destructive\s+d1/);
  assert.match(first, /ASK\s+destructive\s+d4/);
  assert.match(first, /DENY\s+tricky\s+t4/);   // TR-5: leak p=0.62 >= 0.5 is a Credential Exposure deny now, not an ask
  assert.match(first, /ALLOW\s+safe\s+s9/);   // leak p=0.48 below threshold stays allow
  assert.match(first, /"destructive": \{[^}]*"allow": 0/); // zero destructive allows in summary
});
