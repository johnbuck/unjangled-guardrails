// Brain circuit breaker (posture-triage 5.8): consecutive ask() timeouts open the breaker,
// the cool-down window resolves instantly from the local rules floor (guard.js's degrade
// path — no fresh timeout is waited out), a healthy response resets and closes it, and both
// knobs are env-tunable. State rides GUARD_HOME/breaker.json so the count survives the
// one-shot hook processes; every test points GUARD_HOME at its own temp dir.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ask } from "../src/jev.js";
import { assessAction } from "../src/guard.js";
import { createBreaker, breakerFile } from "../src/breaker.js";

const hang = (_u, o) => new Promise((_, rej) => o.signal.addEventListener("abort", () => rej(o.signal.reason)));
// AbortSignal.timeout unref's its timer and a fake fetch keeps no handles: hold the loop open per call.
const withLoop = async (fn) => { const keep = setTimeout(() => {}, 10_000); try { return await fn(); } finally { clearTimeout(keep); } };
const counting = (impl = hang) => { const stub = (...a) => { stub.calls++; return impl(...a); }; stub.calls = 0; return stub; };
const Q = { q: { type: "noul" } };
const healthy = async () => ({ ok: true, json: async () => ({ answers: { q: { type: "noul", noul: 0.1 } } }) });
const timedOut = (err) => err.name === "TimeoutError";
const envIn = (dir, extra = {}) => ({ SYSTEMONE_URL: "http://brain.example:9099", GUARD_HOME: dir, GUARD_TIMEOUT_MS: "40", ...extra });

test("5.8: three consecutive timeouts open the breaker; the window skips the brain instantly", async () => {
  const env = envIn(mkdtempSync(join(tmpdir(), "jg-breaker-")));
  for (let i = 0; i < 3; i++) {
    const t0 = Date.now();
    await withLoop(() => assert.rejects(ask("s", Q, { env, fetchImpl: hang }), timedOut));
    assert.ok(Date.now() - t0 >= 35, "each call waits its budget while the breaker is still closed");
  }
  const stub = counting();
  const t1 = Date.now();
  await withLoop(() => assert.rejects(ask("s", Q, { env, fetchImpl: stub }), /circuit breaker/));
  assert.equal(stub.calls, 0, "the breaker-open skip never touches the brain");
  assert.ok(Date.now() - t1 < 35, "the skip is instant — no timeout is waited out");
  const state = JSON.parse(readFileSync(breakerFile(env), "utf8"));
  assert.ok(state.timeouts >= 3 && state.openedAt > 0, "the state file records the open breaker");
});

test("5.8: a healthy response resets the count and closes an open breaker", async () => {
  // While the window is open no brain call happens at all, so the closing healthy response
  // arrives through the half-open trial after GUARD_BREAKER_COOLDOWN_MS elapses.
  const env = envIn(mkdtempSync(join(tmpdir(), "jg-breaker-")), { GUARD_BREAKER_THRESHOLD: "1", GUARD_BREAKER_COOLDOWN_MS: "40" });
  await withLoop(() => assert.rejects(ask("s", Q, { env, fetchImpl: hang }), timedOut));
  assert.equal(createBreaker({ env }).isOpen(), true);
  const blocked = counting(healthy);  // even a healthy-capable stub is never reached in-window
  await assert.rejects(ask("s", Q, { env, fetchImpl: blocked }), /circuit breaker/);
  assert.equal(blocked.calls, 0);
  await new Promise((r) => setTimeout(r, 60));
  assert.equal((await ask("s", Q, { env, fetchImpl: healthy })).q.p, 0.1);
  assert.deepEqual(JSON.parse(readFileSync(breakerFile(env), "utf8")), { timeouts: 0, openedAt: null });
  assert.equal(createBreaker({ env }).isOpen(), false);
  const stub = counting();
  await withLoop(() => assert.rejects(ask("s", Q, { env, fetchImpl: stub }), timedOut));
  assert.equal(stub.calls, 1, "the brain is tried again after a healthy close");
});

test("5.8: GUARD_BREAKER_THRESHOLD is honored (2 instead of 3); junk falls back to the default", async () => {
  const env = envIn(mkdtempSync(join(tmpdir(), "jg-breaker-")), { GUARD_BREAKER_THRESHOLD: "2" });
  for (let i = 0; i < 2; i++) await withLoop(() => assert.rejects(ask("s", Q, { env, fetchImpl: hang }), timedOut));
  const stub = counting();
  await withLoop(() => assert.rejects(ask("s", Q, { env, fetchImpl: stub }), /circuit breaker/));
  assert.equal(stub.calls, 0, "threshold 2 opens after two timeouts");

  const junk = envIn(mkdtempSync(join(tmpdir(), "jg-breaker-")), { GUARD_BREAKER_THRESHOLD: "abc" });  // non-numeric → default 3
  for (let i = 0; i < 2; i++) await withLoop(() => assert.rejects(ask("s", Q, { env: junk, fetchImpl: hang }), timedOut));
  const stub2 = counting();  // the probe below attempts the brain (calls → 1) and is itself the third timeout
  await withLoop(() => assert.rejects(ask("s", Q, { env: junk, fetchImpl: stub2 }), timedOut));
  assert.equal(stub2.calls, 1, "two junk-config timeouts do not open the default threshold of 3 — the brain was still tried");
  await withLoop(() => assert.rejects(ask("s", Q, { env: junk, fetchImpl: stub2 }), /circuit breaker/));
  assert.equal(stub2.calls, 1, "the third timeout opens the default threshold — the next call skips instantly");
});

test("5.8: the cool-down window elapses and the brain is tried again (GUARD_BREAKER_COOLDOWN_MS)", async () => {
  const env = envIn(mkdtempSync(join(tmpdir(), "jg-breaker-")), { GUARD_BREAKER_THRESHOLD: "1", GUARD_BREAKER_COOLDOWN_MS: "40" });
  await withLoop(() => assert.rejects(ask("s", Q, { env, fetchImpl: hang }), timedOut));
  await withLoop(() => assert.rejects(ask("s", Q, { env, fetchImpl: hang }), /circuit breaker/));  // inside the window: still an instant skip
  await new Promise((r) => setTimeout(r, 60));
  const stub = counting();
  await withLoop(() => assert.rejects(ask("s", Q, { env, fetchImpl: stub }), timedOut));
  assert.equal(stub.calls, 1, "after the window elapses the brain is attempted again");
});

test("5.8: breaker unit — injectable clock, expired window, healthy reset, config floors", () => {
  let t = 1_000;
  const env = { GUARD_HOME: mkdtempSync(join(tmpdir(), "jg-breaker-")), GUARD_BREAKER_THRESHOLD: "2", GUARD_BREAKER_COOLDOWN_MS: "100" };
  const br = createBreaker({ env, now: () => t });
  br.recordTimeout();
  t += 10;
  assert.equal(br.isOpen(), false);
  br.recordTimeout();
  t += 10;
  assert.equal(br.isOpen(), true, "threshold 2 opens on the second timeout");
  t += 200;
  assert.equal(br.isOpen(), false, "an elapsed window reads closed without a write");
  br.recordTimeout();  // fresh count after expiry
  assert.deepEqual(JSON.parse(readFileSync(breakerFile(env), "utf8")), { timeouts: 1, openedAt: null });
  br.recordHealthy();
  assert.deepEqual(JSON.parse(readFileSync(breakerFile(env), "utf8")), { timeouts: 0, openedAt: null });

  const floored = createBreaker({ env: { GUARD_HOME: env.GUARD_HOME, GUARD_BREAKER_THRESHOLD: "abc", GUARD_BREAKER_COOLDOWN_MS: "0" }, now: () => t });
  floored.recordTimeout();
  floored.recordTimeout();
  t += 1_000;
  assert.equal(floored.isOpen(), false, "junk threshold falls back to 3 — two timeouts do not open");
  floored.recordTimeout();
  assert.equal(floored.isOpen(), true, "the third opens; junk cooldown falls back to the 60s default (still inside)");
});

test("5.8: with the breaker open, a judged action resolves from the local rules floor instantly", async () => {
  const env = envIn(mkdtempSync(join(tmpdir(), "jg-breaker-")), { GUARD_TIMEOUT_MS: "500" });
  const br = createBreaker({ env });
  br.recordTimeout(); br.recordTimeout(); br.recordTimeout();
  assert.equal(br.isOpen(), true);
  const t0 = Date.now();
  const v = await assessAction({ tool: "Write", input: { file_path: "/proj/src/x.ts", content: "hi" }, cwd: "/proj", sessionId: "s1" }, { env, fetchImpl: hang });
  assert.ok(Date.now() - t0 < 250, "the skip never waits out the 500ms budget");
  assert.equal(v.level, "allow");
  assert.equal(v.degraded, true);
  assert.match(v.why, /passed the built-in offline rules/);
});
