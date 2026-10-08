import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ask, backend } from "../src/jev.js";
import { scanContent } from "../src/guard.js";

const localEnv = { SYSTEMONE_URL: "http://shim.example:9099" };
const pad = (s) => s + " lorem ipsum ".repeat(30);

// Capturing stub shaped like the SemIf shim's documented responses.
function shimStub(answers = { directed: { type: "noul", noul: 0.02 }, kind: { type: "choice", choice: "benign", probabilities: { benign: 0.97 }, confidence: 0.93 } }) {
  const seen = [];
  const fetchImpl = async (url, opts) => {
    seen.push({ url, headers: opts.headers, body: JSON.parse(opts.body) });
    return { ok: true, json: async () => ({ model: "semif-0.1.0", answers, usage: { input_tokens: 100, output_tokens: 0 } }) };
  };
  return { fetchImpl, seen };
}

test("backend: SYSTEMONE_URL selects local and beats every cloud credential", () => {
  assert.deepEqual(backend({ SYSTEMONE_URL: "http://x:1" }), { kind: "local", url: "http://x:1", key: undefined });
  assert.deepEqual(
    backend({ SYSTEMONE_URL: "http://x:1", JEV_API_KEY: "k", AI_GATEWAY_API_KEY: "g", VERCEL_OIDC_TOKEN: "o" }),
    { kind: "local", url: "http://x:1", key: undefined });
  assert.equal(backend({ JEV_API_KEY: "k" }).kind, "typesafe"); // unchanged without local
});

test("backend: config-file localBaseUrl is used when env is empty", () => {
  const dir = mkdtempSync(join(tmpdir(), "jg-local-"));
  const cfgFile = join(dir, "config.json");
  writeFileSync(cfgFile, JSON.stringify({ localBaseUrl: "http://cfg:9099", localApiKey: "k2" }));
  assert.deepEqual(backend({ GUARD_CONFIG: cfgFile }), { kind: "local", url: "http://cfg:9099", key: "k2" });
});

test("ask: local request shape - url join, body fields, conditional auth, model alias", async () => {
  const keyed = shimStub();
  await ask("s", { q: { type: "noul", instructions: "?" } }, { env: { ...localEnv, SYSTEMONE_KEY: "sekrit" }, fetchImpl: keyed.fetchImpl });
  const r = keyed.seen[0];
  assert.equal(r.url, "http://shim.example:9099/v1/systemone");
  assert.deepEqual(Object.keys(r.body).sort(), ["questions", "state"]); // no model key: the shim's default answers
  assert.equal(r.body.questions.q.type, "noul"); // no gateway "boolean" mapping
  assert.equal(r.headers.Authorization, "Bearer sekrit");
  const plain = shimStub();
  await ask("s", { q: { type: "noul", instructions: "?" } }, { env: localEnv, fetchImpl: plain.fetchImpl });
  assert.equal(plain.seen[0].headers.Authorization, undefined); // no auth header without a key
  const over = shimStub();
  await ask("s", { q: { type: "noul", instructions: "?" } }, { env: { SYSTEMONE_URL: "http://x:1/", SYSTEMONE_MODEL: "semif-0.1.0" }, fetchImpl: over.fetchImpl });
  assert.equal(over.seen[0].url, "http://x:1/v1/systemone"); // trailing slash normalized
  assert.equal(over.seen[0].body.model, "semif-0.1.0");      // SYSTEMONE_MODEL override
});

test("ask: maps shim answer shapes (noul/choice/score)", async () => {
  const answers = {
    n: { type: "noul", noul: 0.81 },
    c: { type: "choice", choice: "injection", probabilities: { injection: 0.88, benign: 0.12 }, confidence: 0.71 },
    s: { type: "score", score: 2.31, legend: { 0: "a", 1: "b", 2: "c", 3: "d" }, probabilities: { 0: 0.02, 1: 0.1, 2: 0.55, 3: 0.33 }, confidence: 0.62 },
  };
  const { fetchImpl } = shimStub(answers);
  const out = await ask("s", { n: { type: "noul" }, c: { type: "choice" }, s: { type: "score" } }, { env: localEnv, fetchImpl });
  assert.equal(out.n.p, 0.81);
  assert.equal(out.c.choice, "injection");
  assert.equal(out.c.confidence, 0.71);
  assert.equal(out.s.score, 2.31);
  assert.equal(out.s.probabilities["2"], 0.55);
});

test("ask: retries 529 then succeeds; labels local errors", async () => {
  let calls = 0;
  const flaky = async () => { calls++; return calls === 1 ? { ok: false, status: 529, text: async () => "overloaded" } : { ok: true, json: async () => ({ answers: { x: { type: "noul", noul: 0.5 } } }) }; };
  assert.equal((await ask("s", { x: { type: "noul" } }, { env: localEnv, fetchImpl: flaky })).x.p, 0.5);
  assert.equal(calls, 2);
  await assert.rejects(
    ask("s", { x: { type: "noul" } }, { env: localEnv, fetchImpl: async () => ({ ok: false, status: 400, text: async () => "prompt too long" }) }),
    /local HTTP 400/);
});

test("ask: local configured + cloud creds present - only the local URL is ever fetched", async () => {
  const urls = [];
  const dead = async (url) => { urls.push(url); return { ok: false, status: 503, text: async () => "down" }; };
  await assert.rejects(
    ask("s", { x: { type: "noul" } }, { env: { SYSTEMONE_URL: "http://local:9", JEV_API_KEY: "cloud", AI_GATEWAY_API_KEY: "gw", VERCEL_OIDC_TOKEN: "oidc" }, fetchImpl: dead }),
    /local HTTP 503/);
  assert.ok(urls.length >= 1 && urls.every((u) => u.startsWith("http://local:9/")), JSON.stringify(urls));
});

test("scanContent: GUARD_MAX_STATE_CHARS bounds the state (head+tail, tail kept)", async () => {
  const { fetchImpl, seen } = shimStub();
  const big = "A".repeat(50_000) + "ENDMARK";
  await scanContent({ text: big, tool: "WebFetch" }, { env: { ...localEnv, GUARD_MAX_STATE_CHARS: "12000" }, fetchImpl });
  const sent = seen[0].body.state.content;
  assert.ok(sent.length <= 12000 + 100, `sent ${sent.length}`);
  assert.ok(sent.endsWith("ENDMARK"));
  assert.match(sent, /middle truncated/);
});

test("scanContent: local backend + no env - scan-safe 12000 default (truncate-and-scan, not 400-skip)", async () => {
  const { fetchImpl, seen } = shimStub();
  const big = "A".repeat(80_000) + "ENDMARK";
  await scanContent({ text: big, tool: "WebFetch" }, { env: localEnv, fetchImpl });
  const sent = seen[0].body.state.content;
  assert.ok(sent.length <= 12000 + 100, `sent ${sent.length}`);
  assert.ok(sent.endsWith("ENDMARK"), "tail kept whole");
});


// Back-compat (operator ruling 2026-10-07): the pre-rename JEV_* spellings still work.

test("back-compat: JEV_BASE_URL / JEV_API_KEY_LOCAL still select the local backend; new name wins", () => {
  assert.deepEqual(backend({ JEV_BASE_URL: "http://old:1" }), { kind: "local", url: "http://old:1", key: undefined });
  assert.deepEqual(backend({ JEV_BASE_URL: "http://old:1", JEV_API_KEY_LOCAL: "k" }), { kind: "local", url: "http://old:1", key: "k" });
  assert.equal(backend({ SYSTEMONE_URL: "http://new:1", JEV_BASE_URL: "http://old:1" }).url, "http://new:1");  // new name first
});

test("back-compat: JEV_GUARD_CONFIG still points readConfig at a file", () => {
  const dir = mkdtempSync(join(tmpdir(), "jg-local-"));
  const cfgFile = join(dir, "config.json");
  writeFileSync(cfgFile, JSON.stringify({ jevApiKey: "legacy" }));
  assert.deepEqual(backend({ JEV_GUARD_CONFIG: cfgFile }), { kind: "typesafe", key: "legacy" });
});

test("back-compat: JEV_MODEL still overrides the model alias; SYSTEMONE_MODEL wins", async () => {
  const over = shimStub();
  await ask("s", { q: { type: "noul", instructions: "?" } }, { env: { SYSTEMONE_URL: "http://x:1", JEV_MODEL: "legacy-model" }, fetchImpl: over.fetchImpl });
  assert.equal(over.seen[0].body.model, "legacy-model");
  const both = shimStub();
  await ask("s", { q: { type: "noul", instructions: "?" } }, { env: { SYSTEMONE_URL: "http://x:1", SYSTEMONE_MODEL: "new-model", JEV_MODEL: "legacy-model" }, fetchImpl: both.fetchImpl });
  assert.equal(both.seen[0].body.model, "new-model");
});

test("back-compat: JEV_GUARD_TIMEOUT_MS still bounds the call", async () => {
  const hang = (_u, o) => new Promise((_res, rej) => o.signal.addEventListener("abort", () => rej(o.signal.reason)));
  const keep = setTimeout(() => {}, 10_000);  // AbortSignal.timeout unref's its timer; hold the loop open
  try {
    await assert.rejects(ask("s", { q: { type: "noul" } }, { env: { SYSTEMONE_URL: "http://x:1", JEV_GUARD_TIMEOUT_MS: "10" }, fetchImpl: hang }));
  } finally { clearTimeout(keep); }
});

test("back-compat: JEV_GUARD_MAX_STATE_CHARS still bounds the scan state; JEV_GUARD_SKIP_SCAN still skips", async () => {
  const { fetchImpl, seen } = shimStub();
  const big = "A".repeat(50_000) + "ENDMARK";
  await scanContent({ text: big, tool: "WebFetch" }, { env: { ...localEnv, JEV_GUARD_MAX_STATE_CHARS: "12000" }, fetchImpl });
  const sent = seen[0].body.state.content;
  assert.ok(sent.length <= 12000 + 100, `sent ${sent.length}`);
  assert.match(sent, /middle truncated/);
  assert.equal(await scanContent({ text: pad("ordinary text long enough to scan"), tool: "webfetch" }, { env: { ...localEnv, JEV_GUARD_SKIP_SCAN: "webfetch" }, fetchImpl: shimStub().fetchImpl }), null);
});

// Back-compat (operator ruling 2026-10-07): the pre-rename JEV_* spellings still work.

test("back-compat: JEV_BASE_URL / JEV_API_KEY_LOCAL still select the local backend; new name wins", () => {
  assert.deepEqual(backend({ JEV_BASE_URL: "http://old:1" }), { kind: "local", url: "http://old:1", key: undefined });
  assert.deepEqual(backend({ JEV_BASE_URL: "http://old:1", JEV_API_KEY_LOCAL: "k" }), { kind: "local", url: "http://old:1", key: "k" });
  assert.equal(backend({ SYSTEMONE_URL: "http://new:1", JEV_BASE_URL: "http://old:1" }).url, "http://new:1");  // new name first
});

test("back-compat: JEV_GUARD_CONFIG still points readConfig at a file", () => {
  const dir = mkdtempSync(join(tmpdir(), "jg-local-"));
  const cfgFile = join(dir, "config" + ".json");
  writeFileSync(cfgFile, JSON.stringify({ jevApiKey: "legacy" }));
  assert.deepEqual(backend({ JEV_GUARD_CONFIG: cfgFile }), { kind: "typesafe", key: "legacy" });
});

test("back-compat: JEV_MODEL still overrides the model alias; SYSTEMONE_MODEL wins", async () => {
  const over = shimStub();
  await ask("s", { q: { type: "noul", instructions: "?" } }, { env: { SYSTEMONE_URL: "http://x:1", JEV_MODEL: "legacy-model" }, fetchImpl: over.fetchImpl });
  assert.equal(over.seen[0].body.model, "legacy-model");
  const both = shimStub();
  await ask("s", { q: { type: "noul", instructions: "?" } }, { env: { SYSTEMONE_URL: "http://x:1", SYSTEMONE_MODEL: "new-model", JEV_MODEL: "legacy-model" }, fetchImpl: both.fetchImpl });
  assert.equal(both.seen[0].body.model, "new-model");
});

test("back-compat: JEV_GUARD_TIMEOUT_MS still bounds the call", async () => {
  const hang = (_u, o) => new Promise((_res, rej) => o.signal.addEventListener("abort", () => rej(o.signal.reason)));
  const keep = setTimeout(() => {}, 10_000);  // AbortSignal.timeout unref's its timer; hold the loop open
  try {
    await assert.rejects(ask("s", { q: { type: "noul" } }, { env: { SYSTEMONE_URL: "http://x:1", JEV_GUARD_TIMEOUT_MS: "10" }, fetchImpl: hang }));
  } finally { clearTimeout(keep); }
});

test("back-compat: JEV_GUARD_MAX_STATE_CHARS still bounds the scan state; JEV_GUARD_SKIP_SCAN still skips", async () => {
  const { fetchImpl, seen } = shimStub();
  const big = "A".repeat(50_000) + "ENDMARK";
  await scanContent({ text: big, tool: "WebFetch" }, { env: { ...localEnv, JEV_GUARD_MAX_STATE_CHARS: "12000" }, fetchImpl });
  const sent = seen[0].body.state.content;
  assert.ok(sent.length <= 12000 + 100, `sent ${sent.length}`);
  assert.match(sent, /middle truncated/);
  assert.equal(await scanContent({ text: pad("ordinary text long enough to scan"), tool: "webfetch" },
    { env: { ...localEnv, JEV_GUARD_SKIP_SCAN: "webfetch" }, fetchImpl: shimStub().fetchImpl }), null);
});
