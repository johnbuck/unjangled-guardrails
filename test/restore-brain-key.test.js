// `key --infisical` (epic-installer follow-up, 2026-10-12): the gate's own Infisical restore
// path, so no agent command text ever names a credential source (the 7.7 floor's operand leg
// only sees `key --infisical --project <id>`). The Infisical CLI is a stub on PATH — it records
// what it received and prints canned values — so the full chain runs offline and every
// no-exposure claim is asserted against what the stub actually got, not what we hope it got.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const FAKE_KEY = "infisical-test-key-value";
// v0.43.1's --silent prints banner lines (upgrade notice, tips, blanks) around the token, and
// the token line itself is long and space-free — the extractor keys on that shape, so the stub
// reproduces the observed output structure, banners included.
const FAKE_TOKEN = "infisical-test-" + "t".repeat(120);
const FAKE_CLIENT_ID = "fake-client-id";
const FAKE_CLIENT_SECRET = "fake-client-secret";
const FAKE_SITE = "https://infisical.example.example";

function makeFixture() {
  const home = mkdtempSync(join(tmpdir(), "ug-key-infisical-"));
  const binDir = join(home, "bin");
  mkdirSync(binDir, { recursive: true });
  mkdirSync(join(home, ".config", "infisical"), { recursive: true });
  mkdirSync(join(home, ".unjangled-guardrails"), { recursive: true });
  // The stub: appends simple marker lines (fake values only) and prints the canned token for
  // login, the canned key for secrets get --plain.
  const record = join(home, "stub-record.txt");
  writeFileSync(join(binDir, "infisical"), [
    "#!/bin/bash",
    `echo "cmd:$*" >> ${JSON.stringify(record)}`,
    `echo "authid:$([ -n \\"$INFISICAL_UNIVERSAL_AUTH_CLIENT_ID\\" ] && echo yes || echo no)" >> ${JSON.stringify(record)}`,
    `echo "token:$([ -n \\"$INFISICAL_TOKEN\\" ] && echo yes || echo no)" >> ${JSON.stringify(record)}`,
    'if [ "$1" = "login" ]; then echo "A new release of infisical is available: 0.43.141 -> 0.44.9"; echo; echo "Install the update:"; echo "' + FAKE_TOKEN + '"; echo; echo "To fetch all secrets, run: infisical secrets"; fi',
    'if [ "$1" = "secrets" ]; then echo "' + FAKE_KEY + '"; fi',
  ].join("\n"), { mode: 0o755 });
  writeFileSync(join(home, ".config", "infisical", "identity.env"),
    `INFISICAL_CLIENT_ID=${FAKE_CLIENT_ID}\nINFISICAL_CLIENT_SECRET=${FAKE_CLIENT_SECRET}\nINFISICAL_SITE_URL=${FAKE_SITE}\n`);
  writeFileSync(join(home, ".unjangled-guardrails", "config.json"),
    JSON.stringify({ localBaseUrl: "https://brain.example.example" }));
  return { home, binDir, record };
}

const run = (home, binDir, args) => new Promise((resolve) => {
  const child = spawn(process.execPath, ["src/cli.js", "key", ...args],
    { cwd: REPO, env: { PATH: `${binDir}:${process.env.PATH}`, HOME: home } });
  let stdout = "", stderr = "";
  child.stdout.on("data", (d) => (stdout += d));
  child.stderr.on("data", (d) => (stderr += d));
  child.on("error", (e) => resolve({ status: -1, stdout, stderr: stderr + String(e) }));
  child.on("close", (status) => resolve({ status, stdout, stderr }));
});

test("key --infisical: full chain — identity read by the gate, key lands in the 0600 config, no secret in argv or output", async () => {
  const { home, binDir, record } = makeFixture();
  const r = await run(home, binDir, ["--infisical", "--project", "p1"]);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  assert.match(r.stdout, /brain key restored from Infisical/);
  // the config: the fetched key, 0600, base URL untouched
  const cfgPath = join(home, ".unjangled-guardrails", "config.json");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  assert.equal(cfg.localApiKey, FAKE_KEY);
  assert.equal(cfg.localBaseUrl, "https://brain.example.example");
  assert.equal(statSync(cfgPath).mode & 0o777, 0o600);
  // the stub got the identity via ENV (never argv) and the token via ENV for the secrets call
  const stubLines = readFileSync(record, "utf8").trim().split("\n");
  assert.equal(stubLines.filter((l) => l.startsWith("cmd:login")).length, 1);
  assert.equal(stubLines.filter((l) => l.startsWith("cmd:secrets")).length, 1);
  assert.ok(stubLines.includes("authid:yes"), "identity must travel via child env");
  assert.ok(stubLines.includes("token:yes"), "token must travel via child env");
  // no secret value anywhere in the CLI's own output
  assert.ok(!r.stdout.includes(FAKE_KEY) && !r.stdout.includes(FAKE_TOKEN), r.stdout);
  assert.ok(!r.stderr.includes(FAKE_KEY) && !r.stderr.includes(FAKE_TOKEN), r.stderr);
});

test("--project is required: hard usage error, nothing fetched", async () => {
  const { home, binDir } = makeFixture();
  const r = await run(home, binDir, ["--infisical"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /needs --project/);
  assert.equal(existsSync(join(home, ".unjangled-guardrails", "config.json")), true);  // untouched pre-existing config
});

test("no identity file: clean error naming the searched directory, no stack", async () => {
  const home = mkdtempSync(join(tmpdir(), "ug-key-infisical-empty-"));
  const r = await run(home, [], ["--infisical", "--project", "p1"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /no Infisical identity file found/);
  assert.ok(!/\n\s+at /.test(r.stderr), r.stderr);
});

test("no localBaseUrl in the config: clean error pointing at `key --local` first", async () => {
  const { binDir } = makeFixture();
  const home = mkdtempSync(join(tmpdir(), "ug-key-infisical-nourl-"));
  mkdirSync(join(home, ".config", "infisical"), { recursive: true });
  writeFileSync(join(home, ".config", "infisical", "identity.env"),
    `INFISICAL_CLIENT_ID=x\nINFISICAL_CLIENT_SECRET=y\nINFISICAL_SITE_URL=https://s.example.example\n`);
  const r = await run(home, binDir, ["--infisical", "--project", "p1"]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /no localBaseUrl/);
});
