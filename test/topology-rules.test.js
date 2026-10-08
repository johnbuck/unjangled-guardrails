import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import {
  UNIVERSAL_FAMILIES,
  RESIDUALS,
  matchesResidual,
  isExemptPath,
  loadOperatorConfig,
  scanLine,
  parseAddedLines,
} from "../tools/topology-rules.mjs";

// import.meta.dirname needs Node 20.11+; engines declare >=20.3
const HERE = dirname(fileURLToPath(import.meta.url));
const MODULE = join(HERE, "..", "tools", "topology-rules.mjs");
const REPO_ROOT = dirname(HERE);

// Documented canary values from the story's I/O matrix — FAKE, non-operator.
// Every canary-carrying line in this file names "canary" so the accepted
// residual in tools/topology-rules.mjs keeps the suite committable.
const canaryRfc = "10.255.255.1";
const canaryRfc192 = "192.168.1.10";
const canaryRfc172 = "172.16.4.9";
const canaryCgnat = "100.100.1.1";
const canaryLan = "host.example.lan";
const canaryLocal = "box.local";
const canaryToken = "sk-canary0000000000000000000000";

function tmpRepo() {
  return mkdtempSync(join(tmpdir(), "topology-rules-"));
}

test("families: universal families cover the I/O matrix canaries", () => {
  const noCfg = { patterns: [] };
  assert.match(scanLine("src/x.js", `curl -s http://${canaryRfc}/health`, noCfg), /RFC1918/);
  assert.match(scanLine("src/x.js", `ping ${canaryRfc192}`, noCfg), /RFC1918/);
  assert.match(scanLine("src/x.js", `route via ${canaryRfc172}`, noCfg), /RFC1918/);
  assert.match(scanLine("src/x.js", `tailscale ip ${canaryCgnat}`, noCfg), /CGNAT/);
  assert.match(scanLine("src/x.js", `ssh deploy@${canaryLan}`, noCfg), /\.lan\/\.local/);
  assert.match(scanLine("src/x.js", `smb://${canaryLocal}/share`, noCfg), /\.lan\/\.local/);
  // sentence-final period after the name must not hide the canary host
  assert.match(scanLine("src/x.js", `the NAS is ${canaryLocal}.`, noCfg), /\.lan\/\.local/);
  assert.match(scanLine("src/x.js", `key = "${canaryToken}"`, noCfg), /secret-shaped/);
});

test("families: clean lines pass and filenames like settings.local.json are not hostnames", () => {
  const noCfg = { patterns: [] };
  assert.equal(scanLine("src/x.js", "const x = 1; // plain code", noCfg), null);
  assert.equal(scanLine("src/x.js", 'fs.readFileSync(".claude/settings.local.json")', noCfg), null);
  assert.equal(scanLine("src/x.js", "cat /x/.env.local for config keys", noCfg), null);
  assert.equal(scanLine("src/x.js", "see docs/publishing.md and AGENTS.md", noCfg), null);
  assert.equal(scanLine("src/x.js", "127.0.0.1 loopback and 0.0.0.0 are not private ranges", noCfg), null);
  assert.equal(scanLine("src/x.js", "version 1.2.3 and 172.16 are not full quads", noCfg), null);
});

test("families: deny family never echoes the canary content", () => {
  const noCfg = { patterns: [] };
  for (const line of [`ip ${canaryRfc}`, `host ${canaryLan}`, `token ${canaryToken}`, `ip ${canaryCgnat}`]) {
    const family = scanLine("src/x.js", line, noCfg);
    assert.ok(family && typeof family === "string");
    assert.ok(!family.includes(canaryRfc) && !family.includes(canaryLan) && !family.includes(canaryToken));
  }
});

test("exemptions: evidence/ and _bmad-output/ are exempt paths; lookalikes are not", () => {
  assert.ok(isExemptPath("evidence/live-verify.jsonl"));
  assert.ok(isExemptPath("evidence/nested/deep.md"));
  assert.ok(isExemptPath("_bmad-output/initiative-x/story-plan.md"));
  assert.ok(!isExemptPath("src/evidence-adjacent.js"));
  assert.ok(!isExemptPath("src/guard.js"));
  assert.ok(!isExemptPath("docs/evidence.md"));
});

test("residuals: every entry carries a date and a reason; patterns stay structural", () => {
  assert.ok(RESIDUALS.length >= 10);
  for (const r of RESIDUALS) {
    assert.ok(r.date && /^\d{4}-\d{2}-\d{2}$/.test(r.date), `residual for ${r.path} needs a date`);
    assert.ok(r.reason && r.reason.length > 20, `residual for ${r.path} needs a reason`);
    assert.ok(r.pattern instanceof RegExp, `residual for ${r.path} must pin with a RegExp`);
  }
  assert.ok(UNIVERSAL_FAMILIES.length >= 4);
  // Value-freedom of tracked files (residuals included) is enforced by the
  // gate itself, not restated here: this suite runs under the same hook and
  // scan-tree, so any operator value in a tracked file blocks its own commit.
});

test("residuals: canary lines in the suite's own path are exempt; the same line elsewhere is not", () => {
  const noCfg = { patterns: [] };
  const canaryLine = `const canaryIp = "${canaryRfc}";`;
  assert.equal(matchesResidual("test/topology-rules.test.js", canaryLine)?.reason.includes("canary"), true);
  assert.equal(scanLine("test/topology-rules.test.js", canaryLine, noCfg), null);
  assert.match(scanLine("src/other.js", canaryLine, noCfg), /RFC1918/);
  // a residual pin is content-scoped: an unrelated leak in the same file still blocks
  assert.match(scanLine("test/topology-rules.test.js", `const other = "${canaryCgnat}";`, noCfg), /CGNAT/);
});

test("diff parser: added lines with correct numbers; deletions and context never appear", () => {
  const diff = [
    "diff --git a/a.txt b/a.txt",
    "index 111..222 100644",
    "--- a/a.txt",
    "+++ b/a.txt",
    "@@ -1,3 +1,3 @@",
    " context keeps",
    "-deleted line gone",
    `+added at 2 (${canaryRfc} canary)`,
    " context after",
    "@@ -10,2 +11,2 @@",
    "+added at 11",
    "\\ No newline at end of file",
    "diff --git a/new.txt b/new.txt",
    "new file mode 100644",
    "--- /dev/null",
    "+++ b/new.txt",
    "@@ -0,0 +1,2 @@",
    "+first",
    "+second",
  ].join("\n");
  assert.deepEqual(parseAddedLines(diff), [
    { path: "a.txt", line: 2, text: `added at 2 (${canaryRfc} canary)` },
    { path: "a.txt", line: 11, text: "added at 11" },
    { path: "new.txt", line: 1, text: "first" },
    { path: "new.txt", line: 2, text: "second" },
  ]);
  assert.deepEqual(parseAddedLines(""), []);
});

test("diff parser: added lines that start with '+++ ' stay added lines of the real file (hunk-aware)", () => {
  const diff = [
    "diff --git a/tools/x.sh b/tools/x.sh",
    "index 111..222 100644",
    "--- a/tools/x.sh",
    "+++ b/tools/x.sh",
    "@@ -1,2 +1,3 @@",
    " context",
    "++++ b/tools/x.sh",
    "++++ evidence/leak.txt",
  ].join("\n");
  assert.deepEqual(parseAddedLines(diff), [
    { path: "tools/x.sh", line: 2, text: "+++ b/tools/x.sh" },
    { path: "tools/x.sh", line: 3, text: "+++ evidence/leak.txt" },
  ]);
});

test("operator config: absent file = NOT CONFIGURED and universal families still block", async () => {
  const dir = tmpRepo();
  const cfg = await loadOperatorConfig(join(dir, "absent.local.mjs"));
  assert.equal(cfg.present, false);
  assert.deepEqual(cfg.patterns, []);
  assert.match(scanLine("src/x.js", `ip ${canaryRfc}`, cfg), /RFC1918/);
});

test("operator config: configured pattern blocks as operator topology; label names the family", async () => {
  const dir = tmpRepo();
  const cfgPath = join(dir, "topology.local.mjs");
  writeFileSync(cfgPath, 'export default { patterns: [{ label: "operator hostname", source: "example-host", flags: "i" }] };');
  const cfg = await loadOperatorConfig(cfgPath);
  assert.equal(cfg.present, true);
  assert.equal(cfg.patterns.length, 1);
  assert.match(scanLine("src/x.js", "deploy to example-host now", cfg), /^operator topology \(operator hostname\)$/);
  assert.equal(scanLine("src/x.js", "nothing here", cfg), null);
});

test("operator config: broken file fails closed with an error and no patterns", async () => {
  const dir = tmpRepo();
  const cfgPath = join(dir, "topology.local.mjs");
  writeFileSync(cfgPath, "export default { patterns: [{ label: 5 }] };");
  const cfg = await loadOperatorConfig(cfgPath);
  assert.equal(cfg.present, true);
  assert.ok(cfg.error);
  assert.deepEqual(cfg.patterns, []);
});

test("CLI --init: scaffolds the config, refuses to overwrite, output never contains operator values", () => {
  const dir = tmpRepo();
  const cfgPath = join(dir, "nested", "topology.local.mjs");
  mkdirSync(join(dir, "nested"), { recursive: true });
  const first = spawnSync(process.execPath, [MODULE, "--init", "--config", cfgPath], { encoding: "utf8" });
  assert.equal(first.status, 0, first.stderr);
  assert.ok(existsSync(cfgPath));
  assert.ok(readFileSync(cfgPath, "utf8").includes("GITIGNORED"));
  const second = spawnSync(process.execPath, [MODULE, "--init", "--config", cfgPath], { encoding: "utf8" });
  assert.equal(second.status, 1);
  assert.match(second.stderr, /refusing to overwrite/);
});

test("CLI --status: NOT CONFIGURED names what is unchecked; configured lists the pattern labels", async () => {
  const dir = tmpRepo();
  const missing = spawnSync(process.execPath, [MODULE, "--status", "--config", join(dir, "none.mjs")], { encoding: "utf8" });
  assert.equal(missing.status, 0);
  assert.match(missing.stdout, /NOT CONFIGURED/);
  assert.match(missing.stdout, /NOT CHECKED: operator hostnames/);
  assert.match(missing.stdout, /universal families/);

  const cfgPath = join(dir, "topology.local.mjs");
  writeFileSync(cfgPath, 'export default { patterns: [{ label: "operator hostname", source: "example-host" }] };');
  const have = spawnSync(process.execPath, [MODULE, "--status", "--config", cfgPath], { encoding: "utf8" });
  assert.equal(have.status, 0);
  assert.match(have.stdout, /CONFIGURED/);
  assert.match(have.stdout, /operator hostname/);
});

test("CLI --scan-tree: clean tree exits 0; a canary tree exits non-zero naming file:line + family without echoing the canary", () => {
  const dir = tmpRepo();
  const clean = spawnSync(process.execPath, [MODULE, "--scan-tree", dir, "--config", join(dir, "none.mjs")], { encoding: "utf8" });
  assert.equal(clean.status, 0, clean.stdout + clean.stderr);

  const dirty = tmpRepo();
  writeFileSync(join(dirty, "leak.txt"), `gateway is ${canaryRfc} per the runbook\nplain line\n`);
  writeFileSync(join(dirty, "ok.txt"), "no shapes here\n");
  const bad = spawnSync(process.execPath, [MODULE, "--scan-tree", dirty, "--config", join(dir, "none.mjs")], { encoding: "utf8" });
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /leak\.txt:1 — RFC1918 private address/);
  assert.ok(!bad.stdout.includes(canaryRfc), "scan output must not echo the canary value");
  assert.match(bad.stdout, /1 hit\(s\)/);
});

test("CLI --scan-tree: exempt paths are skipped even when passed explicitly", () => {
  const dir = tmpRepo();
  mkdirSync(join(dir, "evidence"), { recursive: true });
  writeFileSync(join(dir, "evidence", "note.md"), `sanctioned home canary ${canaryRfc}\n`);
  const r = spawnSync(process.execPath, [MODULE, "--scan-tree", dir, "--config", join(dir, "none.mjs")], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, /1 exempt file\(s\)/);
});

test("CLI --scan-tree: passing an exempt repo directory itself still exempts its contents (repo-keyed check)", () => {
  // Regression for the explicit-argument exemption gap: the scan root IS the
  // exempt directory, so the base-relative path has no evidence/ prefix left
  // and only the repo-relative check can exempt it. Runs against the real
  // checkout's evidence/ (output counts files; values are never echoed).
  const evidenceDir = join(REPO_ROOT, "evidence");
  if (!existsSync(evidenceDir)) return; // public cuts exclude evidence/ — regression targets private checkouts
  const r = spawnSync(
    process.execPath,
    [MODULE, "--scan-tree", evidenceDir, "--config", join(tmpRepo(), "none.mjs")],
    { encoding: "utf8", cwd: REPO_ROOT },
  );
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /exempt file\(s\)/);
  assert.match(r.stdout, /0 hit\(s\)/);
});

test("CLI --scan-tree with no args covers every tracked file even from a subdirectory", () => {
  const r = spawnSync(process.execPath, [MODULE, "--scan-tree"], { encoding: "utf8", cwd: join(REPO_ROOT, "src") });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const scanned = parseInt(/scanned (\d+) file\(s\)/.exec(r.stdout)?.[1] ?? "0", 10);
  assert.ok(scanned > 50, `expected a repo-wide scan, saw only ${scanned} file(s)`);
});
