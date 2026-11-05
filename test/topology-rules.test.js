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
  verifyCutCore,
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
// a NON-canary CGNAT address, assembled at runtime so this file's source
// stays shape-free: the value leaks at runtime, never in the tracked text
const freshCgnat = ["100", "101", "1", "1"].join(".");

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
  // the pin consumes the accepted canary values only: an unpinned value in
  // the same file still blocks
  assert.match(scanLine("test/topology-rules.test.js", `const other = "${freshCgnat}";`, noCfg), /CGNAT/);
});

test("residuals: a pin exempts only the pinned term — a fresh leak on the same line still blocks (retro B)", () => {
  const noCfg = { patterns: [] };
  const line = `canary note ${canaryRfc} beside a fresh ${freshCgnat} address`;
  assert.ok(matchesResidual("test/topology-rules.test.js", line)); // the pin matches the accepted value
  assert.match(scanLine("test/topology-rules.test.js", line, noCfg), /CGNAT/); // …and the remainder still blocks
});

test("residuals: secret-shaped tokens never pass, even in whole-file-pinned paths (retro B)", () => {
  const noCfg = { patterns: [] };
  const pasted = `note: token ${canaryToken} left in the file`;
  for (const p of ["CHANGELOG-fork.md", ".specify/ruling-xyz.md", "docs/session-handoff-2099-01-01.md"]) {
    assert.ok(matchesResidual(p, pasted)); // the /./ whole-file pin accepts the line…
    assert.match(scanLine(p, pasted, noCfg), /secret-shaped/); // …but secrets are checked regardless
  }
  // a token starting the line survives whole-line masking — still blocked on the original line
  assert.match(scanLine("CHANGELOG-fork.md", `${canaryToken} at line start`, noCfg), /secret-shaped/);
});

test("residuals: metadata-key pin exempts the key, not the value — a topology-bearing value still hits (retro B)", () => {
  const noCfg = { patterns: [] };
  const line = `"url": "http://${canaryLan}"`;
  assert.ok(matchesResidual("package.json", line)); // the narrowed key pin still matches…
  assert.match(scanLine("package.json", line, noCfg), /\.lan\/\.local/); // …but the value is still scanned
  assert.equal(scanLine("package.json", '"url": "https://example.com/a"', noCfg), null);
  // key-like words without the colon are not pinned at all
  assert.equal(matchesResidual("package.json", 'the "url" field is documented'), null);
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

test("CLI --scan-tree --require-config: refuses without scanning when the config is absent, empty, or fine when CONFIGURED", () => {
  const clean = tmpRepo();
  writeFileSync(join(clean, "ok.txt"), "no shapes here\n");
  const common = [MODULE, "--scan-tree", clean, "--require-config"];

  // absent config: non-zero exit, clear provisioning message, no scan summary
  const absent = spawnSync(process.execPath, [...common, "--config", join(tmpRepo(), "none.mjs")], { encoding: "utf8" });
  assert.notEqual(absent.status, 0);
  assert.match(absent.stderr, /--require-config/);
  assert.match(absent.stderr, /--init/);
  assert.match(absent.stderr, /CONFIGURED/);
  assert.doesNotMatch(absent.stdout ?? "", /scanned \d+ file/);

  // present but zero patterns: still vacuous coverage — refuse
  const cfgDir = tmpRepo();
  const cfgPath = join(cfgDir, "topology.local.mjs");
  writeFileSync(cfgPath, "export default { patterns: [] };");
  const empty = spawnSync(process.execPath, [...common, "--config", cfgPath], { encoding: "utf8" });
  assert.notEqual(empty.status, 0);
  assert.match(empty.stderr, /no patterns/);

  // configured: the gate runs and a clean tree passes as before
  writeFileSync(cfgPath, 'export default { patterns: [{ label: "operator hostname", source: "example-host", flags: "i" }] };');
  const pass = spawnSync(process.execPath, [...common, "--config", cfgPath], { encoding: "utf8" });
  assert.equal(pass.status, 0, pass.stdout + pass.stderr);
  assert.match(pass.stdout, /scanned 1 file\(s\)/);
});

test("CLI --scan-tree: binary files are tallied as skipped and do not fail the gate (retro E)", () => {
  const dir = tmpRepo();
  writeFileSync(join(dir, "blob.bin"), `ok\x00not-text\nplain\n`);
  writeFileSync(join(dir, "ok.txt"), "no shapes here\n");
  const r = spawnSync(process.execPath, [MODULE, "--scan-tree", dir, "--config", join(dir, "none.mjs")], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /1 binary file\(s\) skipped/);
  assert.match(r.stdout, /scanned 1 file\(s\)/);
});

test("mirror: docs/publishing.md accepted-residuals table matches the RESIDUALS array entry for entry (retro C)", () => {
  const md = readFileSync(join(REPO_ROOT, "docs", "publishing.md"), "utf8");
  const rows = [];
  let inTable = false;
  for (const ln of md.split("\n")) {
    if (/^\| Path \|/.test(ln)) {
      inTable = true;
      continue;
    }
    if (!inTable) continue;
    if (!ln.startsWith("|")) break; // table ended
    if (/^\|---/.test(ln)) continue; // separator row
    rows.push(ln.split("|")[1].trim()); // the Path cell
  }
  assert.ok(rows.length >= 10, "expected to find the accepted-residuals table");

  // Canonical keys: the table groups the manifest files as ONE row and the
  // array carries them as ONE regex — both count as one entry a side.
  const GROUPED = "manifest metadata (grouped row)";
  const canonTable = (cell) => (/marketplace\.json/.test(cell) ? GROUPED : cell.replaceAll("`", "").trim());
  const canonArray = (r) => {
    if (typeof r.path === "string") return r.path;
    const src = r.path.source;
    if (src.includes("marketplace")) return GROUPED;
    if (src.includes("plugins")) return "plugins/unjangled-guardrails/**";
    if (src.includes("session-handoff")) return "docs/session-handoff-*.md";
    if (/specify/.test(src)) return ".specify/**";
    return src;
  };

  const tableKeys = rows.map(canonTable);
  const arrayKeys = RESIDUALS.map(canonArray);
  assert.equal(
    tableKeys.length,
    arrayKeys.length,
    `mirror drifted: table has ${tableKeys.length} row(s), RESIDUALS has ${arrayKeys.length} entry(ies) — fix both in one commit`,
  );
  const tableSet = new Set(tableKeys);
  const arraySet = new Set(arrayKeys);
  for (const k of arraySet) assert.ok(tableSet.has(k), `RESIDUALS entry [${k}] has no dated row in docs/publishing.md`);
  for (const k of tableSet) assert.ok(arraySet.has(k), `docs/publishing.md row [${k}] has no RESIDUALS entry`);
});

// --verify-cut (2026-10-24 incident): the committed tree itself is the assertion
// surface — the scan-then-add ordering hole shipped 454 private paths past a
// passing index scan and a passing history count.
test("verify-cut: clean single-root cut passes with zero failures", () => {
  const r = verifyCutCore({
    count: 1,
    paths: ["README.md", "src/guard.js", ".claude-plugin/plugin.json"],
    config: { patterns: [] },
    readContent: (p) => (p === "README.md" ? "# public cut\n" : "export const x = 1;\n"),
  });
  assert.deepEqual(r.failures, []);
});

test("verify-cut: history count above 1 fails with the named assertion", () => {
  const r = verifyCutCore({ count: 3, paths: ["README.md"], config: { patterns: [] }, readContent: () => "# x\n" });
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /history count is 3/);
});

test("verify-cut: a cut-excluded committed path fails and is named", () => {
  const r = verifyCutCore({
    count: 1,
    paths: ["README.md", "evidence/live-verify.jsonl", "_bmad-output/initiative-x/plan.md"],
    config: { patterns: [] },
    readContent: () => null,
  });
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /2 cut-excluded path\(s\)/);
  assert.match(r.failures[0], /evidence\/live-verify\.jsonl/);
});

test("verify-cut: a family hit hiding in committed content fails", () => {
  const r = verifyCutCore({
    count: 1,
    paths: ["README.md"],
    config: { patterns: [] },
    readContent: (p) => (p === "README.md" ? `deploy target: ${canaryLan}\n` : null),
  });
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /1 scan hit\(s\)/);
  assert.match(r.failures[0], /\.lan\/\.local/);
});
