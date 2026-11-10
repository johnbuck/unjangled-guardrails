// CAP-1 (epic-installer ticket 2): defaults name no host, brain, or key of ours. The topology
// guard scrubs public cuts at publish time; this test holds the CLONE ITSELF to the same bar —
// every tracked file outside the exempt trees (evidence/, _bmad-output/) scans clean against
// the universal families, with the internal forge name pinned explicitly as a regression fence.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { EXEMPT_PATHS, scanLine } from "../tools/topology-rules.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));

// The forge-name pin, split-constructed so no single line carries the operator domain (the
// topology guard scans added lines; a literal here would need its own residual entry). This
// fences the internal forge hostname itself — see the retirement note in docs/publishing.md.
const FORGE_PIN = new RegExp(["dried", "550"].join(""));

// Record carriers: intentional internal spellings, governed by the residuals regime rather
// than this test — AGENTS.md is the private rules doc (it must name the patterns it forbids),
// docs/publishing.md is the residual-sanctioned process doc, CHANGELOG-fork.md is dated
// history (the same rule that keeps old env-var spellings in old entries). The topology
// families still scan them; only the forge-name pin skips them.
const RECORD_CARRIERS = [/^AGENTS\.md$/, /^docs\/publishing\.md$/, /^CHANGELOG-fork\.md$/];

test("tracked tree scans clean: no RFC1918, no homelab hostname, no internal forge name", () => {
  const files = execFileSync("git", ["ls-files"], { cwd: REPO, encoding: "utf8" }).split("\n").filter(Boolean);
  const hits = [];
  for (const f of files) {
    if (EXEMPT_PATHS.some((r) => r.test(f))) continue;  // the sanctioned homes of internal specifics
    let lines;
    try { lines = readFileSync(join(REPO, f), "utf8").split("\n"); } catch { continue; }
    lines.forEach((line, i) => {
      const family = scanLine(f, line, { present: false, patterns: [] });
      if (family) hits.push(`${f}:${i + 1} ${family}`);
      if (!RECORD_CARRIERS.some((r) => r.test(f)) && FORGE_PIN.test(line)) hits.push(`${f}:${i + 1} internal forge name (operator domain pin)`);
    });
  }
  assert.deepEqual(hits, [], `topology hits in tracked files:\n${hits.join("\n")}`);
});
