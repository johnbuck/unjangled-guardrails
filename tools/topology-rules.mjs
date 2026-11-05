// topology-rules — single source of truth for the no-topology rule (AGENTS.md).
//
// Pure JS (no deps), house style mirrored from vendor/secrets-guard-core/rules.mjs:
// exported check functions return a deny FAMILY (string) or null; block messages
// name file:line + family and NEVER echo the matched text (it may be a real
// hostname, username, or address).
//
// Two layers, mirroring the secrets corpus principle "shapes travel, values
// stay home":
//  - universal families built in: RFC1918 addresses, Tailscale CGNAT addresses,
//    hostname-shaped .lan/.local names, secret-shaped tokens.
//  - operator-specific values (real hostnames, usernames, private URLs, ports)
//    load from the gitignored .githooks/topology.local.mjs — so the tracked
//    tree, and every public cut of it, carries no topology by construction.
//
// Consumers:
//  - .githooks/pre-commit: scans staged ADDED lines only (`git diff --cached -U0`),
//    so pre-existing topology in untouched files never blocks unrelated commits
//    and deletions never block.
//  - `node tools/topology-rules.mjs --scan-tree [paths...]`: the executable
//    scan gate in docs/publishing.md step 4 (runbook re-cut procedure);
//    `--require-config` makes that gate refuse to scan when the gitignored
//    operator config is absent or empty (the fresh-cut-worktree case).
//  - test/topology-rules.test.js: the I/O-matrix suite (fake values only).
//
// Exemptions: evidence/** and _bmad-output/** are the two sanctioned homes for
// internal specifics (both are excluded from every public cut). Everything else
// needs a dated entry in RESIDUALS below, mirroring the "Accepted residuals"
// record in docs/publishing.md.
//
// KNOWN LIMITATIONS (behavioral, safe-fail):
//  - families are line-regexes, so a shape split across two lines passes and a
//    quoted example that looks like a private address is also blocked;
//  - \b-sk-… token shapes can match prose-like slugs after a hyphen.

import { existsSync, readdirSync, readFileSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { pathToFileURL, fileURLToPath } from "node:url";
import { dirname, join, relative, resolve, sep } from "node:path";
import { execFileSync } from "node:child_process";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// Where the operator config lives, relative to the repo root. Gitignored
// (see .gitignore); it carries the real values and must never be committed
// and never be scanned by this module.
export const CONFIG_PATH = ".githooks/topology.local.mjs";

// Sanctioned homes for internal specifics; excluded from every public cut.
export const EXEMPT_PATHS = [/^evidence\//, /^_bmad-output\//];

export function isExemptPath(p) {
  return EXEMPT_PATHS.some((re) => re.test(p));
}

// ---------------------------------------------------------------------------
// Universal families (shapes travel). Always enforced, config or not.

const O = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)"; // one dotted-quad octet

export const UNIVERSAL_FAMILIES = [
  {
    family: "RFC1918 private address",
    re: new RegExp(
      `\\b10\\.${O}\\.${O}\\.${O}\\b` +
      `|\\b192\\.168\\.${O}\\.${O}\\b` +
      `|\\b172\\.(?:1[6-9]|2\\d|3[01])\\.${O}\\.${O}\\b`,
    ),
  },
  {
    family: "Tailscale CGNAT address",
    re: new RegExp(`\\b100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])\\.${O}\\.${O}\\b`),
  },
  {
    // A dotted multi-label name ending in .lan/.local. The trailing lookahead
    // rejects only hostname continuations — extension chains (a dot followed
    // by a name character, e.g. settings.local.json) and glued characters —
    // while sentence punctuation after the name still matches. The leading
    // dot-lookbehind keeps dotfile stems like ".env.local" from matching.
    family: "hostname-shaped .lan/.local name",
    re: /(?<!\.)\b[a-z\d](?:[a-z\d-]*[a-z\d])?(?:\.[a-z\d](?:[a-z\d-]*[a-z\d])?)*\.(?:lan|local)(?!\.?[a-z\d-])/i,
  },
  {
    // Provider key shapes with length floors so prose and short examples pass.
    family: "secret-shaped token",
    re: /\b(?:sk-[A-Za-z\d_-]{16,}|ghp_[A-Za-z\d]{20,}|gho_[A-Za-z\d]{20,}|github_pat_[A-Za-z\d_]{22,}|AKIA[0-9A-Z]{16}|vck_[A-Za-z\d_-]{16,}|xai-[A-Za-z\d_-]{16,})\b/,
  },
];

// ---------------------------------------------------------------------------
// The de-identity rule (consolidation 2026-10-20, plan-consolidation-two-layers): NO
// workflow-specific operator shape in src/. The consolidation moved the in-code operator
// shapes (the agent-management plane hardcode, the workflow bookkeeping skip classes, the
// per-install lane examples) into examples/user-policy.default.json; these families hold
// src/ to that. A shape creeping back into code blocks the commit — while the same text in
// examples/, docs/, evidence/ or test/ stays fine (it is data there, not behavior). The
// adapter seam stays out of these families on purpose: "hermes" is a product surface (the
// --agent spelling, the approver env), not a homelab shape.
export const SRC_SCOPED_FAMILIES = [
  {
    family: "workflow-specific identifier in src/ (de-identity)",
    re: /\b(?:paseo|bmad|cognee|uptime-kuma|scrapling|serena|email-mcp)\b/i,
  },
  {
    family: "workflow-specific path in src/ (de-identity)",
    re: /_bmad-output|\/_bmad\/|\.specify\/|\.specify\b/,
  },
];

function isSrcPath(p) {
  const norm = String(p ?? "").replace(/\\/g, "/");
  return norm === "src" || norm.startsWith("src/") || norm.includes("/src/");
}

// ---------------------------------------------------------------------------
// Accepted residuals — MIRRORS the "Accepted residuals" record in
// docs/publishing.md. Every entry: path + value-free line pattern + date +
// reason. Operator values NEVER appear here (they live only in the gitignored
// operator config); a pin describes the SHAPE of the accepted lines instead.
//
// A pin exempts only what its own pattern matches: scanLine masks every
// pinned occurrence and re-runs all families on the remainder, and the
// secret family runs on the original line regardless — so a pin must
// CONSUME the accepted text (mask-to-end-of-line for prose pins, whole
// token shapes for fixture pins), or the line will still block.
//
// `provisional` retired 2026-10-08: the operator accepted all private-side keeps
// with cut-time genericize-or-exclude dispositions (docs/publishing.md "Accepted
// residuals"). Pins here mirror that record entry for entry.
// A path-scoped pin is broader than a value-scoped one; the operator can
// tighten these entries in place at any time — such edits are welcome commits.

export const RESIDUALS = [
  {
    path: "docs/publishing.md",
    pattern: /^RFC1918 ranges\b|^## Scan terms\b/,
    date: "2026-10-07",
    reason:
      "the scan-terms inventory names the identifier families it guards against; this publishing-process doc is genericized or excluded on public cuts",
  },
  {
    path: "AGENTS.md",
    // mask-to-end-of-line from each anchor: the pinned prose (origin-remote
    // line, binding rule paragraph) carries the accepted identifiers after
    // the anchor, and the remainder stays generic
    pattern: /private Gitea.*$|^No RFC1918 addresses\b.*$/,
    date: "2026-10-07",
    reason:
      "pre-existing: the origin-remote line and the binding rule paragraph that names the private host domain; AGENTS.md is the system-of-record doc, scrubbed on public cuts",
  },
  {
    path: "test/topology-rules.test.js",
    // pins the documented fake canary VALUES themselves (mask-and-rescan:
    // only these exact fakes are exempt; any other shape on the line blocks)
    pattern: /\b(?:10\.255\.255\.1|192\.168\.1\.10|172\.16\.4\.9|100\.100\.1\.1|host\.example\.lan|box\.local|sk-canary\d+)\b/,
    date: "2026-10-07",
    reason:
      "documented fake canary values from the story's I/O matrix — the suite must exercise the universal families on purpose; the pin consumes the canary values so only they are exempt",
  },
  {
    path: "test/local.test.js",
    pattern: /localEnv|localBaseUrl|r\.url\b|"http:\/\/cfg:|brain\.example/,
    date: "2026-10-07",
    reason:
      "local-backend fixtures naming the operator brain port on generic or operator hosts; awaiting the operator's accept-or-genericize decision",
  },
  // Retired 2026-10-08 (epic-installer ticket 2): the tools/battery.mjs s7 row and the
  // tools/demo-dryrun.mjs dead-backend line were genericized (example.com / loopback), so
  // their "awaiting accept-or-genericize" residuals lapsed — nothing on those lines needs
  // vouching for anymore. The publishing.md mirror rows went in the same commit.

  {
    path: "tools/battery-secrets.mjs",
    // whole token shapes only (same floors as the secret family): the pin
    // consumes each synthetic token in full, which is what suppresses the
    // always-on secret check for this file's documented fakes
    pattern: /\bsk-[A-Za-z\d_-]{16,}\b|\bghp_[A-Za-z\d]{20,}\b|\bgho_[A-Za-z\d]{20,}\b|\bgithub_pat_[A-Za-z\d_]{22,}\b|\bAKIA[0-9A-Z]{16}\b|\bvck_[A-Za-z\d_-]{16,}\b|\bxai-[A-Za-z\d_-]{16,}\b/,
    date: "2026-10-07",
    reason:
      "synthetic secret-shaped fixtures — the secrets battery must contain shaped fakes to exercise the guard; the pin consumes whole synthetic tokens so only they are exempt",
  },
  {
    path: /(^|\/)(package\.json|plugin\.json|gemini-extension\.json)$|marketplace\.json$/,
    // key-with-colon only: the key is pinned, the VALUE stays scanned — a
    // topology-bearing value on a metadata line must still hit
    pattern: /"(?:repository|homepage|bugs|url|source|description|author)":/,
    date: "2026-10-07",
    reason:
      "package/plugin metadata key names whose values name the private origin and homelab brand; values are still scanned, genericized on public cuts",
  },
  {
    path: /^plugins\/unjangled-guardrails\//,
    // consume-shaped pins: env var names, the brain placeholder WITH its port,
    // backticked host-home paths, and the two provenance sentences that name
    // hosts mid-line — masking the anchor alone would leave the host behind
    pattern: /JEV_BASE_URL|SYSTEMONE_URL|your-brain(?::\d+)?|semif|`\w[\w-]*:~\/[^`]*`|on \S+ remains the source|on \S+ the key now lives|router\.env|author:/i,
    date: "2026-10-07",
    reason:
      "adapter install notes naming the operator hosts, brain port, and key locations; the pin consumes the pinned phrases and the remainder is re-scanned",
  },
  {
    path: "README.md",
    pattern: /JEV_BASE_URL|SYSTEMONE_URL|your-brain(?::\d+)?/,
    date: "2026-10-07",
    reason:
      "install doc's example env line names the brain port on a generic placeholder host; the pin consumes the placeholder WITH its port",
  },
  {
    path: "VENDORED.md",
    // "staged at" masks to end-of-line (the provenance tail carries host
    // paths); "runs CPU-only on <word>" consumes the sentence's host mention
    pattern: /SemIf|Qwen|runs CPU-only on \w+|staged at.*$/i,
    date: "2026-10-07",
    reason:
      "provenance notes naming the brain project and operator hosts; pinned phrases are consumed and the remainder is re-scanned",
  },
  {
    path: /^docs\/session-handoff-.*\.md$/,
    pattern: /./,
    date: "2026-10-08",
    reason:
      "operator session-handoff notes (internal ops detail: local ports, brain host hints); append-only working record; excluded at cut",
  },
  {
    path: "CHANGELOG-fork.md",
    pattern: /./,
    date: "2026-10-07",
    reason:
      "append-only fork history saturated with pre-existing homelab identifiers; history is never rewritten per AGENTS.md; excluded or genericized on public cuts",
  },
  {
    path: /^\.specify\//,
    pattern: /./,
    date: "2026-10-07",
    reason:
      "binding operator-ruling and planning history saturated with pre-existing homelab identifiers; append-only per AGENTS.md; excluded or genericized on public cuts",
  },
];

// True if (path, line) is covered by an accepted residual; returns the entry.
export function matchesResidual(path, line) {
  for (const r of RESIDUALS) {
    const pathHit = typeof r.path === "string" ? path === r.path : r.path.test(path);
    if (pathHit && r.pattern.test(line)) return r;
  }
  return null;
}

// The secret-shaped token family, kept findable: unlike every other family it
// also runs on the ORIGINAL line under a residual pin (see scanLine).
const SECRET_FAMILY = UNIVERSAL_FAMILIES.find((f) => f.family === "secret-shaped token");

// Global variant of a pin/family regex, for masking every pinned occurrence.
function globalized(re) {
  return re.flags.includes("g") ? re : new RegExp(re.source, re.flags + "g");
}

// True if some match of `re` on `line` fully contains the span of match `m`.
function matchCovers(re, line, m) {
  const end = m.index + m[0].length;
  for (const pm of line.matchAll(globalized(re))) {
    if (pm.index <= m.index && end <= pm.index + pm[0].length) return true;
  }
  return false;
}

// Universal families, then (for src/ paths) the de-identity families, then operator
// patterns, against one (possibly masked) line.
function scanFamilies(line, config, path) {
  for (const { family, re } of UNIVERSAL_FAMILIES) {
    if (re.test(line)) return family;
  }
  if (isSrcPath(path)) {
    for (const { family, re } of SRC_SCOPED_FAMILIES) {
      if (re.test(line)) return family;
    }
  }
  for (const { label, re } of config?.patterns ?? []) {
    if (re.test(line)) return `operator topology (${label})`;
  }
  return null;
}

// Scan ONE line of ONE path. Returns the family (string) that matched, or null.
// An accepted residual exempts only the text its pin matches: every pinned
// occurrence is masked out and all families re-run on the remainder, so a
// fresh leak sharing a line with a pin still blocks. One check is inverted
// on purpose — the secret family ALSO runs on the original line, because
// whole-file pins (`/./`) mask the entire line and would otherwise carry a
// freshly pasted token through; a pin suppresses that check only by
// consuming the token itself (the synthetic-fixture residuals do exactly
// that). Never echo the matched text in a family label.
export function scanLine(path, line, config) {
  const pin = matchesResidual(path, line);
  if (!pin) return scanFamilies(line, config, path);
  const masked = line.replace(globalized(pin.pattern), "");
  const hit = scanFamilies(masked, config, path);
  if (hit) return hit;
  const sm = SECRET_FAMILY.re.exec(line);
  if (sm && !matchCovers(pin.pattern, line, sm)) return SECRET_FAMILY.family;
  return null;
}

// ---------------------------------------------------------------------------
// Operator config: .githooks/topology.local.mjs (gitignored, never commits).
// Contract: `export default { operator?: string, patterns: [{ label, source, flags? }] }`.

export async function loadOperatorConfig(configPath) {
  const p = configPath ?? join(REPO_ROOT, CONFIG_PATH);
  if (!existsSync(p)) return { present: false, path: p, patterns: [] };
  try {
    // Cache-buster so repeat imports in one process (tests) see edits.
    const mod = await import(pathToFileURL(p).href + "?t=" + process.hrtime.bigint().toString(36));
    const cfg = mod.default;
    if (!cfg || typeof cfg !== "object" || !Array.isArray(cfg.patterns)) {
      return { present: true, path: p, patterns: [], error: "default export must be { operator?, patterns: [{ label, source, flags? }] }" };
    }
    const patterns = [];
    for (const [i, pat] of cfg.patterns.entries()) {
      if (!pat || typeof pat !== "object" || typeof pat.source !== "string" || typeof pat.label !== "string") {
        return { present: true, path: p, patterns: [], error: `patterns[${i}] needs string fields label and source` };
      }
      patterns.push({ label: pat.label, re: new RegExp(pat.source, pat.flags ?? "") });
    }
    return { present: true, path: p, patterns, operator: typeof cfg.operator === "string" ? cfg.operator : "" };
  } catch (err) {
    return { present: true, path: p, patterns: [], error: String((err && err.message) || err) };
  }
}

// Parse a unified diff (`git diff --cached --unified=0`) into the ADDED lines
// with their new-file line numbers. Deletions and context never appear.
// Hunk-aware: inside a hunk body, a line starting with "+++ " is ADDED
// CONTENT (a committed file may contain such a line), not a file header.
export function parseAddedLines(diffText) {
  const out = [];
  let file = null;
  let line = 0;
  let inHunk = false;
  for (const raw of diffText.split("\n")) {
    if (raw.startsWith("diff --git ")) {
      inHunk = false; // a new file section begins; header lines are trusted again
      continue;
    }
    if (!inHunk && raw.startsWith("+++ ")) {
      const p = raw.slice(4);
      file = p === "/dev/null" ? null : p.startsWith("b/") ? p.slice(2) : p;
      continue;
    }
    if (raw.startsWith("@@")) {
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
      if (m) {
        line = parseInt(m[1], 10);
        inHunk = true;
      }
      continue;
    }
    if (file === null) continue;
    if (raw.startsWith("+")) {
      out.push({ path: file, line, text: raw.slice(1) });
      line++;
      continue;
    }
    if (raw.startsWith("-") || raw.startsWith("\\")) continue; // deletion / "\ No newline"
    if (inHunk) line++; // context line
  }
  return out;
}

// ---------------------------------------------------------------------------
// CLI: --init | --status | --scan-tree [paths...]   (optional: --config <path>)

const TEMPLATE = `// topology.local.mjs — operator topology values. GITIGNORED; never commits.
// Fill the patterns in with REAL values (hostnames, usernames, private URL
// fragments, ports). Entries are JavaScript RegExp sources; flags is optional.
// Check coverage any time:  node tools/topology-rules.mjs --status
// The tracked tree must never contain these values — this file is the only
// sanctioned home for them on this checkout.

export default {
  operator: "fill in a label for this checkout, or leave empty",
  patterns: [
    // { label: "operator hostname", source: "your-hostname-here", flags: "i" },
    // { label: "operator username", source: "your-username-here", flags: "i" },
    // { label: "operator domain", source: "your-domain-suffix-here", flags: "i" },
  ],
};
`;

function fail(msg, code = 1) {
  console.error(`topology-rules: ${msg}`);
  process.exit(code);
}

function configFlag(args) {
  const i = args.indexOf("--config");
  if (i < 0) return undefined;
  const v = args[i + 1];
  if (!v) fail("--config needs a path");
  args.splice(i, 2);
  return v;
}

// --require-config (scan-tree only): refuse to scan at all when the operator
// config is absent or has no patterns — the gate must never pass vacuously
// in a fresh cut worktree (retro finding A).
function requireConfigFlag(args) {
  const i = args.indexOf("--require-config");
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
}

// Longest directory prefix shared by every scan path — the base that
// scan-tree's file:line output and exemption checks are relative to.
function commonAncestor(paths) {
  const abs = paths.map((p) => resolve(p));
  if (abs.length === 1) {
    return statSync(abs[0]).isDirectory() ? abs[0] : dirname(abs[0]);
  }
  let base = abs[0].split(sep);
  for (const parts of abs.slice(1)) {
    const other = parts.split(sep);
    let i = 0;
    while (i < base.length && i < other.length && base[i] === other[i]) i++;
    base = base.slice(0, Math.max(i, 1));
  }
  return base.join(sep) || sep;
}

function walkTree(paths) {
  const files = [];
  const visit = (p) => {
    const st = statSync(p);
    if (st.isDirectory()) {
      for (const e of readdirSync(p)) {
        if (e === "node_modules" || e === ".git") continue;
        visit(join(p, e));
      }
    } else files.push(p);
  };
  for (const p of paths) visit(p);
  return files;
}

async function cmdScanTree(args) {
  const config = await loadOperatorConfig(args.configPath);
  if (config.error) {
    fail(`operator config failed to load (${config.path}): ${config.error} — fix it or remove it; refusing to scan with a broken config`, 2);
  }
  if (args.requireConfig && (!config.present || config.patterns.length === 0)) {
    fail(
      `--require-config: refusing to scan — operator config is ${config.present ? `present but has no patterns (${config.path})` : `absent (${config.path})`}, ` +
        "so operator values (hostnames, usernames, private URLs, ports) would go unchecked. " +
        "Provision the config in this worktree: node tools/topology-rules.mjs --init, fill in the real values " +
        "(the file is gitignored and never commits), confirm node tools/topology-rules.mjs --status prints CONFIGURED, " +
        "then re-run the gate.",
      3,
    );
  }
  let files; // absolute paths
  let base; // exemptions and residuals are keyed on paths relative to the scan base
  if (args.paths.length) {
    files = walkTree(args.paths);
    base = commonAncestor(args.paths);
  } else {
    files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 })
      .split("\0")
      .filter(Boolean)
      .map((p) => join(process.cwd(), p));
    base = process.cwd();
  }
  const hits = [];
  let scanned = 0;
  let exemptFiles = 0;
  let residualLines = 0;
  let unreadable = 0;
  let binary = 0;
  for (const f of files) {
    const rel = relative(base, f).split(sep).join("/");
    // Exemptions are repo-keyed: `--scan-tree evidence` must skip the sanctioned
    // dir however the scan base lands. Scans rooted outside the repo keep the
    // base-relative check so their own layout still applies (the tests use it).
    const repoRel = relative(REPO_ROOT, f).split(sep).join("/");
    if (isExemptPath(rel) || isExemptPath(repoRel) || rel === CONFIG_PATH || repoRel === CONFIG_PATH) {
      exemptFiles++;
      continue;
    }
    let text;
    try {
      text = readFileSync(f, "utf8");
    } catch {
      unreadable++; // tallied and surfaced in the summary; the file itself is skipped
      continue;
    }
    if (text.includes("\0")) {
      binary++; // tallied and surfaced in the summary; the file itself is skipped
      continue;
    }
    const lines = text.split("\n");
    scanned += lines.length;
    for (let i = 0; i < lines.length; i++) {
      // Pinned lines still count as accepted residual lines, but scanLine no
      // longer exempts them wholesale: it masks the pinned occurrences and
      // re-scans the remainder (fresh leaks on pinned lines now block).
      if (matchesResidual(repoRel, lines[i])) residualLines++;
      const family = scanLine(repoRel, lines[i], config);
      if (family) hits.push({ path: repoRel, line: i + 1, family });
    }
  }
  for (const h of hits) console.log(`topology-rules: ${h.path}:${h.line} — ${h.family}`);
  console.log(
    `topology-rules: scanned ${files.length - exemptFiles - unreadable - binary} file(s), ${scanned} line(s); ` +
      `${exemptFiles} exempt file(s), ${residualLines} residual line(s), ${hits.length} hit(s)` +
      (binary ? `, ${binary} binary file(s) skipped` : "") +
      (unreadable ? `, ${unreadable} UNREADABLE file(s)` : "") +
      (config.present ? "" : "; NOTE operator values are NOT checked — no operator config"),
  );
  if (hits.length || unreadable) process.exit(1);
}

async function cmdStatus({ configPath }) {
  const config = await loadOperatorConfig(configPath);
  const rel = (p) => relative(process.cwd(), p).split(sep).join("/") || p;
  console.log("topology-rules status");
  console.log(`  universal families (always enforced): ${UNIVERSAL_FAMILIES.map((f) => f.family).join("; ")}`);
  if (!config.present) {
    console.log(`  operator config: NOT CONFIGURED (${rel(join(REPO_ROOT, configPath ?? CONFIG_PATH))} absent)`);
    console.log("  NOT CHECKED: operator hostnames, usernames, private URLs, ports — every operator-specific value.");
    console.log("  setup: node tools/topology-rules.mjs --init   (the config file is gitignored and never commits)");
  } else if (config.error) {
    console.log(`  operator config: BROKEN (${rel(config.path)})`);
    console.log(`    error: ${config.error}`);
    console.log("  NOT CHECKED: operator values — the gate fails closed until the file parses.");
  } else if (!config.patterns.length) {
    console.log(`  operator config: PRESENT, 0 patterns (${rel(config.path)})`);
    console.log("  NOT CHECKED: operator hostnames, usernames, private URLs, ports — fill the patterns in.");
  } else {
    console.log(`  operator config: CONFIGURED (${rel(config.path)}${config.operator ? `, ${config.operator}` : ""})`);
    for (const p of config.patterns) console.log(`    - ${p.label}`);
    console.log("  NOT CHECKED: only operator values not listed above — add a pattern per new identifier family.");
  }
  console.log(`  exempt paths: ${EXEMPT_PATHS.map((r) => r.source.replace(/\\\//g, "/")).join(", ")} (sanctioned homes; excluded from public cuts)`);
  console.log(`  accepted residuals: ${RESIDUALS.length} entries (${RESIDUALS.filter((r) => r.provisional).length} provisional) — see docs/publishing.md "Accepted residuals"`);
}

// --verify-cut: runbook step 4b gate (2026-10-24 incident). Asserts, against the
// COMMITTED tree at HEAD — never the index or workdir; the 2026-10-24 leak shipped
// because the scan saw the index before a later `git add` re-added the exclusions:
//   1. HEAD is a single-root orphan (rev-list --count HEAD === 1);
//   2. no committed path matches the cut-exclusion families;
//   3. the committed CONTENT of every file scans clean against all families
//      (universal + operator) — no exemptions apply inside a correct cut.
// Exit 0 is the only push permission (docs/publishing.md step 4b).
const CUT_EXCLUSIONS = [
  /^_bmad\//,
  /^_bmad-output\//,
  /^\.specify\//,
  /^evidence\//,
  /^CHANGELOG-fork\.md$/,
  /^docs\/session-handoff-/,
  /^user-policy\.json$/,
  /^rulings\.json$/,
  /^rulings-use\.jsonl$/,
  /^\.claude\//,
];

// Pure core, exported for unit tests: given the already-gathered facts, return
// the assertion failures. readContent(path) -> string | null (null = skipped,
// e.g. binary); config feeds scanLine the same way scan-tree does.
export function verifyCutCore({ count, paths, config, readContent }) {
  const failures = [];
  if (count !== 1) failures.push(`history count is ${count}, expected 1 — the cut must be a single-root orphan commit`);
  const privatePaths = paths.filter((p) => CUT_EXCLUSIONS.some((re) => re.test(p)));
  if (privatePaths.length) {
    failures.push(
      `${privatePaths.length} cut-excluded path(s) are committed: ${privatePaths.slice(0, 8).join(", ")}${privatePaths.length > 8 ? " …" : ""}`,
    );
  }
  const hits = [];
  let scanned = 0;
  for (const p of paths) {
    if (CUT_EXCLUSIONS.some((re) => re.test(p))) continue;
    const text = readContent(p);
    if (text === null) continue;
    const lines = text.split("\n");
    scanned += lines.length;
    for (let i = 0; i < lines.length; i++) {
      const family = scanLine(p, lines[i], config);
      if (family) hits.push({ path: p, line: i + 1, family });
    }
  }
  if (hits.length) {
    failures.push(
      `${hits.length} scan hit(s) in committed content: ${hits.slice(0, 8).map((h) => `${h.path}:${h.line} — ${h.family}`).join("; ")}${hits.length > 8 ? " …" : ""}`,
    );
  }
  return { failures, hits, scanned, privatePaths };
}

async function cmdVerifyCut({ configPath }) {
  const config = await loadOperatorConfig(configPath);
  if (config.error) {
    fail(`operator config failed to load (${config.path}): ${config.error} — fix it or remove it; refusing to verify with a broken config`, 2);
  }
  const count = Number(execFileSync("git", ["rev-list", "--count", "HEAD"], { encoding: "utf8" }).trim());
  const paths = execFileSync("git", ["ls-tree", "-r", "--name-only", "-z", "HEAD"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 })
    .split("\0")
    .filter(Boolean);
  const { failures, hits, scanned, privatePaths } = verifyCutCore({
    count,
    paths,
    config,
    readContent: (p) => {
      try {
        const text = execFileSync("git", ["show", `HEAD:${p}`], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
        return text.includes("\0") ? null : text;
      } catch {
        return null;
      }
    },
  });
  for (const f of failures) console.error(`topology-rules --verify-cut: ${f}`);
  console.log(
    `topology-rules --verify-cut: history count ${count}; ${paths.length - privatePaths.length} committed file(s) scanned, ${scanned} line(s); ` +
      `${hits.length} scan hit(s); ${privatePaths.length} excluded-path violation(s); ${failures.length} assertion failure(s)`,
  );
  if (failures.length) process.exit(1);
}

async function main(argv) {
  const args = argv.slice(2);
  const configPath = configFlag(args);
  const requireConfig = requireConfigFlag(args);
  const [cmd, ...rest] = args;
  if (cmd === "--init") {
    cmdInit(rest, configPath);
    return;
  }
  if (cmd === "--status") {
    await cmdStatus({ configPath });
    return;
  }
  if (cmd === "--scan-tree") {
    if (!rest.length) process.chdir(REPO_ROOT); // no-args gate scans the whole tracked tree from any cwd
    await cmdScanTree({ paths: rest, configPath, requireConfig });
    return;
  }
  if (cmd === "--verify-cut") {
    await cmdVerifyCut({ configPath });
    return;
  }
  if (cmd === "--help" || cmd === undefined) {
    console.log("usage: node tools/topology-rules.mjs --init | --status | --scan-tree [paths...] [--require-config] [--config <path>]");
    console.log("  --init       scaffold the gitignored operator config (.githooks/topology.local.mjs)");
    console.log("  --status     report configured families and what is unchecked");
    console.log("  --scan-tree  runbook leak gate (docs/publishing.md step 4); default: git-tracked files; exit 1 on non-exempt hits");
    console.log("    --require-config  refuse to scan (non-zero) when the operator config is absent or has no patterns — the cut-gate variant; never pass vacuously");
    console.log("  --verify-cut runbook step 4b gate (docs/publishing.md): run AFTER the orphan commit; asserts single-root history, no cut-excluded paths, and a clean committed-content scan; exit 0 is the only push permission");
    return;
  }
  fail(`unknown command ${cmd} — see --help`);
}

function cmdInit(args, configPath) {
  const target = args[0] ?? configPath ?? join(REPO_ROOT, CONFIG_PATH);
  if (existsSync(target)) fail(`refusing to overwrite existing ${relative(process.cwd(), target) || target} — edit it in place`);
  writeFileSync(target, TEMPLATE);
  try {
    chmodSync(target, 0o600);
  } catch {
    /* best effort */
  }
  console.log(`topology-rules: scaffolded ${relative(process.cwd(), target) || target}`);
  console.log("topology-rules: fill in the real values (hostnames, usernames, private URLs, ports).");
  console.log("topology-rules: the file is gitignored and never commits; it is the only sanctioned home for operator values.");
  console.log("topology-rules: check coverage any time with: node tools/topology-rules.mjs --status");
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) await main(process.argv);
