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
//    scan gate in docs/publishing.md step 4 (runbook re-cut procedure).
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
// Accepted residuals — MIRRORS the "Accepted residuals" record in
// docs/publishing.md. Every entry: path + value-free line pattern + date +
// reason. Operator values NEVER appear here (they live only in the gitignored
// operator config); a pin describes the SHAPE of the accepted lines instead.
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
    pattern: /private Gitea|^No RFC1918 addresses\b/,
    date: "2026-10-07",
    reason:
      "pre-existing: the origin-remote line and the binding rule paragraph that names the private host domain; AGENTS.md is the system-of-record doc, scrubbed on public cuts",
  },
  {
    path: "test/topology-rules.test.js",
    pattern: /canary/i,
    date: "2026-10-07",
    reason:
      "documented fake canary values from the story's I/O matrix — the suite must exercise the universal families on purpose; every canary-carrying line is marked 'canary'",
  },
  {
    path: "test/local.test.js",
    pattern: /localEnv|localBaseUrl|r\.url\b|"http:\/\/cfg:|shim\.example/,
    date: "2026-10-07",
    reason:
      "local-backend fixtures naming the operator shim port on generic or operator hosts; awaiting the operator's accept-or-genericize decision",
  },
  {
    path: "tools/battery.mjs",
    pattern: /curl -s http:\/\/|id: "s7"/,
    date: "2026-10-07",
    reason:
      "pre-existing safe-case battery row naming the operator shim; awaiting the operator's accept-or-genericize decision",
  },
  {
    path: "tools/demo-dryrun.mjs",
    pattern: /JEV_BASE_URL|SYSTEMONE_URL|http:\/\/10\./,
    date: "2026-10-07",
    reason:
      "degraded-mode demo pointing at a dead shim address on the operator network; awaiting the operator's accept-or-genericize decision",
  },

  {
    path: "tools/battery-secrets.mjs",
    pattern: /\b(?:sk-|ghp_|AKIA|vck_|xai-)/,
    date: "2026-10-07",
    reason:
      "synthetic secret-shaped fixtures — the secrets battery must contain shaped fakes to exercise the guard; bodies are not real credentials",
  },
  {
    path: /(^|\/)(package\.json|plugin\.json|gemini-extension\.json)$|marketplace\.json$/,
    pattern: /"(?:repository|homepage|bugs|url|source|description|author)"/,
    date: "2026-10-07",
    reason:
      "package/plugin metadata fields naming the private origin and homelab brand; genericized on public cuts",
  },
  {
    path: /^plugins\/unjangled-guardrails\//,
    pattern: /JEV_BASE_URL|SYSTEMONE_URL|your-shim|semif|router\.env|key now lives|remains the source|author:/i,
    date: "2026-10-07",
    reason:
      "adapter install notes naming the operator hosts, shim port, and key locations; awaiting the operator's accept-or-genericize decision",
  },
  {
    path: "README.md",
    pattern: /JEV_BASE_URL|SYSTEMONE_URL|your-shim/,
    date: "2026-10-07",
    reason:
      "install doc's example env line names the shim port on a generic placeholder host; port value awaits an operator accept-or-genericize call",
  },
  {
    path: "VENDORED.md",
    pattern: /SemIf|Qwen|shim|staged at/i,
    date: "2026-10-07",
    reason:
      "provenance notes naming the brain project and operator hosts; awaiting the operator's accept-or-genericize decision",
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

// Scan ONE line of ONE path. Returns the family (string) that matched, or null.
// Order: accepted residuals first (they exempt the line from every family),
// then universal families, then operator patterns.
export function scanLine(path, line, config) {
  if (matchesResidual(path, line)) return null;
  for (const { family, re } of UNIVERSAL_FAMILIES) {
    if (re.test(line)) return family;
  }
  for (const { label, re } of config?.patterns ?? []) {
    if (re.test(line)) return `operator topology (${label})`;
  }
  return null;
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
    if (text.includes("\0")) continue; // binary
    const lines = text.split("\n");
    scanned += lines.length;
    for (let i = 0; i < lines.length; i++) {
      if (matchesResidual(repoRel, lines[i])) {
        residualLines++;
        continue;
      }
      const family = scanLine(repoRel, lines[i], config);
      if (family) hits.push({ path: repoRel, line: i + 1, family });
    }
  }
  for (const h of hits) console.log(`topology-rules: ${h.path}:${h.line} — ${h.family}`);
  console.log(
    `topology-rules: scanned ${files.length - exemptFiles - unreadable} file(s), ${scanned} line(s); ` +
      `${exemptFiles} exempt file(s), ${residualLines} residual line(s), ${hits.length} hit(s)` +
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

async function main(argv) {
  const args = argv.slice(2);
  const configPath = configFlag(args);
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
    await cmdScanTree({ paths: rest, configPath });
    return;
  }
  if (cmd === "--help" || cmd === undefined) {
    console.log("usage: node tools/topology-rules.mjs --init | --status | --scan-tree [paths...] [--config <path>]");
    console.log("  --init       scaffold the gitignored operator config (.githooks/topology.local.mjs)");
    console.log("  --status     report configured families and what is unchecked");
    console.log("  --scan-tree  runbook leak gate (docs/publishing.md step 4); default: git-tracked files; exit 1 on non-exempt hits");
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
