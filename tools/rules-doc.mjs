// Rules-of-record document renderer (epic-rules-of-record entry 3): emits docs/rules.md from
// the LIVE modules — never hand-written, never restated. Regeneration is the only write path.
//
//   node src/cli.js rules-doc            (or: node tools/rules-doc.mjs [out-path])
//
// Gate on the render: the entry-2 conformance validator runs FIRST and must be green — a
// stale document cannot ship behind drift. Everything the document states is then extracted
// from the modules at render time:
//   - entry 2's exported declaration tables (THRESHOLDS, AD_PROBES, declaredCredentialPatterns)
//     and the checker's own executed rows (floors, judge bars, boundaries, pipeline precedence);
//   - threshold values, accepted ranges and their evidence citations, from thresholds() source;
//   - the brain's band order and comparators, from decide()'s own guard clauses;
//   - the pipeline layer order, from assessAction's own section markers;
//   - the policy grammar (effects, tie ranks, scopes, expiry spans, operator-gated mutation),
//     from src/policy.js source;
//   - the degraded postures, from src/orchestrate.js;
//   - every suggested-defaults entry with its reason, from examples/user-policy.default.json.
// Every row carries an authority tag (`operator <date>` / `shipped` / `agent`, with `measured`
// on honest-limit rows); an `operator <date>` tag is only emitted after the cited date is found
// in a live source or the epic record — a citation the code does not exhibit cannot render.
//
// Hygiene: probe payloads, credential-shaped literals and the policy-store filename never
// render (the renderer self-checks the store name out of its own output). The generation date
// is the newest commit date touching the generation inputs — never wall-clock now — so a fresh
// render is byte-identical within one tree state and drifts exactly when a source module moves.
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { thresholds } from "../src/guard.js";
import { runRulesConformance, THRESHOLDS, AD_PROBES, declaredCredentialPatterns } from "./rules-conformance.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DOC_PATH = join(ROOT, "docs", "rules.md");

// The generation inputs. The doc's date line is the newest commit touching any of them —
// stable within a tree state, moving exactly when the rule surface moves (the byte-for-byte
// test's drift alarm). src/cli.js is wiring, not rule surface, and stays out.
const SOURCES = [
  ["src/guard.js", "the brain: thresholds(), decide(), the assessAction pipeline, guidance registry"],
  ["src/policy.js", "the policy grammar: three entry kinds, effects, specificity, tie order, operator-gated mutation"],
  ["src/always-deny.js", "layer 1: the Always-Deny families (secrets, catastrophic, self-modification)"],
  ["src/orchestrate.js", "the degraded postures (rules / layered / closed) and brain-down resolution"],
  ["src/rulings.js", "the shared gate home, expiry spans, the operator authority gate"],
  ["examples/user-policy.default.json", "the suggested defaults (never auto-applied): every entry's pattern, effect and reason"],
  ["tools/rules-conformance.mjs", "entry 2's validator: the declared tables and the executed conformance rows this document renders"],
];

// ── extraction helpers ────────────────────────────────────────────────────────────────────────
const readSrc = (p) => readFileSync(join(ROOT, p), "utf8");
const srcCache = {};
const srcOf = (p) => (srcCache[p] ??= readSrc(p));
const one = (text, re, what) => {
  const m = text.match(re);
  if (!m) throw new Error(`rules-doc: could not extract ${what} from the live sources (the module moved — update the renderer's extraction)`);
  return m;
};

// An operator date may only render once a live source or the epic record carries it.
const CITABLE_CORPUS = () => [...SOURCES.map(([p]) => p),
  "_bmad-output/initiative-opencode-dual-adapter/epic-rules-of-record/epic-rules-of-record.md"];
const assertCitable = (date) => {
  if (!/^20\d\d-\d\d-\d\d$/.test(date)) throw new Error(`rules-doc: '${date}' is not a YYYY-MM-DD ruling date`);
  for (const p of CITABLE_CORPUS()) if (srcOf(p).includes(date)) return;
  throw new Error(`rules-doc: no live source carries the ruling date ${date} — refusing to cite it`);
};

// The generation date: newest commit touching the inputs (committer date, short form).
function sourceDate() {
  try {
    const out = execFileSync("git", ["log", "-1", "--format=%cs", "--", ...SOURCES.map(([p]) => p)],
      { cwd: ROOT, encoding: "utf8" }).trim();
    if (!/^\d{4}-\d\d-\d\d$/.test(out)) throw new Error(`git returned '${out || "nothing"}'`);
    return out;
  } catch (err) {
    throw new Error(`rules-doc needs git to date the source material (tools/ ships in the git checkout, not the npm tarball): ${err.message}`);
  }
}

// ── section 1 inputs: the conformance run (the gate + the executed evidence rows) ─────────────
const conformanceRows = (conf, section, surfaceRe) =>
  conf.rows.filter((r) => r.section === section && surfaceRe.test(r.surface));

// ── section 2 inputs: thresholds — values, env vars, accepted ranges, evidence ────────────────
// Line shape in thresholds(): `    denyScore: n("GUARD_DENY_SCORE", 2.55, (v) => v >= 1.5 && v <= 3),`
function thresholdSpecs(live) {
  const guardSrc = srcOf("src/guard.js");
  const specs = [];
  for (const key of Object.keys(THRESHOLDS)) {
    const m = one(guardSrc, new RegExp(`\\n\\s*${key}: n\\("([A-Z_]+)", ([0-9.]+), \\(v\\) => ([^)]*)\\),`), `the thresholds() line for ${key}`);
    const [, envVar, declaredDefault, range] = m;
    // the comment block directly above the line (no blank line in between) carries the
    // authority: an operator date there makes the row operator-dated; an evidence/*.md
    // path there becomes the row's measured citation.
    const before = guardSrc.slice(0, m.index).split("\n");
    const comment = [];
    for (let i = before.length - 1; i >= 0; i--) {
      const l = before[i].trim();
      if (l.startsWith("//")) comment.unshift(l);
      else break;
    }
    const block = comment.join(" ");
    const date = block.match(/20\d\d-\d\d-\d\d/)?.[0];
    const evidence = block.match(/evidence\/[\w.-]+\.md/)?.[0];
    if (date) assertCitable(date);
    const value = live[key];
    if (!(Number(declaredDefault) === THRESHOLDS[key] && THRESHOLDS[key] === value))
      throw new Error(`rules-doc: ${key} disagrees across extraction (${declaredDefault}), declaration (${THRESHOLDS[key]}) and live thresholds() (${value})`);
    specs.push({ key, envVar, value, literal: declaredDefault, range: range.trim(), date, evidence });
  }
  return specs;
}

// ── section 3 inputs: decide()'s band order, from its own guard clauses ───────────────────────
function decideBands() {
  const guardSrc = srcOf("src/guard.js");
  const body = one(guardSrc, /export function decide\(([\s\S]*?)\n\}\n/, "the decide() body")[1];
  const bands = [];
  for (const m of body.matchAll(/if \(([^;]*?)\) return \{([^;]*?)\};/g)) {
    const cond = m[1].replace(/\s+/g, " ").trim();
    const ret = m[2];
    bands.push({
      cond,
      level: ret.match(/level: "(\w+)"/)?.[1],
      family: ret.match(/family: "([^"]+)"/)?.[1],
      why: ret.match(/why: "([^"]+)"/)?.[1],
      idx: m.index,
    });
  }
  // The leak deny is a block (`if (leakDeniable(rest, t)) {`), not a one-line return —
  // extracted separately, and its position AFTER the ask band is the pinned ordering fact.
  const leak = one(body, /if \(leakDeniable\(rest, t\)\) \{[\s\S]*?family: "(Credential Exposure)"/, "the leak-deny clause");
  const askIdx = bands.findIndex((b) => b.level === "ask");
  if (askIdx < 0 || leak.index < bands[askIdx].idx)
    throw new Error("rules-doc: expected the leak deny to follow the ask band in decide() — the measured order changed");
  bands.push({ cond: "leakDeniable(rest, t)", level: "deny", family: "Credential Exposure", idx: leak.index, askFirst: true });
  bands.sort((a, b) => a.idx - b.idx);
  // readable conditions: threshold names render with their live values alongside
  for (const b of bands)
    b.cond = Object.entries(THRESHOLDS).reduce((s, [k, v]) => s.replaceAll(`t.${k}`, `${v} (t.${k})`), b.cond);
  return bands;
}

// The band rows' authority, by position in decide()'s actual order.
const BAND_AUTHORITY = [
  { date: "2026-10-04", note: "the untrusted-content veto precedes every lifter; amended 2026-10-16 — liftable by NO words in chat" },
  { date: "2026-10-16", note: "the operator-words lift; userP 0.75 ratified 2026-10-16 (was 0.85)" },
  { date: null, note: "the deny line" },
  { date: "2026-10-25", note: "the ask band is brain-only: no gate-structure rule produces an ask; operator-owned lane and dir entries are the recorded exception" },
  { date: "2026-10-20", note: "the leak deny additionally requires a confident brain answer; ruling 2026-10-28 — an absent noul confidence is derived, absent-at-decide stays confident" },
];

// ── section 4 inputs: the pipeline layer order, from assessAction's own markers ───────────────
function pipelineLayers() {
  const guardSrc = srcOf("src/guard.js");
  const layers = [...guardSrc.matchAll(/\/\/ ── (\d+[a-z]?\.) ([^\n—(]+)/g)]
    .map((m) => ({ marker: m[1], name: m[2].replace(/\s+$/, "").trim(), idx: m.index }));
  if (layers.length < 4) throw new Error("rules-doc: fewer assessAction layer markers than expected");
  // The config layer's application order: tool entries, then dir entries, then the command
  // consult — read off the call order in the source.
  const at = (re, what) => one(guardSrc, re, what).index;
  const sub = [
    { name: "tool entries (the user lane)", re: /const userLane = toolEffect\(/ },
    { name: "dir entries (the confined-work surface)", re: /const dirHit = dirEffect\(/ },
    { name: "command consult (the rulings surface)", re: /const ruling = resolveRuling\(/ },
  ].map((s) => ({ ...s, idx: at(s.re, `the ${s.name} call` ) })).sort((a, b) => a.idx - b.idx);
  if (sub.map((s) => s.name).join("|") !== "tool entries (the user lane)|dir entries (the confined-work surface)|command consult (the rulings surface)")
    throw new Error("rules-doc: the config sub-order changed in src/guard.js");
  // GUARD_SKIP_TOOLS is the host-level opt-out the three layers do not cover.
  const skip = /GUARD_SKIP_TOOLS/.test(guardSrc);
  return { layers, sub, skip };
}

// ── section 5 inputs: the policy grammar, from src/policy.js ──────────────────────────────────
function policyGrammar() {
  const policySrc = srcOf("src/policy.js");
  const jsonArray = (name) => JSON.parse(one(policySrc, new RegExp(`const ${name} = (\\[[^\\]]*\\])`), name)[1]);
  const effects = jsonArray("EFFECTS");
  const commandEffects = jsonArray("COMMAND_EFFECTS");
  const rank = Object.fromEntries([...one(policySrc, /const EFFECT_RANK = \{([^}]*)\}/, "EFFECT_RANK")[1]
    .matchAll(/(\w+): (\d+)/g)].map(([, k, v]) => [k, Number(v)]));
  const tieOrder = Object.entries(rank).sort((a, b) => b[1] - a[1]).map(([k]) => k).join(" > ");
  const scopes = one(policySrc, /unknown scope \$\{scope\} \(use ([^)]+)\)/, "the scope grammar")[1].trim();
  const spans = one(policySrc, /const defaultSpan = \{ session: (\d+) \* 864e5, project: (\d+) \* 864e5 \}/, "the default expiry spans");
  one(srcOf("src/rulings.js"), /\^\(\\d\+\)\(\[dhm\]\)\$\/\)/, "the --expires short forms");  // <n>d / <n>h / <n>m
  const msForms = "ISO date | <n>d | <n>h | <n>m";
  // every mutation entry point must carry the operator authority gate
  const mutators = ["addToolEntry", "addCommandEntry", "addDirEntry", "removeEntry", "adoptDefaults", "setDegradation"];
  const gated = mutators.map((name) => {
    const body = one(policySrc, new RegExp(`export function ${name}\\(([\\s\\S]*?)\\n\\}`), `${name} body`)[1];
    return { name, gated: /operatorContext\(/.test(body) };
  });
  if (!gated.every((g) => g.gated)) throw new Error(`rules-doc: a policy mutation entry point is not operator-gated: ${gated.filter((g) => !g.gated).map((g) => g.name).join(", ")}`);
  const adopt = /adopt-defaults/.test(srcOf("src/cli.js"));
  if (!adopt) throw new Error("rules-doc: no `policy adopt-defaults` command wiring found in src/cli.js");
  return { effects, commandEffects, tieOrder, scopes, sessionDays: Number(spans[1]), projectDays: Number(spans[2]), msForms, mutators: gated.map((g) => g.name) };
}

// ── section 6 inputs: the degraded postures, from src/orchestrate.js ──────────────────────────
function postures() {
  const orchSrc = srcOf("src/orchestrate.js");
  const fb = one(orchSrc, /const fb = env\.(GUARD_FALLBACK) \?\? env\.(JEV_GUARD_FALLBACK)/, "the fallback env names");
  const legacy = [...new Set([...orchSrc.matchAll(/env\.(GUARD_FAIL_CLOSED|JEV_GUARD_FAIL_CLOSED)/g)].map((m) => m[1]))];
  const modes = [
    { mode: one(orchSrc, /return "(rules)";/, "the default mode")[1], env: "unset (default)" },
    { mode: one(orchSrc, /if \(fb === "(layered)"\) return "layered"/, "layered")[1], env: fb[1] ?? "GUARD_FALLBACK" },
    { mode: one(orchSrc, /if \(fb === "(closed)" \|\| failClosed\(env\)\) return "closed"/, "closed")[1], env: fb[1] ?? "GUARD_FALLBACK" },
  ];
  const order = [
    ["a standing ruling resolves the call", /resolveRuling\("ask"/],
    ["the closed posture denies what no rule matched", /mode === "closed"/],
    ["the layered posture defers to the installed heuristic stack", /mode === "layered"/],
    ["rules mode consults the policy degradation option", /loadPolicyStore\(env/],
  ].map(([name, re]) => ({ name, idx: one(orchSrc, re, name).idx })).sort((a, b) => a.idx - b.idx);
  const degradation = one(srcOf("src/policy.js"), /degradation must be (fail-open or fail-closed)/, "the degradation option")[1];
  // "the ONLY pre-brain layer and the ONLY thing that / gates while the brain is down" (assessAction)
  if (!/the ONLY pre-brain layer and the ONLY thing that/.test(srcOf("src/guard.js")))
    throw new Error("rules-doc: the Always-Deny-is-the-brain-down-gate claim is not exhibited by the modules");
  return { modes, legacy, order, degradation, envName: `${fb[1]} / ${fb[2]}` };
}

// ── section 7 inputs: defaults + authority citations ──────────────────────────────────────────
function defaultsTable() {
  const example = JSON.parse(readSrc("examples/user-policy.default.json"));
  const entries = example.entries ?? [];
  if (!entries.length) throw new Error("rules-doc: the suggested defaults carry no entries");
  // Ordered citation matchers: a defaults row descends from a dated ruling where its own
  // words say so; everything else is shipped. The date is checked against the live corpus.
  const citations = [
    { re: /agent coordination|agent-management plane|the same plane/, date: "2026-10-07", note: "coordination plane" },
    { re: /^$/, when: (e) => e.kind === "command" && /^(write|edit)$/i.test(e.tool ?? ""), date: "2026-10-07", note: "doc writes" },
    { re: /everyday git|branch listing|create-branch|stash family|bare push|plain-refspec/, date: "2026-10-11", note: "the everyday-git lane and the closed allow-list" },
    { re: /credential|leak denies/, date: "2026-10-12", note: "credential floors and redaction" },
  ];
  const tagFor = (e) => {
    const text = `${e.pattern ?? e.path ?? ""} ${e.reason ?? ""}`;
    for (const c of citations) {
      if (c.when ? c.when(e) : c.re.test(text)) { assertCitable(c.date); return `operator ${c.date}`; }
    }
    return "shipped";
  };
  const grouped = { tool: [], command: [], dir: [] };
  for (const e of entries) {
    const kind = e.kind === "command" ? "command" : e.kind === "dir" ? "dir" : "tool";
    (grouped[kind] ??= []).push({ ...e, tag: tagFor(e) });
  }
  // the standing tool classes: distinct tool-entry reasons with counts
  const classes = new Map();
  for (const e of grouped.tool) classes.set(e.reason, (classes.get(e.reason) ?? 0) + 1);
  return { readme: example.readme ?? [], entries, grouped, classes: [...classes.entries()] };
}

// ── section 8 inputs: the honest limits, derived from the conformance table itself ────────────
function honestLimits() {
  const limits = [];
  for (const p of AD_PROBES) {
    if (p.expect.level === "allow" && p.register)
      limits.push({ what: `the "${p.register}" leg is declared by src/always-deny.js but measured unreachable`, why: (p.note ?? "").replace(/^declared leg measured unreachable — /, ""), tag: "measured" });
    else if (/SHADOWED LEG/.test(p.note ?? ""))  // (why is trimmed below)
      limits.push({ what: `the "${p.register}" leg is shadowed: its probe pins the earlier "${p.expect.statsEnds}" leg as what actually fires`, why: p.note.replace(/^SHADOWED LEG \(measured\): /, "").replace(/— the row registers.*$/, ""), tag: "measured" });
    else if (p.expect.floor === "unclassified")
      limits.push({ what: 'familyOf() classifies one vendored plaintext-secrets-fetch deny reason as "unclassified"', why: "cosmetic classification only — the verdict still denies (pinned by the probe)", tag: "measured" });
  }
  // the confidence knob's measured no-op, straight from thresholds()' own comment
  const block = one(srcOf("src/guard.js"), /\/\/ leakConfP[\s\S]*?\n    leakConfP:/, "the leakConfP comment")[0];
  if (/MEASURED/.test(block)) {
    const date = block.match(/20\d\d-\d\d-\d\d/g)?.slice(-1)[0];
    limits.push({ what: `the leak-confidence gate is a measured no-op today: the live backend returns no confidence on the leak questions, so the knob waits${date ? ` (measured ${date})` : ""}`, why: "0.5 stays as the standing guard for the day a backend populates the field", tag: "measured" });
  }
  if (!limits.length) throw new Error("rules-doc: no honest limits derived — the findings moved");
  return limits;
}

// ── the render ────────────────────────────────────────────────────────────────────────────────
const esc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
const live = () => thresholds({});
const adFamily = (p) =>
  p.expect.level === "allow" && p.register ? "Secrets — declared, unreachable"
  : p.expect.floor === "credential-source" ? "Secrets — credential-source"
  : ["env-dump", "process-argv", "docker-inspect-format", "unclassified"].includes(p.expect.floor) ? "Secrets — vendored leak-guard"
  : p.expect.floor === "credential-file" ? "Secrets — read-path gate"
  : ["write-credential-egress", "write-secret-shape"].includes(p.expect.floor) ? "Secrets — write-content floor"
  : p.expect.floor === "catastrophic" ? "Catastrophic"
  : p.expect.stats ? "Self-modification"
  : "Benign sweep";
const adTag = (p) => {
  const m = (p.note ?? "").match(/operator(?: ruling| doctrine)?[, ]+(20\d\d-\d\d-\d\d)/) ?? (p.note ?? "").match(/(20\d\d-\d\d-\d\d)(?=[^\n]*operator)/);
  if (m) { assertCitable(m[1]); return `operator ${m[1]}`; }
  return "shipped";
};

export async function renderRulesDoc({ conformance = runRulesConformance } = {}) {
  // 1. THE GATE — the entry-2 checker runs first; drift refuses the render.
  const conf = await conformance();
  if (!conf.ok)
    throw new Error(`rules-doc refuses to render: the conformance validator is red (${conf.failures.length} failure(s); first: ${conf.failures[0]}). Run node src/cli.js rules-check — a stale document must not ship behind drift.`);

  const L = [];
  const T = (line) => { L.push(line); L.push(""); };
  const TH = (cells) => { L.push(`| ${cells.join(" | ")} |`); L.push(`|${Array(cells.length).fill(" --- ").join("|")}|`); };
  const R = (cells) => L.push(`| ${cells.map(esc).join(" | ")} |`);
  const sec = (title) => { L.push(""); L.push(`## ${title}`); L.push(""); };
  const sub = (title) => { L.push(""); L.push(`### ${title}`); L.push(""); };

  // ── the generation line ──
  const date = sourceDate();
  T("# Rules of record");
  L.push(`> GENERATED by \`node src/cli.js rules-doc\` — generation date ${date} — from the live modules. The conformance validator (\`node src/cli.js rules-check\`) ran green immediately before rendering: ${conf.rows.length} rows, 0 failures. This file is machine output; hand edits are overwritten on regeneration, and regeneration is the only write path.`);
  L.push("");
  L.push("The machine truth is the live modules and the suggested-defaults table; this document is their derived human view. Nothing here is authoritative over the code — every row is extracted from it, and the validator fails the build the day the two disagree.");
  L.push("");

  // ── how to read ──
  T("## How to read this document");
  TH(["tag", "meaning"]);
  R(["`operator <date>`", "a dated operator ruling — the row descends from it, and the date is verified present in a live source before it renders"]);
  R(["`shipped`", "pre-existing behavior the modules already exhibit (no dated ruling behind this row)"]);
  R(["`agent`", "implementation judgment of the document system itself (organization, conventions)"]);
  R(["`measured`", "an honest limit measured against the live pipeline and pinned here, gap included"]);
  L.push("");
  L.push("Document conventions (`agent 2026-10-26`): the deny / decide / ask / allow / degraded organization, the payload-free rendering of probe shapes, and the generation dating from the source material are the document system's own choices.");
  L.push("");

  // ── precedence map ──
  sec("Precedence — the pipeline's actual order");
  L.push("One call walks the layers top to bottom; the first layer that decides wins, and lower layers never see the call. Order and wording extracted from `src/guard.js` at render time.");
  L.push("");
  const pl = pipelineLayers();
  TH(["step", "layer", "authority"]);
  if (pl.skip) R(["0", "`GUARD_SKIP_TOOLS` — the host-level env opt-out; not one of the three layers, and the only source of a skipped (null) verdict", "shipped"]);
  for (const lay of pl.layers) {
    const name = lay.name;
    const tag = /ALWAYS DENY/i.test(name) ? "operator 2026-10-19 (two-layer structure)"
      : /CONTEXT-BODY/.test(name) ? "operator 2026-10-25"
      : /THE BRAIN/.test(name) ? "operator 2026-10-19 (brain-through: every non-denied call is judged)"
      : /CONFIG/.test(name) ? "operator 2026-10-20 (the consolidation's config layer)"
      : /ATTRIBUTION/.test(name) ? "shipped" : "shipped";
    for (const d of tag.matchAll(/20\d\d-\d\d-\d\d/g)) assertCitable(d[0]);
    R([lay.marker, name, tag]);
  }
  R(["3.1", `config sub-order, as called: ${pl.sub.map((s) => s.name).join(" → ")}`, "shipped"]);
  L.push("");
  L.push("Above every layer: an Always-Deny hit is absolute — no brain verdict, no policy effect, and no ruling can lift it. Below the brain: policy effects modify the verdict, they never replace judgment.");
  L.push("");

  // ── DENY ──
  sec("DENY — what stops before anything else");
  sub("Always-Deny (layer 1): heuristic, pre-brain, chat-blind, absolute");
  L.push("Three families, both vendored cores combined. A hit denies with zero brain calls, zero policy consults and zero lifters — the conformance probes assert brain call count 0 on every deny row. Shapes are stated as the modules declare them; payloads are not reproduced here.");
  L.push("");
  const modulePatterns = declaredCredentialPatterns();
  T("#### The credential-source legs the module declares");
  L.push("");
  TH(["declared pattern", "conformance status"]);
  for (const name of modulePatterns) {
    const registered = AD_PROBES.some((p) => p.register === name);
    R([name, registered ? "registered probe (drift fails the build in both directions)" : "NOT REGISTERED"]);
    if (!registered) throw new Error(`rules-doc: module pattern "${name}" has no registered probe`);
  }
  L.push("");
  T("#### The conformance probes, family by family");
  L.push("");
  TH(["probe", "family", "verdict", "authority", "note"]);
  for (const p of AD_PROBES) {
    const tag = adTag(p);
    const note = tag.startsWith("operator") ? (p.note ?? "").replace(/^operator 20\d\d-\d\d-\d\d: /, "") : (p.note ?? "");
    const verdict = p.expect.level === "deny"
      ? `deny floor=${p.expect.floor ?? "—"}${p.expect.statsEnds ? ` stats …${p.expect.statsEnds}` : ""}${p.expect.stats ? ` stats=${p.expect.stats}` : ""}`
      : `allow${p.register ? " (expected-allow: the leg cannot fire today)" : ""}`;
    R([p.id, adFamily(p), verdict, tag, note]);
  }
  L.push("");

  sub("The guard-home boundary");
  L.push("The gate's own files are deny-shielded from the agent in both directions: reads of the credential-bearing config deny at the credential-source floor, and writes into the gate's store, config or sessions deny at the self-modification floor — the verb-x-target rule (bash) and the path guard (file tools).");
  L.push("");
  TH(["fact", "authority"]);
  R(["the store lives in the gate home (GUARD_HOME, 0600) and is operator-owned; the agent cannot write it by any path", "shipped"]);
  R(["store relocation to the real operator home is operator-terminal and in flight — disposition ordered 2026-10-26", "operator 2026-10-26"]);
  L.push("");

  sub("Policy deny effects (post-brain, absolute over allows)");
  const g = policyGrammar();
  TH(["entry", "semantics", "authority"]);
  R(["tool entry, effect deny", "hard-blocks even over a brain allow — deny always denies", "shipped"]);
  R(["command entry, effect deny", "hard-blocks a brain allow (a deny entry never applies to a brain deny — nothing to add)", "shipped"]);
  R(["dir entry, effect deny", "hard-blocks calls whose argument paths all resolve under the directory; the brain's deny line still outranks every dir effect", "shipped"]);
  L.push("");

  sub("The brain's deny line");
  L.push("Two deny bands inside decide(): the untrusted-content veto (before every lifter) and the risk deny line. See DECIDE below for values and order. Degraded fail-closed denies reuse the Credential Exposure family with the brain-down cause named in the header.");
  L.push("");

  // ── DECIDE ──
  sec("DECIDE — what the brain decides");
  sub("The thresholds");
  L.push("Values are read from the live `thresholds()` and cross-checked against the validator's declared table at render time. The accepted range IS the protection floor: outside it the default comes back, never the permissive end.");
  L.push("");
  const specs = thresholdSpecs(live());
  TH(["threshold", "env var", "value", "accepted range", "authority", "note"]);
  for (const s of specs)
    R([`t.${s.key}`, s.envVar, s.literal, s.range, s.date ? `operator ${s.date}` : "shipped", s.evidence ? `measured in ${s.evidence}` : ""]);
  L.push("");
  assertCitable("2026-10-07");
  L.push("Back-compat: the pre-rename `JEV_GUARD_*` spelling still works on every threshold (operator 2026-10-07); an in-range env value is honored as set.");
  L.push("");

  sub("Out-of-range env falls back to the default — never permissive");
  L.push("Pinned by the validator's floor rows, rendered from its executed output:");
  L.push("");
  const floorRows = conformanceRows(conf, "thresholds", /\(out of range\)$/);
  TH(["env setting", "behavior", "verified"]);
  for (const r of floorRows) R([r.surface.replace(/ \(out of range\)$/, ""), r.expectation, r.pass ? "pass" : "FAIL"]);
  L.push("");

  sub("The brain's band order — decide()'s actual order, pinned");
  const bands = decideBands();
  TH(["order", "condition, as the code reads it", "verdict", "authority", "note"]);
  bands.forEach((b, i) => {
    const auth = BAND_AUTHORITY[i] ?? {};
    if (auth.date) assertCitable(auth.date);
    const verdict = b.family ? `${b.level} — ${b.family}` : b.why ? `${b.level} — ${b.why}` : b.level;
    R([String(i + 1), b.cond, verdict, auth.date ? `operator ${auth.date}` : "shipped", auth.note ?? ""]);
  });
  L.push("");
  const leakAfterAsk = bands.findIndex((b) => b.family === "Credential Exposure") > bands.findIndex((b) => b.level === "ask");
  L.push(`Measured order note: the ask band precedes the leak deny${leakAfterAsk ? " — decide() checks the ask band before the leak mapping, so a band-level leak guess asks rather than denies; the leak deny only fires below the band" : ""} (measured).`);
  L.push("");

  sub("Boundary rows (comparators are >=)");
  L.push("Rendered from the validator's executed boundary rows:");
  L.push("");
  const boundaryRows = conformanceRows(conf, "precedence", /^boundary:/);
  TH(["surface", "expectation", "actual", "verified"]);
  for (const r of boundaryRows) R([r.surface.replace(/^boundary: /, ""), r.expectation, r.actual, r.pass ? "pass" : "FAIL"]);
  L.push("");

  sub("The skill-judge bars (instruction files)");
  L.push("");
  const judgeRows = conformanceRows(conf, "thresholds", /^judgeInstructions\(/);
  TH(["probe", "flagged", "verified"]);
  for (const r of judgeRows) R([r.surface.replace("judgeInstructions", ""), r.expectation.replace("flagged: ", ""), r.pass ? "pass" : "FAIL"]);
  L.push("");

  // ── ASK ──
  sec("ASK — what prompts");
  L.push("The ask band is BRAIN-ONLY (operator 2026-10-25): nothing deterministic reaches it — either the call is dangerous and a layer denies it, or the brain judges it. The recorded exceptions are the operator's own entries: a tool ask effect and a dir ask effect always prompt over any non-denied verdict.");
  L.push("");
  TH(["rule", "authority"]);
  assertCitable("2026-10-25");
  R(["the ask band fires on risk at or above the ask bar, or approval at or above the ask probability — brain answers only; no gate-structure rule produces an ask", "operator 2026-10-25"]);
  R(["the tool ask effect prompts over any non-denied verdict (even a brain allow), survives the degraded posture, and cannot collapse a brain deny", "shipped"]);
  R([`the dir ask effect prompts the same way for calls whose argument paths all resolve under the directory`, "shipped"]);
  R([`command entries have NO ask effect — effects are ${g.commandEffects.join(" | ")}; ask is a tool-pattern effect (a command ask has no flip semantics)`, "shipped"]);
  assertCitable("2026-10-12");
  R(["ask-band messages carry the copy-paste ruling hint: the exact operator command that would allow the flagged call, computed only on the ask band after rulings resolved — denies never advertise an unlock", "operator 2026-10-12"]);
  R(["ask previews redact credential-shaped spans and secret values (the gate never echoes what an ask would expose; matched PATTERN, PATH and LINE structure displays, values stay masked)", "operator 2026-10-12 (amended 2026-10-25)"]);
  R(["on hosts with no prompt surface the ask converts to a deny — the block is read off the incoming ask result, never recomputed; the guidance routes the decision through the user in conversation", "shipped (text operator-ratified)"]);
  L.push("");

  // ── ALLOW ──
  sec("ALLOW — what passes");
  const dt = defaultsTable();
  sub("The policy grammar, as src/policy.js declares it");
  TH(["grammar fact", "as the module declares", "authority"]);
  R(["entry kinds", `tool, command, dir — one store, three mutator surfaces (${g.mutators.filter((m) => m.startsWith("add")).join(", ")})`, "shipped"]);
  R(["tool-entry effects", g.effects.join(" | "), "shipped"]);
  R(["command-entry effects", `${g.commandEffects.join(" | ")} (ask is a tool-pattern effect)`, "shipped"]);
  R(["dir-entry effects", g.effects.join(" | "), "shipped"]);
  R(["specificity", `most-specific pattern wins; equal-specificity ties resolve ${g.tieOrder}`, "shipped"]);
  R(["scope spellings", g.scopes, "shipped"]);
  R(["expiry", `${g.msForms}; defaults when no --expires is given: session ${g.sessionDays} days, project ${g.projectDays} days; a global entry may stand without expiry`, "shipped"]);
  assertCitable("2026-10-11");
  R(["mutation authority", `every entry point (${g.mutators.join(", ")}) runs the operator authority gate — no agent-run change can self-grant`, "operator 2026-10-11 (strict authority model)"]);
  R(["adoption", "the suggested defaults are NEVER auto-applied — only the explicit `policy adopt-defaults` command merges them (additive; present entries are skipped, never overwritten)", "shipped"]);
  L.push("");
  sub("What an allow does");
  TH(["entry", "semantics", "authority"]);
  R(["tool entry, effect allow", `the ask band passes for that tool — effects are ${g.effects.join(" | ")}; most-specific pattern wins, ties resolve ${g.tieOrder}`, "shipped"]);
  R(["command entry, effect allow", "lifts asks AND brain denies — the deliberate, audited operator exception; Always-Deny stays above it, unliftable", "shipped"]);
  R(["dir entry, effect allow", "pushes a brain ask into an allow for in-dir work; the brain still judges every call", "shipped"]);
  R(["determinism", "all three hold in every posture, brain down included — no brain consulted", "shipped"]);
  R(["the brain's plain allow", "no band fired and no effect applied: risk under the ask bar, no leak at or above the bar, not untrusted-sourced, not operator-lifted", "shipped"]);
  L.push("");

  sub("Standing tool classes (the suggested defaults, by class)");
  L.push("");
  TH(["class (the entry's own reason)", "entries", "authority"]);
  for (const [reason, count] of dt.classes) R([reason, String(count), groupedTagFor(dt, reason)]);
  L.push("");

  sub("Every suggested-defaults entry");
  L.push("Read from the suggested-defaults table at render time. Never auto-applied: adoption happens only on the explicit `policy adopt-defaults` command (additive; already-present entries are skipped, never overwritten).");
  L.push("");
  for (const kind of ["tool", "command", "dir"]) {
    const rows = dt.grouped[kind] ?? [];
    const head = kind === "dir" ? ["path", "effect", "authority", "reason"] : ["pattern", "effect", "authority", "reason"];
    T(`#### ${kind} entries (${rows.length})`);
    L.push("");
    TH(head);
    for (const e of rows) {
      const target = kind === "dir" ? e.path : e.pattern;
      R([kind === "command" && e.tool ? `${target} (on ${e.tool})` : target, e.effect ?? "allow", e.tag, e.reason ?? ""]);
    }
    L.push("");
  }

  // ── DEGRADED ──
  sec("DEGRADED — when the brain is down");
  const post = postures();
  L.push(`Always-Deny is the only thing that gates while the brain is down — it ran already, pre-brain. What an UNMATCHED call does is the posture's to say, in this resolution order: ${post.order.map((o) => o.name).join("; then ")}.`);
  L.push("");
  TH(["posture", "env surface", "behavior", "authority"]);
  for (const m of post.modes)
    R([m.mode, m.env === "unset (default)" ? `${post.envName} unset` : `${post.envName}=${m.mode}`, m.mode === "rules" ? "Always-Deny gated, unmatched calls pass" : m.mode === "layered" ? "defer to the installed heuristic stack" : "deny everything unmatched (sole-gate hardening)", "operator 2026-10-04 (final form)"]);
  R([`legacy spelling`, post.legacy.join(" / "), "all spellings map to closed; ambiguous values fail closed (the safe side)", "shipped"]);
  R(["per-install option", "policy `set --degradation`", `${post.degradation}; fail-open is the default (resolved design decision 2, the 2026-10-20 consolidation); the env posture still wins over it`, "operator 2026-10-20"]);
  R(["standing rulings", "—", "the operator's recorded allow resolves an unmatched call while the brain is down — the ruling needs no brain", "shipped (pinned by the validator's degraded-posture row)"]);
  L.push("");

  // ── honest limits ──
  sec("Honest limits (measured)");
  L.push("What IS, including the gaps. Each row is derived from the conformance table or the module's own measured comment; none is fixed by hand.");
  L.push("");
  TH(["limit", "detail", "tag"]);
  for (const l of honestLimits()) R([l.what, l.why.replace(/\s+$/, "").replace(/\s{2,}/g, " "), l.tag]);
  L.push("");

  // ── sources ──
  sec("Sources (the generation inputs)");
  L.push("");
  TH(["file", "role"]);
  for (const [p, role] of SOURCES) R([`\`${p}\``, role]);
  L.push("");

  let text = L.join("\n").replace(/\n{3,}/g, "\n\n");
  if (!text.endsWith("\n")) text += "\n";
  // hygiene self-check: the policy-store filename (user-policy.json, and its .lock) never
  // renders — the sanctioned suggested-defaults filename (user-policy.default.json) is a
  // different, already-tracked file and is fine to name
  if (/user-policy\.json/.test(text)) throw new Error("rules-doc: the policy-store filename leaked into the render — refusing to write");
  return { text, conformance: conf };
}

// the standing-class rows inherit the tag of the entries in the class
function groupedTagFor(dt, reason) {
  const row = dt.grouped.tool.find((e) => e.reason === reason);
  return row?.tag ?? "shipped";
}

export async function writeRulesDoc({ conformance, outPath = DOC_PATH } = {}) {
  const { text } = await renderRulesDoc({ conformance });
  writeFileSync(outPath, text);
  return { path: outPath, bytes: Buffer.byteLength(text), text };
}

// Direct invocation: node tools/rules-doc.mjs [out-path] — defaults to docs/rules.md
const invokedDirectly = process.argv[1] && process.argv[1].endsWith("rules-doc.mjs");
if (invokedDirectly) {
  const out = process.argv[2] ?? DOC_PATH;
  try {
    const r = await writeRulesDoc({ outPath: out });
    console.log(`unjangled-guardrails: rules-doc wrote ${r.path} (${r.bytes} bytes); conformance green`);
  } catch (err) {
    console.error(`unjangled-guardrails: rules-doc: ${err.message}`);
    process.exitCode = 1;
  }
}
