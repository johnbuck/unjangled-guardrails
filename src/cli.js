#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const [cmd, ...rest] = process.argv.slice(2);

const USAGE = `unjangled-guardrails — prompt-injection and dangerous-action guard for coding agents, powered by Jev

  unjangled-guardrails hook [--agent codex|copilot|hermes]  Command hook (JSON on stdin → JSON on stdout) for Claude Code, Codex, Copilot CLI,
                                                 Gemini CLI and Cursor; the host is detected from the payload, --agent overrides
  unjangled-guardrails acp -- <agent command...>            ACP proxy: unjangled-guardrails acp -- claude-agent-acp
  unjangled-guardrails check <tool> '<json input>'          Assess one tool call, e.g. check Bash '{"command":"rm -rf /"}'
  unjangled-guardrails scan [file]                          Scan a file (or stdin) for AI-directed instructions
  unjangled-guardrails scan-skills [paths...]               Sweep skills, plugins, rules and CLAUDE.md/AGENTS.md files (default: every
                                                 agent's user dirs + the current project) for instructions their installer
                                                 would not expect; cached by content hash, exit 2 if anything is flagged
  unjangled-guardrails install [<agent>] [--v2] [--force] [--ask-permissions] [--home <dir>]  Register in that agent's user config:
                                                           claude | codex | copilot | gemini | cursor | pi | opencode
                                                             (<agent> optional; detected when omitted: the CLAUDECODE env
                                                             marker first, else the single registration file under HOME —
                                                             several registrations or none print the candidates, exit 1)
                                                           (one install = the whole plugin: brain + rulings + orchestrator)
                                                           opencode: --v2 writes the v2 adapter (default-export {id, setup}). Before
                                                           writing, opencode reads any existing unjangled-guardrails.js in both
                                                           plugin dirs and refuses a mismatched or ambiguous generation
                                                           takeover — --force writes anyway, warning printed. --ask-permissions
                                                           prints the opencode.json permission snippet and its tradeoff (it
                                                           prompts on EVERY bash call, not just the gate-flagged ones); nothing
                                                           is written for it, and the default install stays silent on the
                                                           permission topic. --home
                                                           retargets every target's HOME tree (tests use a fixture copy, not
                                                           your profile)
  unjangled-guardrails verify <harness>                     Live-verify that harness's REAL surface with the battery's must-pass
                                                 safe call and must-stop destructive call (probes are scored, never
                                                 executed); appends evidence/live-verify-<harness>-<date>.jsonl.
                                                 Harnesses: opencode | claude | pi | codex | copilot | gemini | cursor
  unjangled-guardrails rules-check                          Conformance validator (rules-of-record): executes the DECLARED rule
                                                 surface — thresholds, Always-Deny families, defaults-table entries,
                                                 precedence — through the real assessAction pipeline offline (scripted
                                                 brain, scratch homes); prints the table and exits 1 on any drift in
                                                 either direction (declared-but-not-actual, actual-but-not-declared)
  unjangled-guardrails rules-doc                            Regenerate the rules-of-record document (docs/rules.md) from the live
                                                 modules — the only write path the document has. Runs rules-check
                                                 first and refuses on drift; hand edits are overwritten
  unjangled-guardrails setup [<agent>]                      One commanded path from clone to a verified first session: install that
                                                 agent's hooks, create the empty operator rulings store, live-verify the
                                                 REAL surface, and print the seven-section readiness report (backend /
                                                 registration / rulings / policy / posture / verification / calibration —
                                                 the policy section WARNs loudly while the policy is empty, naming the
                                                 suggested defaults and the adopt command; the posture section names the
                                                 active brain-down posture, how it was set, and the one-line command to
                                                 change it; adoption is never automatic) with one evidence row
                                                 (<agent> optional; detected when omitted — same detection as install)
  unjangled-guardrails calibrate [--url <u> [--key <k>]] [--quick]  Self-certify a brain (--url/--key are a pair and override the configured
                                                 backend: env or config file; cloud backends take their keys from their own
                                                 env/config) against the battery corpus through the wire contract
                                                 directly — ask + the gate's own decide(), no guard pipeline:
                                                 per-class report (safe/destructive/tricky), ask-band rows annotated
                                                 and never fatal; exit 1 only when a safe case is denied, a destructive
                                                 case is allowed, or a destructive case goes unanswered; appends
                                                 evidence/calibrate-<date>.jsonl. --quick: one sample per class (partial
                                                 run, flagged as such)
  unjangled-guardrails key <api key>                        Save the key to ~/.unjangled-guardrails/config.json (0600); vck_… keys are
                                                 treated as Vercel AI Gateway keys, anything else as TypeSafe
  unjangled-guardrails key --local <url> [key]              Save a local Jev-compatible backend URL (and optional bearer key)
  unjangled-guardrails key --infisical --project <id>       Restore the local brain key from Infisical using the machine
                                                 identity (~/.config/infisical/*.env); [--env prod]
                                                 [--secret SYSTEM_ONE_API_KEY]. The key value never
                                                 appears in argv or output — the gate's own code does
                                                 the fetch and writes the 0600 config.
  unjangled-guardrails policy add|list|remove|set|adopt-defaults|where   The CONFIG layer: operator-owned, per-install policy entries.
                                                 Three kinds: tool entries (--tool <pattern>, effects
                                                 allow|deny|ask — exact, server-wide 'mcp__server*', or
                                                 verb-class 'mcp__*@read'), command entries
                                                 (--pattern '<command glob>', effects allow|deny, with
                                                 --scope global|project[:path]|session:<id> and --expires
                                                 ISO|7d|12h|30m|never), and directory entries (--dir <absolute
                                                 path>, effects allow|deny|ask, optional --expires in the
                                                 same grammar — absent = permanent: calls whose argument
                                                 paths all resolve under the directory — an ask becomes
                                                 allow for that in-dir work; deny hard-blocks; ask always
                                                 prompts; the brain's deny line and Always-Deny outrank).
                                                 set --degradation fail-open|fail-closed
                                                 chooses the brain-down posture (fail-open default).
                                                 remove takes an id, pattern, or dir path.
                                                 adopt-defaults merges examples/user-policy.default.json on
                                                 explicit command — never auto-applied; alternate example
                                                 files adopt BY NAME (the opt-in git-work file:
                                                 policy adopt-defaults examples/user-policy.git-work.json)
                                                 where prints the policy store per surface (this terminal,
                                                 the default store, every harness's recorded store, and
                                                 registered installs with no record yet); every command
                                                 names the store it touched and warns when a recorded
                                                 harness reads a different one
                                                 Run \`policy add --help\` (or \`policy --help\`) for the
                                                 per-kind flag matrix — which flags each entry kind takes
  unjangled-guardrails ruling init|add|list|revoke          Alias of policy (one release): init creates the stranger-owned
                                                 empty store (agent-runnable, idempotent); add keeps the old
                                                 refusal of a global ruling without --expires
  unjangled-guardrails lane add|list|remove                 Alias of policy for tool entries (the user-lane surface)
  unjangled-guardrails decision export [--from <path>]      Emit the decision-record export document (docs/decision-records.md, format v1)
                                                 as 2-space JSON on stdout: the redacted v:1 rows verbatim under a
                                                 header naming the stores and the format. Default reads BOTH
                                                 stores (<gate home>/decisions-candidates.jsonl and <gate home>/
                                                 decisions-allows.jsonl), merged timestamp-ordered, a missing
                                                 store an empty window; --from reads that one file instead
                                                 (strict). Exit 1 on an unreadable or malformed --from store

Credentials are read from JEV_API_KEY / AI_GATEWAY_API_KEY / VERCEL_OIDC_TOKEN first, then from that file.`;

// The policy-family help block (GHI-17, operator ruling 5): one string, three surfaces —
// the needs-a-subcommand error, `policy --help`, and `policy add --help` (the per-kind
// flag-matrix surface the main help names). The add lines ARE the matrix: which flags each
// entry kind takes; --scope/--expires on a kind that does not take them refuse with one
// line naming the command-entry flag's home — never silently dropped. Declared above the
// dispatch switch: the switch's top-level await suspends the module body, so anything the
// policy family needs must be initialized before it.
const POLICY_HELP = `  policy add --tool 'mcp__server' [--effect allow|deny|ask] [--reason 'why']     (repeat --tool; the user-lane surface — no --scope, no --expires)
  policy add --effect allow|deny --pattern '<command glob>' [--tool Bash] [--scope global|project|project:<path>|session:<id>]
            [--expires <ISO date | 7d | 12h | 30m | never>] [--reason 'why']            (repeat --pattern = staged segments; the ruling surface)
  policy add --dir <absolute path> [--effect allow|deny|ask] [--expires <ISO date | 7d | 12h | 30m | never>] [--reason 'why']
            (directory entries: confined work under the directory — calls whose argument paths all
            resolve under it; an ask becomes allow for that work, the brain's deny line and Always-Deny
            outrank; --expires absent = permanent; widening = add the new expiry, let the old lapse)
  flag matrix: --tool kinds take --effect/--reason; --pattern kinds take
            --effect/--tool/--scope/--expires/--reason; --dir kinds take --effect/--expires/--reason
  policy list
  policy remove <id | pattern | dir path>
  policy set --degradation fail-open | fail-closed                             (the brain-down posture; fail-open default)
  policy adopt-defaults [<file>]                                               (merge the suggested defaults; never auto-applied)
  policy where                                                                  (the store per surface: this terminal, the default
            store, every harness's recorded store — divergences marked)`;

switch (cmd) {
  case "hook": {
    const { main } = await import("./hook.js");
    await main(rest);
    break;
  }
  case "acp": {
    const args = rest[0] === "--" ? rest.slice(1) : rest;
    if (!args.length) die("acp needs an agent command after --");
    const { runProxy } = await import("./acp.js");
    runProxy(args[0], args.slice(1));
    break;
  }
  case "check": {
    if (!rest[0]) die("check needs a tool name and a JSON input argument");
    let input;
    try { input = rest[1] ? JSON.parse(rest[1]) : {}; }
    catch { die("check: the input argument is not valid JSON"); }
    const { assessAction } = await import("./guard.js");
    const r = await assessAction({ tool: rest[0], input, cwd: process.cwd() }).catch((e) => die(`${e.message} (exit 3)`, 3));
    console.log(r ? `${r.level.toUpperCase()}  ${r.message}` : "SKIPPED  read-only tool");
    process.exitCode = r?.level === "deny" ? 2 : r?.level === "ask" ? 1 : 0;
    break;
  }
  case "scan": {
    const { scanContent } = await import("./guard.js");
    const text = rest[0] ? readFileSync(rest[0], "utf8") : readFileSync(0, "utf8");
    const r = await scanContent({ text, tool: "scan", source: rest[0] }).catch((e) => die(`${e.message} (exit 3)`, 3));
    console.log(r ? `${r.flagged ? "FLAGGED" : "CLEAN"}  ${r.message}` : "SKIPPED  nothing to scan");
    process.exitCode = r?.flagged ? 2 : 0;
    break;
  }
  case "scan-skills": {
    const { findInstructionFiles, projectRoots, scanFiles, userRoots } = await import("./skills.js");
    const roots = rest.length ? rest.map((r) => resolve(r)) : [...userRoots(), ...projectRoots()];
    const files = findInstructionFiles(roots);
    if (!files.length) { console.log("unjangled-guardrails: no instruction files found"); break; }
    process.stderr.write(`unjangled-guardrails: scanning ${files.length} instruction files…\n`);
    const results = await scanFiles(files);
    const flagged = results.filter((r) => r.flagged), errors = results.filter((r) => r.error);
    for (const r of flagged) console.log(`FLAGGED  ${r.file}\n         ${r.kind.replace("_", " ")} p=${r.p}${r.cached ? " (cached)" : ""}`);
    for (const r of errors) console.log(`ERROR    ${r.file}: ${r.error}`);
    console.log(`${results.length} scanned (${results.filter((r) => r.cached).length} cached), ${flagged.length} flagged, ${errors.length} errors`);
    process.exitCode = flagged.length ? 2 : errors.length ? 3 : 0;
    break;
  }
  case "install": {
    const { installFor } = await import("./install.js");
    const home = takeFlag(rest, "install", "--home");
    const v2 = takeBoolFlag(rest, "--v2");
    const force = takeBoolFlag(rest, "--force");
    const askPermissions = takeBoolFlag(rest, "--ask-permissions");
    let target = rest[0];
    if (target === undefined) target = (await detectOrDie("install", { home })).target;
    // The opencode-only restrictions fire only once an agent is actually decided — a missing
    // agent must report its own error (candidates/unknown), never a misleading off-target
    // complaint. (--v2 held this same post-detection order with the other two; an early
    // parse-time check used to fire it before detection, reporting the restriction instead of
    // the candidate table — epic-host-isolation sweep.)
    if (v2 && target !== "opencode") die("install --v2 applies only to opencode");
    if (force && target !== "opencode") die("install --force applies only to opencode");
    if (askPermissions && target !== "opencode") die("install --ask-permissions applies only to opencode");
    try { installFor(target, { v2, home, force, askPermissions }); } catch (e) { die(e.message); }
    await keyHint();
    // Recommended next steps (GitHub issue 19 / CAP-13): the install path ends naming the
    // policy step it cannot do for the operator — adoption stays explicit, never automatic,
    // so the surface that finishes an install must say the policy is empty until they act.
    // Here, not inside installFor: setup reuses installFor in-process and carries its own
    // policy step (the readiness report's policy section) — printing this too would be the
    // same instruction twice in one run.
    console.log("Recommended next steps (the policy is empty until you adopt one — adoption is explicit, never automatic):");
    console.log("  1. review the suggested defaults in your checkout (examples/user-policy.default.json), then run: unjangled-guardrails policy adopt-defaults");
    console.log("  2. choose the brain-down posture: unjangled-guardrails policy set --degradation fail-open | fail-closed (fail-open is the default)");
    console.log("  3. unjangled-guardrails calibrate — self-certify the configured brain");
    console.log(`  4. unjangled-guardrails verify ${target} — live-verify ${target}'s real surface with the safe and destructive probes`);
    break;
  }
  case "verify": {
    // tools/ ships in the git checkout, not the npm tarball — say so plainly rather than a stack trace.
    const { runLiveVerify } = await import("../tools/verify/live-verify.mjs").catch(() => ({}));
    if (!runLiveVerify) die("verify lives in tools/, which the npm tarball does not ship; run it from a git clone of unjangled-guardrails");
    process.exitCode = await runLiveVerify(rest[0], { log: console.log });
    break;
  }
  case "rules-check": {
    // tools/ ships in the git checkout, not the npm tarball (same caveat as verify/calibrate).
    const { runRulesConformance } = await import("../tools/rules-conformance.mjs").catch(() => ({}));
    if (!runRulesConformance) die("rules-check lives in tools/, which the npm tarball does not ship; run it from a git clone of unjangled-guardrails");
    const r = await runRulesConformance({ log: console.log }).catch((e) => die(`${e.message} (exit 3)`, 3));
    process.exitCode = r.ok ? 0 : 1;
    break;
  }
  case "rules-doc": {
    // tools/ ships in the git checkout, not the npm tarball (same caveat as verify/calibrate).
    const { writeRulesDoc } = await import("../tools/rules-doc.mjs").catch(() => ({}));
    if (!writeRulesDoc) die("rules-doc lives in tools/, which the npm tarball does not ship; run it from a git clone of unjangled-guardrails");
    try { const r = await writeRulesDoc(); console.log(`unjangled-guardrails: rules-doc wrote ${r.path} (${r.bytes} bytes); conformance green`); }
    catch (err) { console.error(`Unjangled Guardrails: rules-doc: ${err.message}`); process.exitCode = 1; }  // one clean line: no stack, no USAGE
    break;
  }
  case "setup": {
    // tools/ ships in the git checkout, not the npm tarball (same caveat as verify — the
    // setup module's own import of the live-verify runner is what fails).
    const { runSetup } = await import("./setup.js").catch(() => ({}));
    if (!runSetup) die("setup runs the live-verify step from tools/, which the npm tarball does not ship; run it from a git clone of unjangled-guardrails");
    let target = rest[0];
    if (target === undefined) target = (await detectOrDie("setup", {})).target;  // setup has no --home: the child's HOME is the tree
    try { process.exitCode = await runSetup(target, { log: console.log }); }
    catch (err) { die(`${err.message} (exit 3)`, 3); }
    break;
  }
  case "calibrate": {
    // tools/ ships in the git checkout, not the npm tarball (same caveat as verify/setup).
    const { runCalibrate } = await import("../tools/calibrate.mjs").catch(() => ({}));
    if (!runCalibrate) die("calibrate lives in tools/, which the npm tarball does not ship; run it from a git clone of unjangled-guardrails");
    const url = takeFlag(rest, "calibrate", "--url"), brainKey = takeFlag(rest, "calibrate", "--key");
    // --key is only read on the local (SYSTEMONE_URL) branch of backend(); advertising it as
    // an independent override would let a stranger passing --key with a cloud-credential env
    // quietly calibrate a different brain than they think.
    if (brainKey !== undefined && url === undefined) die("calibrate --key requires --url (cloud backends take their keys from their own env or config file)");
    const quick = takeBoolFlag(rest, "--quick");
    if (rest.length) die(`calibrate takes only --url, --key and --quick (got ${rest.join(" ")})`);
    try { process.exitCode = await runCalibrate({ url, key: brainKey, quick, log: console.log }); }
    catch (err) { console.error(`Unjangled Guardrails: calibrate: ${err.message}`); process.exitCode = 1; }  // one clean line: no stack, no USAGE
    break;
  }
  case "key": {
    const { CONFIG_FILE, readConfig } = await import("./jev.js");
    if (rest.includes("--infisical")) {
      // The gate's own credential chain (2026-10-12): the Infisical fetch runs in gate code so
      // no agent command text names a credential source — the floor's operand leg only sees
      // `key --infisical --project <id>`. The key returns in-process and goes straight into the
      // same 0600 config write `key --local` uses; status output only, never the value.
      const flag = (name) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };
      const { restoreBrainKey } = await import("./restore-brain-key.js");
      let key;
      try { key = restoreBrainKey({ project: flag("--project"), envName: flag("--env"), secret: flag("--secret"), log: console.log }); }
      catch (err) { die(`key --infisical: ${err.message}`, 1); }
      const url = readConfig().localBaseUrl;
      if (!url) die("key --infisical: no localBaseUrl in the config yet — the brain URL is not stored in Infisical; run `key --local <url>` once first");
      const cfg = { ...readConfig(), localApiKey: key };
      mkdirSync(dirname(CONFIG_FILE), { recursive: true, mode: 0o700 });
      writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 }); chmodSync(CONFIG_FILE, 0o600);  // mode applies at creation only — an existing world-readable config stays fixed
      console.log(`unjangled-guardrails: brain key restored from Infisical to ${CONFIG_FILE} — the key value was never in argv or output`);
      break;
    }
    const positional = rest.filter((a) => !a.startsWith("--"));
    if (rest.includes("--local")) {
      const [url, localKey] = positional;
      if (!url) die("key --local needs the backend URL as an argument");
      const cfg = { ...readConfig(), localBaseUrl: url, ...(localKey ? { localApiKey: localKey } : {}) };
      mkdirSync(dirname(CONFIG_FILE), { recursive: true, mode: 0o700 });
      writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 }); chmodSync(CONFIG_FILE, 0o600);  // mode applies at creation only — an existing world-readable config stays fixed
      console.log(`unjangled-guardrails: local backend ${url} saved to ${CONFIG_FILE}${localKey ? " (with API key)" : ""}`);
      break;
    }
    const key = positional[0];
    if (!key) die("key needs the API key as an argument");
    const gateway = rest.includes("--gateway") || key.startsWith("vck_");
    const cfg = { ...readConfig(), [gateway ? "aiGatewayApiKey" : "jevApiKey"]: key };
    mkdirSync(dirname(CONFIG_FILE), { recursive: true, mode: 0o700 });
    writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 }); chmodSync(CONFIG_FILE, 0o600);
    console.log(`unjangled-guardrails: ${gateway ? "Vercel AI Gateway" : "TypeSafe"} key saved to ${CONFIG_FILE}`);
    break;
  }
  case "policy":
  case "ruling":  // one-release alias: the ruling surface over the folded store
  case "lane": {  // one-release alias: the tool-entry (user-lane) surface
    await policyCommand(cmd, rest);
    break;
  }
  case "decision": {
    // FR-E3 (CAP-2): the operator's audit-document emitter. Failures are one clean stderr
    // line and exit 1 — no stack, no USAGE (the calibrate-case precedent).
    const [sub, ...dargs] = rest;
    const { exportDecisions } = await import("./decision-export.js");
    if (sub !== "export") die("decision needs a subcommand: export");
    const from = takeFlag(dargs, "decision export", "--from");
    if (dargs.length) die(`decision export takes only --from <path> (got ${dargs.join(" ")})`);
    try { console.log(JSON.stringify(exportDecisions({ source: from }), null, 2)); }
    catch (err) { console.error(`Unjangled Guardrails: ${err.message}`); process.exitCode = 1; }
    break;
  }
  default:
    console.log(USAGE);
    process.exitCode = cmd ? 1 : 0;
}

// The CONFIG surface (consolidation 2026-10-20; dir entries 2026-10-20): one store, three
// kinds of entry. `policy` is the name; `ruling` and `lane` stay as one-release aliases —
// ruling keeps its old refusal of a global entry without --expires, lane maps onto tool
// entries.
async function policyCommand(alias, rest) {
  const [sub, ...args] = rest;
  const P = await import("./policy.js");
  const R = await import("./rulings.js");
  const flag = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
  const repeated = (name) => { const out = []; for (let i = args.indexOf(name); i >= 0; i = args.indexOf(name, i + 1)) { if (args[i + 1] !== undefined) out.push(args[i + 1]); } return out; };
  const reason = () => (args.includes("--reason") ? flag("--reason") : undefined);
  // GHI-17: `--help` is a real surface for the policy family — `policy --help`,
  // `policy add --help` (the spelling the main help names), the aliases too. Exit 0, the
  // shared help block with the per-kind flag matrix; the bare/unknown-subcommand error
  // keeps its own shape (exit 1, the same text after the needs-a-subcommand line).
  if (rest.includes("--help")) {
    console.log(`unjangled-guardrails policy — the CONFIG layer${alias === "ruling" || alias === "lane" ? ` (${alias}: an alias of policy)` : ""}:\n${POLICY_HELP}`);
    return;
  }
  // Store visibility (CAP-5, entry 5): every successful policy-family command names the
  // store file it touched (stdout, one uniform footer line) and warns on stderr for every
  // recorded harness whose store resolves elsewhere — the two-terminal split made visible.
  // `where` is exempt from the footer: its whole output is the store map.
  const storeEcho = () => {
    console.log(`unjangled-guardrails: policy store: ${P.policyFile()}`);
    const storeName = basename(P.policyFile());
    for (const d of P.divergentHarnessStores())
      R.warn(`warning: harness '${d.harness}' reads a different policy store: ${join(d.home, storeName)} (recorded ${d.at ?? "unknown"}) — entries changed here do not apply there; run \`policy where\` to see every store`);
  };
  try {
    if (alias === "lane") {
      // The user-lane surface, byte-compatible: add/list/remove over tool entries.
      if (sub === "add") {
        const tools = repeated("--tool");
        if (!tools.length) die("lane add needs at least one --tool <pattern> (exact, server-wide 'mcp__server*', or verb-class 'mcp__*@read')", 1);
        if (flag("--expires") !== undefined) die("--expires is a command-entry flag (use it with --pattern), not a tool entry", 1);
        if (flag("--scope") !== undefined) die("--scope is a command-entry flag (use it with --pattern), not a tool entry", 1);
        const effect = (flag("--effect", "allow") ?? "allow").toLowerCase();
        for (const t of tools) {
          const r = P.addToolEntry({ pattern: t, effect, reason: reason() });
          console.log(`unjangled-guardrails: lane ${r.id} ${r.existed ? "already present" : "saved"} (${r.effect} ${r.pattern})`);
        }
      } else if (sub === "list") {
        const lanes = P.listEntries().filter((t) => (t.kind ?? "tool") === "tool");
        if (!lanes.length) console.log("user lane is empty — every tool gets the normal flow");
        for (const t of lanes) console.log(`${t.id}  ${(t.effect ?? "allow").padEnd(5)}  ${t.pattern}${t.reason ? `\n     reason: ${t.reason}` : ""}`);
      } else if (sub === "remove") {
        if (!args[0]) die("lane remove needs a lane id or pattern (see `lane list`)", 1);
        const r = await P.removeEntry(args[0]);
        console.log(r.removed ? `unjangled-guardrails: lane entry removed (${args[0]})` : `unjangled-guardrails: no lane entry matched ${args[0]}`);
      } else {
        die("lane needs a subcommand: add | list | remove\n" +
          "  lane add --tool 'mcp__server' [--effect allow|deny|ask] [--tool 'mcp__*@read'] [--reason 'why']\n" +
          "            effects: allow = the ask band passes; deny = always blocks; ask = always prompts (unless the brain denies). Most-specific pattern wins.\n" +
          "  lane list\n" +
          "  lane remove <id | pattern>");
      }
      storeEcho();
      return;
    }
    if (alias === "ruling") {
      if (sub === "init") {
        // First-session bootstrap (epic-installer ticket 4): the stranger-owned empty store.
        // initStore is deliberately not operator-gated — an empty store grants no authority
        // (add/revoke stay gated below) — and idempotent; it never shadows a legacy store
        // that the first-run migration would fold in.
        let created;
        try { created = R.initStore(undefined, "cli"); }
        catch (err) { die(`ruling init: ${err.message}`, 1); }  // unwritable home: a clean message, not a stack
        console.log(created
          ? `unjangled-guardrails: empty policy store created at ${P.policyFile()} (0600, provenance audit row written)`
          : `unjangled-guardrails: a policy store is already present at ${P.policyFile()} — untouched (a legacy rulings store migrates on first assess)`);
      } else if (sub === "add") {
        let ruling;
        try {
          const patterns = repeated("--pattern");
          ruling = await R.addRuling({
            effect: flag("--effect"), ...(patterns.length > 1 ? { stages: patterns } : { pattern: patterns[0] }), tool: flag("--tool"),
            scope: flag("--scope", `project:${process.cwd()}`), expiresAt: flag("--expires"), reason: reason(),
          });
        } catch (err) {
          if (/operator-only/.test(err.message)) die("ruling add is operator-only: run it from your own terminal. Agents must not self-grant rulings.", 1);
          die(`ruling add: ${err.message}`, 1);
        }
        const shape = ruling.stages ? ruling.stages.join(" && ") : `'${ruling.pattern}'`;
        console.log(`unjangled-guardrails: policy entry ${ruling.id} saved as a command entry (${ruling.effect} ${shape}, scope ${ruling.scope}, expires ${ruling.expiresAt ?? "never"})`);
      } else if (sub === "list") {
        const now = Date.now();
        const rulings = R.listRulings();
        if (!rulings.length) console.log("no rulings");
        for (const r of rulings) console.log(`${r.id}  ${r.effect.padEnd(4)}  ${r.pattern}  tool=${r.tool ?? "any"}  scope=${r.scope}  expires=${r.expiresAt ?? "never"}${r.expiresAt && Date.parse(r.expiresAt) <= now ? "  [EXPIRED]" : ""}${promptTag(r)}${r.reason ? `\n     reason: ${r.reason}` : ""}`);
      } else if (sub === "revoke") {
        if (!args[0]) die("ruling revoke needs a ruling id (see `ruling list`)", 1);
        try { await R.revokeRuling(args[0]); }  // the library gate covers revoke too (plan 1.1)
        catch (err) { if (/operator-only/.test(err.message)) die("ruling revoke is operator-only: run it from your own terminal. Agents must not revoke operator rulings.", 1); die(`ruling revoke: ${err.message}`, 1); }
        console.log(`unjangled-guardrails: policy entry ${args[0]} removed`);
      } else {
        die("ruling needs a subcommand: init | add | list | revoke (an alias of policy — see `policy` help)\n" +
          "  ruling add --effect allow|deny --pattern '<command glob>' [--tool Bash] [--scope global|project|project:<path>|session:<id>]\n" +
          "            [--expires <ISO date | 7d | 12h | 30m | never>] [--reason 'why']\n" +
          "            (global rulings require an explicit --expires; project defaults to 30d, session to 7d)");
      }
      storeEcho();
      return;
    }
    if (sub === "add") {
      const tools = repeated("--tool");
      const patterns = repeated("--pattern");
      const dir = flag("--dir");
      if ((dir !== undefined ? 1 : 0) + (tools.length ? 1 : 0) + (patterns.length ? 1 : 0) > 1)
        die("policy add takes ONE kind: --tool <pattern> (a tool entry), --pattern '<command glob>' (a command entry), or --dir <absolute path> (a directory entry) — not a mix");
      if (dir !== undefined) {
        // Operator ruling 5 (2026-11-09, GHI-17): dir entries carry expiry like command
        // entries — 1.7's refusal here was the marked seam, now flipped. --expires passes
        // through to addDirEntry (absent = permanent, never = the explicit permanent
        // spelling, bad values refused with the accepted forms); --scope still refuses —
        // dir entries have no scope dimension.
        if (flag("--scope") !== undefined) die("--scope is a command-entry flag (use it with --pattern), not a directory entry", 1);
        const effect = (flag("--effect", "allow") ?? "allow").toLowerCase();
        const r = P.addDirEntry({ path: dir, effect, expiresAt: flag("--expires"), reason: reason() });
        console.log(`unjangled-guardrails: policy ${r.id} ${r.existed ? "already present" : "saved"} (${r.kind} ${r.effect} ${r.path}, expires ${r.expiresAt ?? "never"})`);
      } else if (tools.length) {
        if (flag("--expires") !== undefined) die("--expires is a command-entry flag (use it with --pattern), not a tool entry", 1);
        if (flag("--scope") !== undefined) die("--scope is a command-entry flag (use it with --pattern), not a tool entry", 1);
        const effect = (flag("--effect", "allow") ?? "allow").toLowerCase();
        for (const t of tools) {
          const r = P.addToolEntry({ pattern: t, effect, reason: reason() });
          console.log(`unjangled-guardrails: policy ${r.id} ${r.existed ? "already present" : "saved"} (${r.kind} ${r.effect} ${r.pattern})`);
        }
      } else if (patterns.length) {
        const r = await P.addCommandEntry({
          effect: flag("--effect", "allow"), ...(patterns.length > 1 ? { stages: patterns } : { pattern: patterns[0] }),
          tool: tools[0], scope: flag("--scope", `project:${process.cwd()}`), expiresAt: flag("--expires"), reason: reason(),
        });
        const shape = r.stages ? r.stages.join(" && ") : `'${r.pattern}'`;
        console.log(`unjangled-guardrails: policy ${r.id} ${r.existed ? "already present" : "saved"} (${r.kind} ${r.effect} ${shape}, scope ${r.scope}, expires ${r.expiresAt ?? "never"})`);
      } else {
        die("policy add needs --tool <pattern> (a tool entry: effects allow|deny|ask), --pattern '<command glob>' (a command entry: effects allow|deny, optional --scope and --expires), or --dir <absolute path> (a directory entry: effects allow|deny|ask — confined work under the directory)");
      }
    } else if (sub === "list") {
      const now = Date.now();
      const entries = P.listEntries();
      const degradation = loadDegradation(P);
      if (!entries.length && !degradation) console.log("policy is empty — Always-Deny and the brain gate, no config effects");
      if (degradation) console.log(`degradation: ${degradation}`);
      // Story 5 (CAP-4/R-5): the capture tier surfaces beside the degradation knob — the one
      // runtime knob line the CLI already had. Always printed, off included: visibility is
      // the point, and an unknown GUARD_PROMPT_RULINGS value reads off because the tier
      // comes from promptCaptureTier (the 1.4.0 contract export — the same parse the mint
      // honors; a CLI-side copy could drift from it).
      console.log(`prompt-capture: ${R.promptCaptureTier(process.env)}`);
      for (const e of entries) {
        const kindTag = e.kind === "command" ? "cmd " : e.kind === "dir" ? "dir " : "tool";
        const name = e.kind === "dir" ? e.path : e.pattern;
        const extra = e.kind === "command" || e.scope ? `  scope=${e.scope ?? "global"}  expires=${e.expiresAt ?? "never"}${e.expiresAt && Date.parse(e.expiresAt) <= now ? "  [EXPIRED]" : ""}`
          : e.kind === "dir" && e.expiresAt ? `  expires=${e.expiresAt}${Date.parse(e.expiresAt) <= now ? "  [EXPIRED]" : ""}` : "";
        console.log(`${e.id}  ${kindTag}  ${(e.effect ?? "allow").padEnd(5)}  ${name}${e.tool ? `  (on ${e.tool})` : ""}${extra}${promptTag(e)}${e.reason ? `\n     reason: ${e.reason}` : ""}`);
      }
    } else if (sub === "remove") {
      if (!args[0]) die("policy remove needs an entry id, exact pattern, or dir path (see `policy list`)", 1);
      const r = await P.removeEntry(args[0]);
      console.log(r.removed ? `unjangled-guardrails: policy entry removed (${args[0]})` : `unjangled-guardrails: no policy entry matched ${args[0]}`);
    } else if (sub === "set") {
      const d = flag("--degradation");
      if (d !== "fail-open" && d !== "fail-closed") die("policy set --degradation takes fail-open | fail-closed (fail-open is the default posture)");
      const r = await P.setDegradation(d);
      console.log(`unjangled-guardrails: degradation posture set to ${r.degradation} (brain-down: Always-Deny gates, unmatched calls ${r.degradation === "fail-closed" ? "deny" : "pass"})`);
    } else if (sub === "adopt-defaults") {
      const file = args.find((a) => !a.startsWith("--"));
      const r = await P.adoptDefaults(undefined, file ? { file } : {});
      console.log(`unjangled-guardrails: adopted ${r.added} suggested entr(ies) (${r.skipped} already present) from ${r.source}`);
    } else if (sub === "where") {
      await policyWhere(P, R);
      return;
    } else {
      die("policy needs a subcommand: add | list | remove | set | adopt-defaults | where\n" + POLICY_HELP);
    }
    storeEcho();
  } catch (err) {
    if (/operator-only/.test(err.message)) die("policy changes are operator-only: run them from your own terminal. Agents must not edit the policy.", 1);
    die(`policy: ${err.message}`, 1);
  }
}

function loadDegradation(P) {
  try { return P.loadPolicyStore().degradation ?? null; } catch { return null; }
}

// `policy where` (CAP-5, entry 5): the store-visibility doctor — read-only and not
// operator-gated (an agent may run it too: the issue's agent side could not discover
// GUARD_HOME because the credential floor rightly denies harness-env reads; this command
// answers the same question without reading anyone's env file). Prints the store per
// surface: this terminal, the default store, every recorded harness (divergences marked),
// and every registered install with no runtime record yet — an unrun install's store is
// never guessed, it is whatever its harness env resolves at run time.
async function policyWhere(P, R) {
  const { registrations } = await import("./detect.js");
  const storeName = basename(P.policyFile());
  const here = R.guardHome();
  const spell = P.storeSpell();
  const pad = (s) => String(s).padEnd(14);
  console.log("unjangled-guardrails: policy where — the policy store per surface");
  console.log(`${pad("this terminal")}${join(here, storeName)}  (${spell === "default" ? "GUARD_HOME unset — the default store" : spell})`);
  const defaultHome = R.guardHome({});
  if (defaultHome !== here)
    console.log(`${pad("default store")}${join(defaultHome, storeName)}  (what terminals and harnesses without GUARD_HOME read)`);
  const records = Object.entries(P.readHarnessStores().harnesses).sort(([a], [b]) => a.localeCompare(b));
  for (const [name, r] of records)
    console.log(`${pad(name)}${join(r.home ?? "?", storeName)}  (${r.spell ?? "?"}, recorded ${r.at ?? "unknown"})${(r.home ?? "") !== here ? "  [diverges]" : ""}`);
  const recorded = new Set(records.map(([n]) => n));
  const installed = [];
  for (const { target, path } of registrations(homedir()))
    if (!recorded.has(target) && existsSync(path)) installed.push({ target, path });
  const hermesPlugin = join(homedir(), ".hermes", "plugins", "unjangled-guardrails");
  if (!recorded.has("hermes") && existsSync(join(hermesPlugin, "__init__.py"))) installed.push({ target: "hermes", path: hermesPlugin });
  for (const { target, path } of installed)
    console.log(`${pad(target)}no runtime record yet — install registered at ${path}; its store is its harness env's GUARD_HOME, else the default store`);
  if (!records.length && !installed.length)
    console.log("no other harness store recorded and no other install registered");
}

async function keyHint() {
  const { backend } = await import("./jev.js");
  const { KEY_HINT } = await import("./install.js");
  if (!backend()) console.log(`No backend configured yet: ${KEY_HINT}. Until then the guard fails open.`);
}

// Targetless install/setup resolve the running harness here (epic-installer ticket 3):
// detection is consulted ONLY when no target was given — an explicit target is never
// detected-over, so today's behavior for `install <agent>` / `setup <agent>` is unchanged.
// A decided detection is announced with the signal that decided it; ambiguity and unknown
// environments die loudly with the candidate table and the ACP-editor note (exit 1) —
// never a silent pick between registrations.
async function detectOrDie(cmdName, { home } = {}) {
  const { candidateTable, detectHarness, registrations } = await import("./detect.js");
  const { ACP_NOTE } = await import("./install.js");
  const dir = home ? resolve(home) : homedir();  // one resolved tree: the header and every table row show the same absolute path
  const d = detectHarness({ env: process.env, home: dir });
  if (d.ambiguous)
    die(`${cmdName}: ${d.ambiguous.length} harness registrations found — pass one explicitly, refusing to guess:\n${candidateTable(d.ambiguous)}\n${ACP_NOTE}`);
  if (d.unknown)
    die(`${cmdName}: no harness detected — no CLAUDECODE env marker, no registration file under ${dir}; pass a target:\n${candidateTable(registrations(dir))}\n${ACP_NOTE}`);
  console.log(`unjangled-guardrails: no target given — detected ${d.target} (${d.signal})`);
  return d;
}

// GHI-7 (CAP-14): an error is ONE clean line — the full help never rides an argument
// error (in the issue's repro, `bad --expires never` was buried under ~100 lines of USAGE).
// The full USAGE keeps its own surfaces — bare invocation (exit 0) and an unknown command
// (exit 1) print it themselves in the switch default — and the subcommand families keep
// their short targeted usage text inside their messages. Precedent: calibrate, rules-doc
// and decision export already print one clean line on failure.
function die(msg, code = 1) { console.error(`Unjangled Guardrails: ${msg}`); process.exit(code); }

// Story 5 (CAP-4/R-5): prompt-captured entries — the only carriers of a `prompt:` via,
// minted by rulings.js capturePromptRuling — render their provenance on the list line: an
// end-of-line (prompt:<harness>) tag, the stored via verbatim, so every harness spelling
// renders itself and nothing maps or validates it here. Operator-minted rows carry no via
// and stay byte-identical.
function promptTag(e) {
  return typeof e.via === "string" && e.via.startsWith("prompt:") ? `  (${e.via})` : "";
}

// Consume `<flag> <value>` from an argv tail: the value, with the pair spliced out. A present
// flag without a usable value dies naming the command — install and calibrate share the exact
// wording (docs/messages.md; test/calibrate.test.js pins one of the two).
function takeFlag(argv, cmdName, name) {
  const i = argv.indexOf(name);
  if (i < 0) return undefined;
  const v = argv[i + 1];
  if (v === undefined || v.startsWith("--") || !v.trim()) die(`${cmdName} ${name} needs a value`);
  argv.splice(i, 2);
  return v;
}

// Consume a boolean flag from an argv tail: true iff present, spliced out either way so the
// positional parsing after it sees only what remains.
function takeBoolFlag(argv, name) {
  return argv.includes(name) ? (argv.splice(argv.indexOf(name), 1), true) : false;
}
