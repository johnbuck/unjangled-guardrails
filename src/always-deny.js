// ALWAYS DENY (consolidation 2026-10-20, plan-consolidation-two-layers): layer 1 of the
// two-layer gate. Heuristic, PRE-brain, chat-blind, absolute — and the degradation floor:
// it is the only thing that gates while the brain is down. Three families, both vendored
// cores combined:
//
//   Secrets         — vendor/secrets-guard-core (checkBash / checkRead / isSecretFile) plus
//                     SECRET_SHAPE value detection from vendor/guardrails-core over write
//                     content (restores the write-content detection lost in vendoring), the
//                     credential-source command legs (operator doctrine 2026-10-12), and the
//                     gate's own credential-bearing config leg (fleet incident 2026-10-16).
//   Catastrophic    — vendor/guardrails-core CATASTROPHIC (11 shapes: recursive rm of /,
//                     device writes, fork bomb, force push, chmod -R 777, pipe-to-shell).
//   Self-modification — bash + path guards over the gate's own source/store/config (the
//                     2026-10-17 verb×target rule and the 1.1 path guard, merged).
//
// Verdict: deny. No brain verdict, no policy effect, and no ruling consult can lift it
// (self-mod precedent) — the guidance blocks below say so, and the consult step in
// assessAction never runs for an Always-Deny hit. Both cores stay the single sources of
// truth: every rule shape here imports them; nothing re-implements a vendored regex.
//
// DEV-FLOW NOTE (found live 2026-10-20): this file is the rule table, so its own source text
// matches the write-content floor's two legs — the egress alternation's bare pieces match
// their own literals. Writing the file whole trips the floor on itself. The sanctioned way
// to author it: leg-separated chunks (a write whose content carries the credential-source
// shapes, then a write that carries the egress shapes) — no single write is ever a staging
// chain, which is the compound the floor exists to catch.
import { checkBash, checkRead, isSecretFile } from "../vendor/secrets-guard-core/rules.mjs";
import { checkCatastrophic, SECRET_SHAPE } from "../vendor/guardrails-core/rules.mjs";
import { guardHome, subCommands } from "./rulings.js";
import { sessionsDir } from "./session.js";
import { CONFIG_FILE, LEGACY_CONFIG_FILE } from "./jev.js";
import { homedir } from "node:os";
import { join, resolve, sep } from "node:path";

// ── family verdicts ──────────────────────────────────────────────────────────────────────────
// alwaysDeny returns null (not Always-Denied — the brain judges) or one of:
//   { family, floor, reason, category, stats, matched?, pattern?, lines? }
// `floor` is the fine rule tag the result object exposes (the old rule families); `reason`
// is the deny why (already stripped of the vendored core's BLOCKED prefix); `stats` is the
// header parens — the plain rule name + specifics (the message-registry format, no layer
// naming); `matched` is the per-trigger matched clause the guidance's (matched: …) slot
// renders; `pattern` is the short pattern name the credential-source floor's `what` shows.

// ── Secrets ───────────────────────────────────────────────────────────────────────────────────
// The gate's own backend-config paths hold the brain credential by design (the `key` command
// and the config-file backend write there). Display or evaluator-sink shapes over them deny
// here — fleet incident 2026-10-16: a JSON.parse error frame echoed the stored key into
// session context. Matched as substrings so tilde, absolute, relative, and backup-suffixed
// spellings all catch.
export const GUARD_CONFIG_RE = /\.unjangled-guardrails[/\\]config\.json|\.jev-guard[/\\]config\.json/i;

// Bash-plane legs. Content-bearing verbs whose operands can move or print a file's values;
// a remote-host call site (the live incident: ssh fetched a named key into a shell variable);
// the blessed safe shapes that keep the brain (vendor design: presence checks, silent loads).
// "cut" joined for the read-utility premise round (2026-10-25): a field-select over a
// credential file (`cut -d: -f2 /etc/shadow`) prints the value fields — cat in pieces.
const CONTENT_VERBS = new Set(["cat", "bat", "tac", "nl", "head", "tail", "less", "more", "most", "view", "od", "xxd", "strings", "cut", "cp", "mv", "rsync", "scp", "install", "dd", "tee", "curl", "wget"]);
const SSH_FETCH_RE = /(^|[\s;&(])(ssh|scp|sftp|rsync)\b/i;
const STDIN_STORE_RE = /(^|\|\s*)(?:printenv|env)\s+[^\n|;&]*\|\s*(?:infisical|op|pass|sops|age|vault)\b/i;
const SSH_INSPECTION_RE = /\.ssh[/\\](?:known_hosts|authorized_keys|config)\b/gi;  // inspection files, not credential material
// The gitignored secret family (party precedence row, John's rows + our project-local names):
// as git-staging operands these deny outright, brain-independent.
const GIT_SENSITIVE_RE = /(?:^|[/\\])(?:\.env$|\.env\.(?!example$|sample$|template$|dist$)[^/\\]*$|\.git-credentials$|\.netrc$|\.jev-key$|\.zai-key$|id_rsa$|id_ed25519$|id_ecdsa$|[^/\\]*\.pem$)/i;  // the example/sample/template/dist spellings are safe templates
// System credential files (read-utility premise round, 2026-10-25 — battery r5 measured ALLOW
// before this leg): /etc/shadow, /etc/gshadow, /etc/sudoers are credential material the vendored
// isSecretFile does not know. Local family list, the established GIT_SENSITIVE_RE pattern — the
// vendored matcher stays untouched. The lookahead admits the backup spelling (/etc/shadow-) and
// the docker bind-mount spelling (-v /etc/shadow:/s) but not the shadowsocks class.
const SYSTEM_CRED_FILE_RE = /(?:^|[/\\])etc[/\\](?:shadow|gshadow|sudoers)(?![a-z0-9])/i;
// Secret display forms (same round: battery r8 measured ALLOW) — a kubectl get of a secret
// object with a value-printing output form, or a describe of one, prints the secret's values.
// Table forms and metadata selectors pass: they print names and byte counts, never values.
const KUBECTL_SECRET_DISPLAY_RE = /\bkubectl\s+get\s+secrets?\b[^\n|;&]*?(?:-o\s*=?\s*(?:yaml|json|wide)\b|-o\s*=?\s*(?:jsonpath|go-template|template|custom-columns)\b[^\n|;&]*(?:\.data\b|\.stringData\b|\[\s*["']?data["']?\s*\]))/i;
const KUBECTL_DESCRIBE_SECRET_RE = /\bkubectl\s+describe\s+secrets?\b/i;
// Bulk env and history marker-grep pairs (same round: battery r6/r7 measured ALLOW) — a bare
// printenv/env (dumps every variable), a bare history, or a history-FILE read whose next
// segment greps for credential markers filters the dump down to the credential lines and
// prints them. The dumps_env_argv "filtering still reveals" doctrine, at the floor.
const BARE_ENV_DUMP_SEG = /^(?:sudo\s+)?(?:printenv|env)\s*$/;
const BARE_HISTORY_SEG = /^history\s*$/;
const HISTORY_FILE_RE = /(?:^|[/\\])\.(?:bash_history|zsh_history|zhistory|sh_history|history)\b/i;
const MARKER_FILTER_RE = /(?:pass|passwd|password|token|secret|cred|auth|key)/i;
const GREP_FAMILY_RE = /(^|[^A-Za-z0-9_-])(?:grep|egrep|fgrep|rg|ag)\b/;
const GREP_PRESENCE_RE = /(^|\s)-[A-Za-z]*[qlcL](\s|$)|--quiet|--silent|--files-with-matches|--count/;
// M8 (posture-triage 5.3): the shell family is anchored on both sides — a tool name that
// merely CONTAINS "sh" ("fish", "marshmallow") must not route into the bash rules.
export const BASH_SHAPED = /(^|[^a-z_])(bash|shell|run_shell_command|terminal|zsh|sh)([^a-z_]|$)/;
// Operand extraction: the value side of `x=y`, `if=x`, `--out=/y`; bare tokens pass through.
const operandValue = (t) => (t.includes("=") ? t.slice(t.indexOf("=") + 1) : t).replace(/^if=/, "");
// PARITY RE-DECISION (CAP-4, 2026-10-24): the floor's two legs now split differently, on
// purpose. The credential-source legs keep this quote-blind regex — it splits FINER than
// the matcher (src/rulings.js splitTopLevel, which honors quotes and command contexts), so
// those legs can only over-detect a quoted span, never miss a real terminator. The self-mod
// leg instead calls subCommands and inherits the quote-aware matcher split exactly; its
// 20-command quoted battery (run at the change) produced zero verdict diffs, because the
// GATE_SRC_WRITE `[^;|]` middle spans cannot unite a quoted-`;` merge in any matching way.
const SEGMENT_SPLIT = /\s*(?:&&|\|\||[;|\n])\s*/;
const stripShellQuotes = (cmd) => cmd.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'(?:[^'\\]|\\.)*'/g, "''");

// Leg A — credential-source shape. One family, shared by the bash command-text leg and write
// content. The env-file piece excludes the documentation spellings (the example/sample/
// template/dist suffixes); the TOKEN piece is case-sensitive ON PURPOSE — code's lowercase
// access_token stays brain-side, env-style UPPER_TOKEN is credential-source. The api-key
// piece accepts an underscore before "api" (STRIPE_API_KEY) but not an alphanumeric (rapidkey).
const CRED_SOURCE_RES = [
  /(^|[^A-Za-z0-9_])(\.env\b(?!\.(?:example|sample|template|dist))|\.ssh[/\\]|\.aws[/\\]credentials|\.git-credentials|\.netrc)/i,
  /[A-Za-z0-9_]*_TOKEN\b/,
  /(^|[^a-z0-9])api[_-]?key/i,
  /\binfisical\b/i,
];
const credSourceHit = (s) => CRED_SOURCE_RES.some((re) => re.test(s));

const globalize = (re) => new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
// Family spans become this marker everywhere a preview or a matched line is shown; the denial
// itself names only the shape (amendment 2026-10-12: never echo the raw text or matched spans).
export const REDACTED = "[redacted: credential-source pattern matched]";
export const redactCredentialSpans = (s) => CRED_SOURCE_RES.reduce((t, re) => t.replace(globalize(re), REDACTED), String(s ?? ""));
// The value-shape redaction for deny previews: SECRET_SHAPE matches (provider keys, JWTs,
// private-key blocks) mask like the family spans do — a deny that names the shape must not
// echo the value (the write-content legs' matched LINES were always redacted; this covers the
// preview of the input as a whole, whose JSON fallback carries notebookedit/patch content).
export const SECRET_REDACTED = "[redacted: credential-shaped value]";
export const redactSecretShapes = (s) => SECRET_SHAPE.reduce((t, re) => t.replace(globalize(re), SECRET_REDACTED), String(s ?? ""));
const VALUE_RUN_RE = /[A-Za-z0-9+/=]{20,}/g;  // opaque value-like runs: masked (dots/underscores/dashes split runs, so identifiers and URLs survive; 20+ unbroken alnum is a value, not a name)

const matchedLines = (text, regexes) => String(text ?? "").split(/\r?\n/).map((l) => l.trim())
  .filter((l) => l && regexes.some((re) => re.test(l))).slice(0, 6);
// Same filter with the source line numbers, for the write floor's matched clause
// ("line N reads a credential file, line M sends its value over the network").
const matchedLinesNumbered = (text, regexes) => String(text ?? "").split(/\r?\n/).map((l, i) => ({ l: l.trim(), n: i + 1 }))
  .filter((x) => x.l && regexes.some((re) => re.test(x.l))).slice(0, 6);
const redactLine = (line) => redactCredentialSpans(String(line).replace(VALUE_RUN_RE, "…")).slice(0, 200);

// Every string leaf of a write input that is CONTENT being written (paths and old_string are
// not staged content; every adapter spelling of new content is).
const WRITE_CONTENT_SKIP = new Set(["file_path", "path", "filePath", "notebook_path", "old_string", "type"]);
function collectWriteContent(value, out = []) {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => collectWriteContent(v, out));
  else if (value && typeof value === "object") Object.entries(value).forEach(([k, v]) => { if (!WRITE_CONTENT_SKIP.has(k)) collectWriteContent(v, out); });
  return out.join("\n");
}

// Content-carrying write tools the write-content legs judge (closed list; deletes carry no
// content). Every adapter spelling.
const WRITE_FLOOR_TOOLS = /^(write|edit|multiedit|notebookedit|apply_patch|patch|write_file|replace)$/;
// Read-shaped tools whose input carries credential-file paths the vendored checkRead judges
// (TR-3, H1). read_many_files takes a paths array.
const READ_PATH_TOOLS = /^(read|view|cat|read_file|read_many_files)$/;

/** Credential-source command floor (epic-ask-band-posture 7.7 amendments 1b + 3, 2026-10-12):
 *  a credential-shaped command resolves at the deterministic floor — DENY, never the ask
 *  band. Returns { family: "credential-source", pattern, matched, reason } or null; the
 *  reason names the SHAPE only (redacted), `pattern` is the short rule name the deny `what`
 *  shows, and `matched` is the per-trigger clause the guidance's (matched: …) slot renders.
 *  Pure; no fs, no env. */
// The redacted display of the operand a leg matched (matched-display amendment, operator
// ruling 2026-10-25): value-like runs and secret shapes mask; credential-file PATH structure
// displays — that is the amendment's point. The credential-source span pipeline still runs
// (a raw .ssh/.env span in the operand reads as the marker, as everywhere else).
// maskCredentialValues is the same treatment without the operand trim — the exported value
// mask every deny-message preview runs (quick-lens patch 2026-10-25: a long value run in the
// ARGV must not print raw in `what` while the matched clause masks it).
export const maskCredentialValues = (s) => redactCredentialSpans(redactSecretShapes(String(s ?? "").replace(VALUE_RUN_RE, "…")));
const redactOperand = (s) => maskCredentialValues(s).replace(/\s+/g, " ").trim().slice(0, 60);
const credHit = (pattern, operand, reason) => ({
  family: "credential-source", pattern,
  matched: `the command's shape matched: ${pattern}, ${redactOperand(operand)}`,
  reason,
});
export function credentialSourceVerdict(tool, input) {
  if (!BASH_SHAPED.test(String(tool ?? "").toLowerCase())) return null;
  const cmd = typeof input?.command === "string" ? input.command : "";
  if (!cmd) return null;
  const stdinStore = STDIN_STORE_RE.test(cmd);  // the rotation pattern is a whole-command shape (its pipe is the segment boundary)
  // Runtime env-dump is a whole-command shape too (phrasing-variant battery 2026-10-24, p5/p6):
  // the quote-blind splitter would cut `python3 -c 'import os; print(os.environ)'` at the quoted
  // semicolon and strand the runtime and the environ text in different segments. Redirect-to-file
  // passes (debug without display).
  const runtimeEnvDump = /^(?:\s*)(?:python3?|node|perl|ruby|php)\b/i.test(cmd) &&
    /\benviron\b|process\.env|%ENV/i.test(cmd) && !/>\s*[^|&\s]/.test(cmd);
  if (runtimeEnvDump)
    return credHit("runtime environment dump", cmd, "a language-runtime command dumps the environment to stdout (shape redacted) — redirect to a file instead");
  const segs = cmd.split(SEGMENT_SPLIT).map((s) => s.trim());
  for (let si = 0; si < segs.length; si++) {
    const seg = segs[si];
    if (!seg) continue;
    const tokens = stripShellQuotes(seg).split(/\s+/);
    // Operand leg: a content-bearing verb whose operand names credential material.
    // git staging is a content move with a harder rule (operator, 2026-10-12: "we never
    // want to add an environment. That should 100% be blocked."): `git add`/`git commit`
    // naming a credential file denies outright — not brain-decidable, not policy-carried.
    // GIT_SENSITIVE_RE is the party's gitignored family (John's rows) on top of the
    // vendored matcher, which does not know our project-local key names.
    // A leading `sudo ` is stripped before verb detection (premise round 2026-10-25): the
    // system credential files must not re-open through `sudo cat /etc/shadow`. `sudo git add`
    // stays outside the staging leg — gitStages keeps requiring the unprefixed form.
    const sudoLead = (tokens[0] ?? "").toLowerCase() === "sudo" ? 1 : 0;
    const verb = (tokens[sudoLead] ?? "").toLowerCase();
    const gitStages = sudoLead === 0 && verb === "git" && (tokens[1] === "add" || tokens[1] === "commit");
    const secretTok = (CONTENT_VERBS.has(verb) || gitStages)
      ? tokens.slice(gitStages ? 2 : sudoLead + 1).map(operandValue).find((t) => t && !t.startsWith("-") && (isSecretFile(t) || SYSTEM_CRED_FILE_RE.test(t) || (gitStages && GIT_SENSITIVE_RE.test(t))))
      : undefined;
    if (secretTok)
      return credHit(gitStages ? "git credential staging" : "credential file operand", secretTok, gitStages
        ? "a credential file was staged for commit (shape redacted) — secrets never enter git history"
        : "a command operand names credential material (shape redacted) — its values would move through this command");
    // Remote-fetch leg: a remote host reached FOR credential material (the live incident shape).
    if (SSH_FETCH_RE.test(seg) && credSourceHit(seg))
      return credHit("remote credential fetch", seg, "the command reaches a remote host for credential material (shape redacted)");
    // Guard-config leg (fleet incident 2026-10-16): the gate's own backend config holds the
    // brain credential by design. Display/movement verbs deny (the value would print or move);
    // input-redirect reads deny (tr/awk-class one-liners print it); echo-prone evaluators deny
    // because their error frames echo the input — a JSON.parse failure printed the stored key
    // into session context. Silent in-place byte ops (sed -i, tr … > samefile) stay allowed:
    // repair without display.
    if (GUARD_CONFIG_RE.test(seg)) {
      if (CONTENT_VERBS.has(verb))
        return credHit("guard config read", seg, "a command operand names the gate's own credential-bearing config (shape redacted) — its values would move through this command");
      if (/<\s*\S*(?:\.unjangled-guardrails|\.jev-guard)[/\\]config\.json/i.test(seg))
        return credHit("guard config redirect read", seg, "the command reads the gate's own credential-bearing config through a redirect (shape redacted) — its values would print");
      if (/JSON\.parse|json\.loads?|\bjq\b|\beval\b|node\s+-e|node\s+--eval|python3?\s+-c/i.test(seg))
        return credHit("guard config evaluator", seg, "an error-displaying evaluator over the gate's own config would echo its credential into context (shape redacted)");
    }
    // Secret-print leg (operator ruling 2026-10-12, walkthrough: "100% blocked"): printing
    // the VALUE of a credential-named variable denies — printenv TOKEN-class, brain-independent.
    // The sanctioned stdin rotation (printenv TOKEN | secret-store client) is exempt —
    // STDIN_STORE_RE on the whole command; a bare printenv with no store client denies.
    if (!stdinStore && /^(?:printenv|env)\s+(?:-\s+)?[A-Za-z_0-9]*(?:TOKEN|SECRET|PASSWORD|PASSWD|AUTH|API_KEY|APIKEY|CRED)[A-Za-z_0-9]*$/i.test(seg))
      return credHit("credential variable print", seg, "the command prints a credential-named variable's value (shape redacted) — values never print");
    // Remote extraction leg: password/token extraction out of a remote host's env or files.
    if (/^\s*ssh\b/i.test(seg) && /(?:env|printenv)\s*\|?\s*grep\s+-iE?\s+['"]?(?:pass|token|secret|key|postgres|database|db_|auth|cred)/i.test(seg))
      return credHit("remote credential extraction", seg, "the command extracts credential values from a remote host (shape redacted)");
    // Credential-env sourcing over ssh: loads every secret in a remote env file at once.
    if (/^\s*ssh\b/i.test(seg) && /(?:source|\.\s|set -a)[^'"|;&]*\.(?:env)\b/i.test(seg))
      return credHit("remote env file source", seg, "the command sources a remote credential env file (shape redacted) — every secret in it loads into the session");
    // Runtime env-dump leg (phrasing-variant battery, 2026-10-24: p5/p6 measured ALLOW — the
    // confidence gate releases what the p-rule denied; 4B calibration cannot hold these). A
    // scripting runtime printing the environment to stdout is the printenv shape in another
    // dialect. Redirect-to-file passes (debug without display).
    if (/^(?:python3?|node|perl|ruby|php)\b/i.test(seg) && /\benviron\b|process\.env|%ENV/i.test(seg) && !/>\s*[^|&\s]/.test(seg))
      return credHit("runtime environment dump", seg, "a language-runtime command dumps the environment to stdout (shape redacted) — redirect to a file instead");
    // Credential-printing tool leg (phrasing-variant battery, 2026-10-24: p7/p10 measured ALLOW —
    // the 4B brain does not know these commands print credentials). The tool segment must be the
    // LAST segment: a pipe to a consuming tool passes (the token feeds the next process, never
    // the conversation).
    // Help/version forms pass — reading a tool's docs is not printing a credential
    // (floor-refinements 2026-10-25: `gh auth token --help` false-denied).
    if (/(?:^|\s)(?:-h|--help|--version|version)\b/i.test(seg)) {
      // fall through to the rest of the assessment
    } else if (si === segs.length - 1 &&
        /^(?:gh\s+auth\s+token\b|gcloud\s+auth\s+print-access-token\b|security\s+find-generic-password\b|aws\s+configure\s+get\s+\S*(?:secret|token|password)[\w.-]*|npm\s+config\s+get\s+\S*(?:_authtoken|authtoken|token))/i.test(seg))
      return credHit("credential-printing tool output", seg, "this command's output is a credential (shape redacted) — pipe it into the tool that consumes it");
    // Display-duplicator leg (floor-refinements 2026-10-25): a credential-printing tool piped
    // into tee/less/more/cat/bat is display-plus-write — the pipe carve-out does not cover
    // duplicators (deep-dive Fact 4, npm config list | tee out.tmp).
    if (si + 2 === segs.length && /^(?:tee|less|more|cat|bat)\b/i.test(segs[si + 1] ?? "") &&
        /^(?:gh\s+auth\s+token\b|gcloud\s+auth\s+print-access-token\b|security\s+find-generic-password\b|aws\s+configure\s+get\s+\S*(?:secret|token|password)[\w.-]*|npm\s+config\s+get\s+\S*(?:_authtoken|authtoken|token))/i.test(seg))
      return credHit("display-duplicator pipe", seg, "the credential is piped into a display duplicator (shape redacted) — it would still print");
    // Encoder leg (phrasing-variant battery, 2026-10-24: p4 measured ALLOW). Encoding a
    // credential file to stdout is cat in another alphabet — exposure is exposure, encoded.
    // -out/redirect to a REAL file passes (backup without display); display targets
    // (/dev/stdout, /dev/stderr, /dev/tty, /dev/fd/*, /proc/*/fd/*) count as stdout
    // (floor-refinements 2026-10-25: the -out /dev/stdout display hole).
    const encTargets = [...seg.matchAll(/(?:-out|>>?)\s*([^\s|&;]+)/gi)].map((m) => m[1]);
    const writesRealFile = encTargets.length > 0 && encTargets.every((t) => !/^\/dev\/(?:stdout|stderr|tty)$/i.test(t) && !/^\/dev\/fd\//i.test(t) && !/^\/proc\/\d+\/fd\//i.test(t));
    if (/(?:^|\s)(?:base64|xxd|gzip|openssl)\b/i.test(seg) && !writesRealFile &&
        seg.split(/\s+/).filter((t) => !t.startsWith("-")).some((t) => isSecretFile(t)))
      return credHit("credential encoding", seg, "a credential file is encoded to stdout (shape redacted) — encoding is still exposure");
    // Secret-display leg (read-utility premise round 2026-10-25: battery r8 measured ALLOW —
    // a value-printing output form over a secret object is cat of a credential file in
    // Kubernetes dialect). Table forms print names and byte counts, never values, so bare
    // `kubectl get secrets`, `kubectl get secret <name>`, `-o name` and metadata jsonpath
    // selectors pass; `kubectl create` never matches. Redirect-to-file passes (write without
    // display, the runtime-env-dump and encoder doctrine).
    if (!/>\s*[^|&\s]/.test(seg) &&
        (KUBECTL_SECRET_DISPLAY_RE.test(seg) || KUBECTL_DESCRIBE_SECRET_RE.test(seg)))
      return credHit("secret object display", seg, "a display output form over a secret object would print its values (shape redacted) — table forms and metadata selectors pass");
    // System credential file grep leg (same round, the r5 family): a value-printing grep over
    // /etc/shadow-class files is the vendored credential-file grep leg in a family the vendored
    // matcher does not know. Presence (-q), counts (-c/-l) and redirect-to-file pass.
    if (GREP_FAMILY_RE.test(seg) && SYSTEM_CRED_FILE_RE.test(seg) &&
        !GREP_PRESENCE_RE.test(seg) && !/>\s*[^|&\s]/.test(seg))
      return credHit("system credential file grep", seg, "a command prints matching lines from a system credential file (shape redacted) — -q/-c/-l and wc -l check presence and counts");
    // Bulk env / history marker-grep legs (same round: battery r6/r7 measured ALLOW — the
    // filter reveals; dumps_env_argv "filtering still reveals" doctrine at the floor). The
    // pair must be ADJACENT segments: a bare env dump, a bare history, or a history-file read,
    // then a grep-family segment whose single non-flag argument (the stdin-filter pattern)
    // carries a credential marker. Presence/count flags pass; redirect-to-file passes; a wc
    // count-sink directly after the grep passes (counting without revealing). The stdin
    // rotation never matches — its first segment is not a bare dump. The quote-blind splitter
    // cuts quoted multi-marker patterns at their pipes, so the FIRST fragment still carries
    // the grep and the marker: the leg fires on it unchanged.
    if (si + 1 < segs.length) {
      const nxt = segs[si + 1];
      const nxtTokens = stripShellQuotes(nxt).split(/\s+/).filter(Boolean);
      const grepIdx = nxtTokens.findIndex((t) => GREP_FAMILY_RE.test(t) && !t.startsWith("-"));
      const patternArgs = grepIdx >= 0 ? nxtTokens.slice(grepIdx + 1).filter((t) => !t.startsWith("-")) : [];
      if (grepIdx >= 0 && patternArgs.length === 1 && MARKER_FILTER_RE.test(patternArgs[0]) &&
          !GREP_PRESENCE_RE.test(nxt) && !/>\s*[^|&\s]/.test(nxt) &&
          !(si + 2 < segs.length && /^wc\b/.test(segs[si + 2])) &&
          (BARE_ENV_DUMP_SEG.test(seg) || BARE_HISTORY_SEG.test(seg) || HISTORY_FILE_RE.test(seg)))
        return credHit("credential marker filter", `${seg} | ${nxt}`, "a bare environment or history dump is filtered down to its credential lines and printed (shape redacted) — wc counts and -q presence check without revealing");
    }
    // Command-text leg: BARE credential-source text in the arguments never rides the ask
    // band. QUOTED payloads are the brain's to judge, not the floor's — the operator ruled
    // the command-text leg stays (restored 2026-10-13 after an over-aggressive removal —
    // heuristics are part of the design, per the operator): catches real compound exposures
    // the brain's output-focused leak question misses in degraded mode — env/token reads
    // piped into egress, argv-passed keys. PRECISION per the reviewer consensus: version
    // checks, package queries, cache cleanup, and tool-log reads of the secret-manager CLI
    // are mention-only safe shapes, not movement. Inspection paths under .ssh/ are exempt.
    const bare = /^git\s+commit\b/i.test(seg)
      ? seg.replace(/(-m|--message)\s+'(?:[^'\\]|\\.)*'/gi, "$1 ''").replace(/(-m|--message)\s+"(?:[^"\\]|\\.)*"/gi, '$1 ""')
      : seg;
    if (credSourceHit(bare)) {
      const safe = stdinStore ||
        /^(?:source|\.)\s/.test(seg) ||
        /^infisical\s+(run|export)\b/i.test(seg) && /run\b|--output-file/i.test(seg) ||
        /^infisical\s+(-h|--help|version|--version)\b/i.test(seg) ||
        /^(?:pacman|paru|pkexec)\b.*(?:-Q|-S|-U|-Si|-Ss|-F|-l)\b/.test(seg) && /infisical/i.test(seg) ||
        /infisical-bin.*(?:\.pkg\.tar\.zst|clone)/.test(seg) ||
        /(^|[^A-Za-z0-9_-])(grep|egrep|fgrep|rg|ag)\s/.test(seg) && GREP_PRESENCE_RE.test(seg) ||
        /(^|[^A-Za-z0-9_-])wc\s/.test(seg);
      if (!safe && credSourceHit(bare.replace(SSH_INSPECTION_RE, " ")))
        return credHit("credential-source argument text", bare, "the command carries credential-source text in its arguments (redacted) — it must not ride the ask band");
    }
  }
  return null;
}

export function stripBlockedPrefix(reason) {
  return String(reason ?? "").replace(/^secret-leak-guard: BLOCKED \(command did not run\) — /, "");
}

// Map a vendored-rules deny reason to its rule family (docs/rules-retirement.md).
export function familyOf(reason) {
  // Order matters: several reasons mention other families' tools in their advice text
  // (the credential-file reason suggests a secret-manager run; the docker-env reason says "environment").
  if (/credential file/i.test(reason)) return "credential-file";
  if (/config\.ya?ml/i.test(reason)) return "agent-config";
  if (/traces every expanded command/i.test(reason)) return "shell-tracing";
  if (/docker/i.test(reason) || /container's full environment/i.test(reason))
    return /Config\.Env|format/i.test(reason) ? "docker-inspect-format" : "docker-env";
  if (/clientSecret|secretValue|secrets\/raw|universal-auth/i.test(reason)) return "curl-secret-api";
  if (/infisical/i.test(reason)) return "infisical";
  if (/printenv|full environment/i.test(reason)) return "env-dump";
  if (/command line|argv|environ|pgrep/i.test(reason)) return "process-argv";
  return "unclassified";
}

// Leg B — executable-egress call-site (write content only).
const EGRESS_RE = /(urlopen\s*\(|requests\s*\.\s*(?:post|put|patch)\s*\(|(^|[^A-Za-z0-9_-])curl\s|Invoke-WebRequest|new\s+WebSocket\s*\(|axios\s*\.|\bfetch\s*\()/i;
// Markdown inline-code spans are discussion, not staging — the corpus's only near-hits are
// backticked shell examples in security docs. Fenced blocks are NOT stripped: a fenced payload
// in a written doc still stages. (Lines and newlines are preserved, so line extraction works.)
const stripInlineCode = (s) => String(s ?? "").replace(/`[^`\n]*`/g, " ");

/** Corpus-selfcheck probe (epic-ask-band-posture 7.7): the write floor's exact legs over one
 *  text blob — leg A on the raw content, leg B on the inline-code-stripped content. Exported
 *  so the test harness measures exactly what the floor enforces, with no regex duplication. */
export function writeFloorSelfcheck(content) {
  const cred = credSourceHit(content);
  const egress = EGRESS_RE.test(stripInlineCode(content));
  return { cred, egress, compound: cred && egress };
}

/** Write-content floor (epic-ask-band-posture 7.7): the two legs ANDed over the content, plus
 *  the existing checkRead secret-shape check routed to the write TARGET (it covered bash- and
 *  read-shaped names only — a write into a credential-shaped path is credential-source
 *  evidence; alone it stays brain-side, since writing into a credential file is ordinary dev
 *  work). Returns { family, lines, matched, reason } on a compound hit, null otherwise; the
 *  matched clause names the write-then-run chain by line number (values masked in the lines). */
export function writeContentFloorVerdict(tool, input, { cwd, env } = {}) {
  if (!WRITE_FLOOR_TOOLS.test(String(tool ?? "").toLowerCase())) return null;
  const target = input?.file_path ?? input?.path ?? input?.filePath ?? input?.notebook_path ?? "";
  const pathHit = !!checkRead(String(target ?? ""));
  const content = collectWriteContent(input);
  const credHits = matchedLinesNumbered(content, CRED_SOURCE_RES);              // leg A: raw content
  const egressHits = matchedLinesNumbered(stripInlineCode(content), [EGRESS_RE]);  // leg B: inline-code spans stripped
  const credLines = credHits.map((x) => x.l);
  const egressLines = egressHits.map((x) => x.l);
  if (!(credLines.length || pathHit) || !egressLines.length) return null;
  const chainClauses = [
    ...(pathHit ? ["the write target is a credential-shaped path"] : []),
    ...(credHits.length ? [`line ${credHits[0].n} reads a credential file / carries a secret-shaped value`] : []),
    ...(egressHits.length ? [`line ${egressHits[0].n} sends its value over the network`] : []),
  ];
  return {
    family: "write-credential-egress",
    lines: [
      ...(pathHit ? ["(the write target is a credential-shaped path — redacted)"] : []),
      ...[...credLines, ...egressLines].slice(0, 5).map((l) => redactLine(l)),
    ],
    matched: chainClauses.join(", "),
    reason: "this write stages credential-source material together with executable network egress (write-then-run; shapes redacted)",
  };
}

// The read-path credential gate (TR-3, H1): reads of credential files and of the gate's own
// config deny in every mode — a printed secret cannot be un-printed. The verdict needs no
// brain round-trip, so it lives in Always-Deny (it always denied pre-brain on the skip stack;
// the consolidation only removed the read-only SKIP that used to sit in front of it).
// The parens specifics derive the key kind from the vendored isSecretFile classes (the SSH
// private-key family vs the rest); the matched clause displays the PATH (matched-display
// amendment 2026-10-25 — paths display, values mask).
const readPathKind = (rawPath) => {
  const bn = String(rawPath ?? "").replace(/["']/g, "").split(/[\\/]/).pop() ?? "";
  return /^id_(?:rsa|ed25519|ecdsa|dsa)$/.test(bn) || /\.(?:pem|key|p12|pfx|jks|keystore|kdbx|asc|gpg)$/.test(bn) ? "SSH private key" : "credential file";
};
function readPathVerdict(tool, input) {
  const name = String(tool ?? "").toLowerCase();
  if (!READ_PATH_TOOLS.test(name)) return null;
  const candidates = Array.isArray(input?.paths) ? input.paths : [input?.file_path ?? input?.path ?? ""];
  // The guard's own config: a Read prints the stored backend credential into context.
  const guardConfig = candidates.map((p) => String(p ?? "")).find((p) => GUARD_CONFIG_RE.test(p));
  if (guardConfig)
    return { family: "credential-file", reason: "displaying the gate's own config would print its stored backend credential (shape redacted)",
      stats: "agent-config gate: gate config holds a stored API key",
      matched: "the gate's own config file, which stores the backend API key" };
  const hit = candidates.map((p) => ({ p: String(p ?? ""), r: checkRead(String(p ?? "")) })).find((h) => h.r);
  if (!hit) return null;
  const kind = readPathKind(hit.p);
  return { family: familyOf(hit.r), reason: stripBlockedPrefix(hit.r),
    stats: `read-path gate: ${kind}`,
    // the PATH displays (matched-display amendment) but a value-shaped run inside it never
    // does — a token-named key file must not print its token into the message
    matched: `${kind}, ${redactSecretShapes(hit.p)}` };
}

// The Secrets family, whole. Order inside the family preserves the old precedence: the
// credential floors named the shape first (redacted), then the read-path gate, then the
// vendored bash leak rules. Stats are the registry's plain rule parens (rule name + specifics,
// no layer naming, plan-message-registry 2026-10-25); `matched` carries the per-trigger clause
// the guidance's (matched: …) slot renders.
// The vendored leak-guard families: display name for the parens, matched clause from the
// vendored rule's reason.
const LEAK_FAMILY_PARENS = {
  "credential-file": "credential file read", "agent-config": "agent config read", "shell-tracing": "shell trace",
  "docker-env": "container environment dump", "docker-inspect-format": "container inspect env select",
  "curl-secret-api": "secret API call", "infisical": "infisical secrets", "env-dump": "environment dump",
  "process-argv": "process argv", "unclassified": "leak-guard rule",
};
const LEAK_FAMILY_MATCHED = {
  "credential-file": "credential file read, its values would print into the conversation",
  "agent-config": "an agent config file, which embeds inline secrets",
  "shell-tracing": "shell trace, expanded secret arguments land in the output",
  "docker-env": "container environment dump, surfaces the container's injected secrets",
  "docker-inspect-format": "container inspect with an env-selecting format, prints the container's Config.Env values",
  "curl-secret-api": "secret API call, plaintext secrets or tokens return to stdout",
  "infisical": "infisical secrets command, prints secret values to stdout",
  "env-dump": "environment dump, prints every variable's value and secrets may be among them",
  "process-argv": "process argv listing, full command lines print and arguments often carry secrets",
  "unclassified": "a leak-guard rule matched",
};
function secretsVerdict(tool, input, { cwd, env } = {}) {
  // Write-content legs first (the compound staging floor).
  const writeFloor = writeContentFloorVerdict(tool, input, { cwd, env });
  if (writeFloor)
    return { family: "secrets", floor: writeFloor.family, reason: writeFloor.reason, lines: writeFloor.lines, matched: writeFloor.matched,
      category: "Credential Exfiltration", stats: "write-content floor: credential read staged with network egress" };
  const secretShape = secretShapeWriteVerdict(tool, input);
  if (secretShape)
    return { family: "secrets", floor: secretShape.family, reason: secretShape.reason, lines: secretShape.lines, matched: secretShape.matched,
      category: "Credential Exposure", stats: "write-content floor: credential-shaped value" };
  // Credential-source command legs (bash plane; redacted shapes).
  const cred = credentialSourceVerdict(tool, input);
  if (cred)
    return { family: "secrets", floor: cred.family, reason: cred.reason, pattern: cred.pattern, matched: cred.matched,
      category: "Credential Exposure", stats: `credential-source floor: ${cred.pattern}` };
  // Read-path gate (TR-3) — every mode, no brain round-trip.
  const readRule = readPathVerdict(tool, input);
  if (readRule)
    return { family: "secrets", floor: readRule.family, reason: readRule.reason, matched: readRule.matched,
      category: "Credential Exposure", stats: readRule.stats };
  // The vendored bash leak rules (the secret-leak-guard core) — every posture, pre-brain.
  if (BASH_SHAPED.test(String(tool ?? "").toLowerCase())) {
    const cmd = String(input?.command ?? "");
    const reason = cmd ? checkBash(cmd) : null;
    if (reason) {
      const family = familyOf(reason);
      return { family: "secrets", floor: family, reason: stripBlockedPrefix(reason), matched: LEAK_FAMILY_MATCHED[family] ?? LEAK_FAMILY_MATCHED.unclassified,
        category: "Credential Exposure", stats: `leak-guard rule: ${LEAK_FAMILY_PARENS[family] ?? family}` };
    }
  }
  return null;
}

// ── Catastrophic ──────────────────────────────────────────────────────────────────────────────
// The vendored CATASTROPHIC list (11 shapes), imported — never re-implemented. Previously it
// only gated brain-DOWN (the rules posture), because the active-floor escalation list excluded
// it; the consolidation makes it Always-Deny: recursive rm of the root, device writes, fork
// bombs, force pushes, recursive 777 and pipe-to-shell never ride the brain or any lifter, in
// any posture.
function catastrophicVerdict(tool, input) {
  if (!BASH_SHAPED.test(String(tool ?? "").toLowerCase())) return null;
  const cmd = String(input?.command ?? "");
  if (!cmd) return null;
  const reason = checkCatastrophic(cmd);
  if (!reason) return null;
  return { family: "catastrophic", floor: "catastrophic", reason,
    category: "Dangerous Action", stats: "catastrophic command" };
}

// SECRET_SHAPE value detection over write content (consolidation: restores the write-content
// detection the vendoring dropped — the vendored OpenCode plugin nudged on exactly this shape,
// "secret-shape"; here it denies). A credential-shaped TARGET is exempt: writing a key INTO
// its sanctioned home (an env file, a key file) is ordinary secret-store work — the guard's
// job is keeping values out of code and docs, and the two-leg floor above still judges staging.
function secretShapeWriteVerdict(tool, input) {
  if (!WRITE_FLOOR_TOOLS.test(String(tool ?? "").toLowerCase())) return null;
  const target = String(input?.file_path ?? input?.path ?? input?.filePath ?? input?.notebook_path ?? "");
  if (target && (isSecretFile(target) || /(^|\/)\.env(\.[^/\\]*)?$/.test(target))) return null;
  const content = collectWriteContent(input);
  const valueLines = matchedLines(content, SECRET_SHAPE);
  if (!valueLines.length) return null;
  return {
    family: "write-secret-shape",
    // the shape mask runs BEFORE redactLine: underscores split value-like runs, so the generic
    // value-run mask alone would leave a ghp_-class token intact in the matched-line block
    lines: valueLines.slice(0, 5).map((l) => redactLine(redactSecretShapes(l))),
    matched: "the written content carries a credential-shaped value",
    reason: "the written content carries a credential-shaped value (shape redacted) — keys live in the secret store or an env file, not in code or docs",
  };
}

// ── Self-modification ─────────────────────────────────────────────────────────────────────────
// Gate self-protection (plan 1.1, red-team R1 + the 2026-10-17 verb×target rule): deny
// attempts to mutate the gate's own store/policy/config/source from agent context. Two
// layers, merged into one family:
//   bash-shaped tools — the regex family on the command text (per-SEGMENT matching for the
//     source-write verbs: a write verb and a gate-source path must share a segment);
//   every other tool — path-based: any file_path-like input that resolves into the gate's own
//     store/audit/policy/config/sessions paths denies, whatever the tool name.
// Returns a reason string on match, null otherwise. Not liftable by rulings or policy — the
// gate does not accept keys cut against itself.
// The guarded paths: the policy store + mutation audit + the legacy rulings/lane stores +
// config (which define what lifts and what the gate trusts) and the sessions dir (which
// defines what counts as the user's own words).

// Read-shaped tools never write: a Read of the gate's files is not self-modification.
const READ_SHAPED_TOOL = /^(read|view|cat|read_file|read_many_files|notebookread|list_directory|search_file_content|grep_search|glob|grep|ls|list)$|(^|_)read$/i;
// Write/edit-shaped tools get the "does not edit itself" phrasing; other non-read tools the neutral one.
const WRITE_SHAPED_TOOL = /^(write|edit|notebookedit|multiedit|write_file|replace|apply_patch|patch|delete)$|(^|_)(write|edit|delete)$/i;

// 2026-10-17 (operator ruling, usage-triage finding): bash-content WRITES into the gate's own
// source are operator-only, same chat-blind family as the store guard. The glob engine has no
// negation and Write/Edit tools are the dev workflow (path guard unchanged), so this is a
// verb×target pairing: each branch fires only when a WRITE shape and a gate-source path share
// a segment. Reads (grep, sed -n, cat, head, tail, rg, wc, node --test) match nothing.
const GATE_MODULES = String.raw`(?:guard|always-deny|policy|lane|orchestrate|jev|rulings|session|context|contract|hook|cli|opencode|acp|detect|install|setup|skills)`;
const GATE_SRC_WRITE = new RegExp([
  // 1. redirect whose TARGET region holds a gate-source path (cat src/guard.js > /tmp/x passes —
  // the path there is the read source, not the redirect target)
  String.raw`>>?\s*["']?(?:[\w.{}$~/-]*[/\\])?src[/\\]` + GATE_MODULES + String.raw`\.(?:js|mjs|ts)\b`,
  // 2. in-place editors
  String.raw`(?:\bsed\s+[^|;\n]*-i|\bperl\s+[^|;\n]*-i[a-zA-Z]*)\s+["']?[^|;\n]*src[/\\]` + GATE_MODULES + String.raw`\.(?:js|mjs|ts)\b`,
  // 3. language writers (python open with w/a/x mode; node write/append)
  String.raw`\bopen\s*\(\s*["'][^"']*src[/\\]` + GATE_MODULES + String.raw`\.(?:js|mjs|ts)["']\s*,\s*["'][wax+]`,
  String.raw`\b(?:writeFileSync|appendFileSync)\s*\(\s*["'\`][^"'\\\`]*src[/\\]` + GATE_MODULES + String.raw`\.(?:js|mjs|ts)`,
  // 4. destination-position copy (cp a src/guard.js fires; cp src/guard.js /tmp/x passes)
  String.raw`\b(?:cp|mv|install)\s+["']?[^"'\n;|]+["']?\s+["']?[^"'\n;|]*[/\\]?src[/\\]` + GATE_MODULES + String.raw`\.(?:js|mjs|ts)\b`,
  String.raw`\btee\s+["']?[^|;\n]*src[/\\]` + GATE_MODULES + String.raw`\.(?:js|mjs|ts)\b`,
  String.raw`\bdd\b[^|;\n]*of=["']?[^|;\n]*src[/\\]` + GATE_MODULES + String.raw`\.(?:js|mjs|ts)\b`,
].join("|"));

// The bash half. The store regex covers every name the store has had: the legacy rulings and
// user-lane files and the consolidated user-policy files. Returns { reason, leg } (leg ∈
// "store" | "source" | "path" — the structural classification the header parens key on) or
// null; the legacy string return is object-wrapped (truthy/null semantics unchanged).
export function selfModVerdict(tool, input, { cwd, env = process.env } = {}) {
  const name = String(tool ?? "").toLowerCase();
  const cmd = /bash|shell|run_shell_command|terminal|zsh|sh/.test(name) ? String(input?.command ?? "") : "";
  if (/ruling\s+(?:add|revoke)|rulings(?:-use)?\.json|user-lane(?:-use)?\.json|user-policy(?:-use)?\.json|\bpolicy\s+(?:add|remove|set|adopt-defaults)\b|\blane\s+(?:add|remove)\b|(?:GUARD|JEV_GUARD)_OPERATOR_CLI\s*=/.test(cmd))
    return { reason: "this command modifies the gate's own policy or rulings store — operator-only (run it from your own terminal)", leg: "store" };
  // Per-SEGMENT matching (the rulings matcher's own lesson, learned live: full-string testing
  // pairs a `sed -i` in one segment with a gate-source path in another across an &&). A write
  // verb and a gate-source path must share a segment to fire.
  if (subCommands(input, tool).some((p) => GATE_SRC_WRITE.test(p)))
    return { reason: "this command writes the gate's own source — operator-only (run it from your own terminal; edit the checkout via the project's reviewed dev flow)", leg: "source" };
  const pathReason = pathSelfModVerdict(tool, input, { cwd, env });
  return pathReason ? { reason: pathReason, leg: "path" } : null;
}

// The path branch, split out so callers can scope the user-words lift to it: only a PATH-guard
// deny yields to the user's own words (operator ruling 2026-10-04); the bash-regex layer above
// denies unchanged in all cases (matrix row 5).
export function pathSelfModVerdict(tool, input, { cwd, env = process.env } = {}) {
  const candidate = typeof input === "string" ? input
    : input?.file_path ?? input?.path ?? input?.filePath ?? input?.notebook_path;
  if (!candidate || !guardedPathHit(candidate, { cwd, env })) return null;
  const name = String(tool ?? "").toLowerCase();
  if (READ_SHAPED_TOOL.test(name)) return null;  // reading the gate's files is not an edit
  return WRITE_SHAPED_TOOL.test(name)
    ? "this file is inside the guard's own store/config/sessions — operator-only (the gate does not edit itself)"
    : "this file is inside the guard's own store/config/sessions — operator-only";
}

// The gate's own paths: the store FILES inside each home (guarding the whole directory would
// brick every Write on hosts where the home is a shared tree — this repo's root is one), the
// config overrides that live outside them, and the sessions DIRECTORY (it only ever holds
// gate state). The consolidated policy store joins its legacy names (a Write to the old
// user-lane.json or rulings.json is still a self-modification attempt).
function guardedPaths(env) {
  return [...new Set([
    ...[guardHome(env), guardHome({})].flatMap((h) => [join(h, "user-policy.json"), join(h, "user-policy-use.jsonl"), join(h, "rulings.json"), join(h, "rulings-use.jsonl"), join(h, "user-lane.json"), join(h, "user-lane-use.jsonl"), join(h, "config.json")]),
    sessionsDir(env), sessionsDir({}), CONFIG_FILE, LEGACY_CONFIG_FILE, env.GUARD_CONFIG, env.JEV_GUARD_CONFIG,
  ].filter(Boolean).map((p) => resolve(p)))];
}

const expandHome = (p) => (p === "~" || p.startsWith("~/") ? join(homedir(), p.slice(1)) : p);

export function guardedPathHit(candidate, { cwd, env = process.env } = {}) {
  const p = resolve(cwd ?? process.cwd(), expandHome(String(candidate)));
  return guardedPaths(env).some((g) => p === g || p.startsWith(g + sep));
}

// In-family presentation: the self-mod family wraps its reasons with the category and the
// registry's plain rule parens, keyed on the leg (the structural classification).
const SELF_MOD_PARENS = { store: "policy store write", source: "gate source write", path: "guard's own store/config/sessions" };
function selfModFamily(tool, input, ctx) {
  const verdict = selfModVerdict(tool, input, ctx);
  if (!verdict) return null;
  return { family: "self-mod", reason: verdict.reason,
    category: "Gate Self-Protection", stats: SELF_MOD_PARENS[verdict.leg] ?? "gate self-protection" };
}

// ── the layer, whole ──────────────────────────────────────────────────────────────────────────
// Order: Secrets, then Self-modification, then Catastrophic — the old precedence, where the
// credential floor named the shape before the self-mod guard ran, and the catastrophic list
// gated only after both.
export function alwaysDeny(tool, input, { cwd, env = process.env } = {}) {
  const ctx = { cwd, env };
  return secretsVerdict(tool, input, ctx)
    ?? selfModFamily(tool, input, ctx)
    ?? catastrophicVerdict(tool, input);
}
