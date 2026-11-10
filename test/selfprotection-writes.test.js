// Target-keyed self-protection, the writes half (ticket 18 / GHI-18, CAP-1 — operator ruling
// 2026-11-09): only an actual write into the gate's own directories triggers the
// self-protection block; a file written anywhere else that merely MENTIONS the gate is judged
// by the normal brain like any other write; real gate writes still deny; every deny names
// exactly what it matched. The rows here are the doctrine's both-directions battery: the
// reporter repro (the 12-file scratch loop whose content discusses the gate) and the
// content-mention shapes pass, the literal write targets under protected roots deny with the
// resolved path named, and every bash-plane row from ticket 10 holds byte-identical.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { selfModVerdict, execPayloadVerdict, pathSelfModVerdict, alwaysDeny } from "../src/always-deny.js";
import { assessAction } from "../src/guard.js";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const scratchHome = () => mkdtempSync(join(tmpdir(), "unjangled-guardrails-selfwr-"));

// The suites' shared fake-brain shape: everything scores 0.2, so a non-floor call allows.
const calmBrain = async () => ({
  ok: true,
  json: async () => ({ answers: {
    risk: { type: "score", score: 0.2, probabilities: {}, confidence: 0.8 },
    approval: { type: "noul", noul: 0.05 }, user_requested: { type: "noul", noul: 0.05 }, from_untrusted: { type: "noul", noul: 0.05 },
    leaks_secrets: { type: "noul", noul: 0.05 }, dumps_env_argv: { type: "noul", noul: 0.05 },
    dumps_process_argv: { type: "noul", noul: 0.05 }, reads_credential_file: { type: "noul", noul: 0.05 },
  } }),
});

const verdict = (code, { cwd = "/proj", home = scratchHome() } = {}) =>
  selfModVerdict("execute_code", { code }, { cwd, env: { GUARD_HOME: home } });

// ── the repro family: content mentions and scratch targets never fire ────────────────────────

test("GHI-18 repro: the 12-file scratch loop — variable targets, content about the gate — passes", () => {
  // the reporter's shape: markdown bodies describing guardrail behaviour written under a
  // scratch cache; the write targets are computed (join), so nothing resolves and no leg
  // keys on payload text
  const code = [
    "files = {}",
    "for i in range(12):",
    "    files[f'field-report-{i}.md'] = body.replace('{n}', str(i))",
    "for name, body in files.items():",
    "    open(join(scratch, name), 'w').write(body)",
  ].join("\n");
  assert.equal(verdict(code), null);
});

test("literal scratch targets pass regardless of gate-related content", () => {
  const home = scratchHome();
  assert.equal(verdict("open('/tmp/scratch/notes.md', 'w')", { home }), null);
  // a batched absolute-target loop — every literal is scratch
  assert.equal(verdict("for p in ['/tmp/scratch/a.md', '/tmp/scratch/b.md']:\n    open(p, 'w')", { home }), null);
});

test("content embedded in the payload (triple-quoted spans quoting write shapes) is discussion, not a target", () => {
  const home = scratchHome();
  // the probe case that denied live during this ticket's investigation (pre-fix): the
  // markdown BODY quotes the gate-source write shape — the span is stripped before extraction
  const body = "the rule denies write" + "FileSync('src/guard.js', code) shapes";
  const code = `files = {'note.md': '''${body}'''}\nopen('/tmp/scratch/note.md', 'w')`;
  assert.equal(verdict(code, { home }), null);
  // the JS template-literal spelling of the same discussion
  const js = `const files = { 'note.md': \`documents writeFileSync(join(root, 'src/always-deny.js'), c)\` };\nwriteFileSync('/tmp/scratch/note.md', '');`;
  assert.equal(verdict(js, { home }), null);
});

test("a write tool whose input carries no path field is not text-scanned (the JSON fallback is out)", () => {
  const home = scratchHome();
  // the second live misfire shape: a pathless write input whose edit text mentions a write
  // shape — pre-fix the whole input JSON was matched as text and denied as a gate source write
  const v = selfModVerdict("write_file", { edits: [{ old: "x", new: "write" + "FileSync('src/guard.js', c)" }] },
    { cwd: "/proj", env: { GUARD_HOME: home } });
  assert.equal(v, null);
});

test("write tools to scratch with gate-mentioning content pass; guarded targets still deny (path branch, pinned)", () => {
  const home = scratchHome();
  const env = { GUARD_HOME: home };
  assert.equal(pathSelfModVerdict("Write", { file_path: "/tmp/scratch/note.md", content: "documents write" + "FileSync('src/guard.js', c)" }, { cwd: "/proj", env }), null);
  assert.equal(selfModVerdict("Write", { file_path: join(home, "user-policy.json"), content: "{}" }, { cwd: "/proj", env })?.leg, "path");
});

// ── the true-write battery: literal targets under protected roots deny ────────────────────────

test("an executing payload's literal STORE write denies, naming the resolved target", () => {
  const home = scratchHome();
  const store = join(home, "user-policy.json");
  for (const [code, clause] of [
    [`open('${store}', 'w')`, `the write target ${store} inside an executing payload`],
    [`open('${store}', 'a')`, `the write target ${store} inside an executing payload`],
    [`open('${store}', mode='x')`, `the write target ${store} inside an executing payload`],
    [`open('~/.unjangled-guardrails/user-policy.json', 'w')`, null],  // tilde: the real operator home
    [`open('user-policy.json', 'w')`, `the write target ${store} inside an executing payload`],  // cwd-relative, cwd=home
  ]) {
    const v = verdict(code, { cwd: home, home });
    assert.ok(v, code);
    assert.equal(v.leg, "store", code);
    if (clause) assert.equal(v.matched, clause, code);
  }
});

test("an executing payload's store READ denies as policy store access — the read split's exec plane", () => {
  const home = scratchHome();
  const store = join(home, "rulings.json");
  for (const code of [`open('${store}')`, `open('${store}', 'r')`, `open('${store}', 'rb')`]) {
    const v = verdict(code, { home });
    assert.ok(v, code);
    assert.equal(v.leg, "store-access", code);
    assert.equal(v.matched, `the store path ${store} inside an executing payload`, code);
  }
  // gate-source READS pass — source is readable (ticket 10's split)
  assert.equal(verdict("open('src/guard.js')", { cwd: REPO }), null);
});

test("an executing payload's literal GATE-SOURCE write denies, naming the resolved module path", () => {
  const v = verdict("open('src/guard.js', 'w')", { cwd: REPO });
  assert.ok(v);
  assert.equal(v.leg, "source");
  assert.equal(v.matched, `the gate-source write target ${join(REPO, "src", "guard.js")}`);
  assert.equal(verdict("open('src/always-deny.js', 'w')", { cwd: REPO })?.leg, "source");
});

test("executing payloads writing sessions/config deny on the path leg; sessions reads stay free", () => {
  const home = scratchHome();
  const env = { GUARD_HOME: home, GUARD_SESSIONS: join(home, "sessions") };
  const sessionsWrite = selfModVerdict("run_code", { code: `require('fs').writeFileSync('${join(env.GUARD_SESSIONS, "x.json")}', '{}')` }, { cwd: "/proj", env });
  assert.ok(sessionsWrite);
  assert.equal(sessionsWrite.leg, "path");
  assert.equal(sessionsWrite.matched, `the guard path ${env.GUARD_SESSIONS} inside an executing payload`);
  const configWrite = verdict(`open('${join(home, "config.json")}', 'w')`, { home, env: undefined });
  assert.ok(configWrite && configWrite.leg === "path");
  assert.equal(verdict(`open('${join(env.GUARD_SESSIONS, "x.json")}')`, { home }), null);  // sessions: the user's own words
});

test("the JS writer family extracts: sync, promises, and deletion spellings over the store", () => {
  const home = scratchHome();
  const store = join(home, "user-lane.json");
  for (const code of [
    `require('fs').writeFileSync('${store}', '[]')`,
    `await fs.promises.writeFile('${store}', '[]')`,
    `fs.appendFile('${store}', '[]', cb)`,
    `require('fs').rmSync('${store}')`,
  ]) {
    const v = verdict(code, { home });
    assert.ok(v, code);
    assert.equal(v.leg, "store", code);
  }
  // the Python deletion family over the store, same classification as the bash rm verb
  assert.equal(verdict(`os.remove('${store}')`, { home })?.leg, "store");
  const rmtreeEnv = { GUARD_HOME: home, GUARD_SESSIONS: join(home, "sessions") };
  assert.equal(selfModVerdict("execute_code", { code: `shutil.rmtree('${join(home, "sessions")}')` }, { cwd: "/proj", env: rmtreeEnv })?.leg, "path");
});

test("look-alikes never fire: exact module shape and extension, exact store paths", () => {
  const home = scratchHome();
  for (const code of [
    "open('src/guard.js.bak', 'w')",      // wrong extension
    "open('src/guard.tsx', 'w')",         // not a gate module extension
    "open('lib/guard.js', 'w')",          // not under src/
    "open('/proj/rulings.json', 'w')",    // a sibling file, not the store
    "Path('/tmp/scratch/x.md').write_text(body)",
  ]) assert.equal(verdict(code, { cwd: "/proj", home }), null, code);
});

test("the module-shape residual is conservative and shared with the bash plane", () => {
  // src/<gate-module>.js in a project that is not a gate tree still denies — exactly like the
  // bash `sed -i src/guard.js` row; accepted residual, documented in the plan
  const v = verdict("open('/proj/src/guard.js', 'w')", { cwd: "/proj" });
  assert.ok(v && v.leg === "source");
});

// ── the payload planes: one payload, one jurisdiction ─────────────────────────────────────────

test("shell-named tools keep the bash plane: command payloads never reach the exec extractors", () => {
  const home = scratchHome();
  // the pinned bash classifications hold byte-identical — the node -e span row (store-ACCESS:
  // the span proves a touch, not a mode) and the source segment row
  const span = selfModVerdict("Bash", { command: `node -e "require('fs').writeFileSync('${join(home, "user-policy.json")}','[]')"` }, { cwd: "/proj", env: { GUARD_HOME: home } });
  assert.ok(span && span.leg === "store-access");
  const src = selfModVerdict("Bash", { command: "sed -i 's/a/b/' src/guard.js" }, { cwd: "/proj", env: { GUARD_HOME: home } });
  assert.ok(src && src.leg === "source");
  assert.match(src.matched, /the write shape '/);
  // execPayloadVerdict itself refuses shell-named calls outright
  assert.equal(execPayloadVerdict("Bash", { command: "echo x" }, { cwd: "/proj", env: { GUARD_HOME: home } }), null);
});

test("a command field on a NON-shell-named tool extracts too — neither plane is left empty", () => {
  // execute_code-class harnesses that carry their script in the command field: the bash store
  // legs never ran for them (they key on the shell-family name), so without extraction here a
  // literal store touch would ride the brain — the plane gap found live in this investigation
  const home = scratchHome();
  const v = selfModVerdict("execute_code", { command: `open('${join(home, "rulings.json")}')` }, { cwd: "/proj", env: { GUARD_HOME: home } });
  assert.ok(v);
  assert.equal(v.leg, "store-access");
  assert.equal(selfModVerdict("python", { script: `open('${join(home, "rulings.json")}', 'w')` }, { cwd: "/proj", env: { GUARD_HOME: home } })?.leg, "store");
});

test("payloads riding unlisted field names ride the brain (the recorded residual)", () => {
  const home = scratchHome();
  assert.equal(execPayloadVerdict("execute_code", { program: `open('${join(home, "user-policy.json")}', 'w')` }, { cwd: "/proj", env: { GUARD_HOME: home } }), null);
  assert.equal(execPayloadVerdict("execute_code", {}, { cwd: "/proj", env: { GUARD_HOME: home } }), null);
});

// ── end to end: the surfaced verdicts and their named matches ────────────────────────────────

test("e2e: the repro allows; the exec store write denies pre-brain with the matched slot", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: scratchHome() };
  const store = join(env.GUARD_HOME, "user-policy.json");
  // the repro through the real pipeline: a scratch-writing loop — allowed by the calm brain
  const repro = await assessAction({ tool: "execute_code", input: { code: "for name, body in files.items():\n    open(join(scratch, name), 'w').write(body)" }, cwd: "/proj" },
    { env, fetchImpl: calmBrain });
  assert.equal(repro.level, "allow");
  // the literal store write denies with the resolved target in the (matched: …) slot
  const write = await assessAction({ tool: "execute_code", input: { code: `open('${store}', 'w')` }, cwd: "/proj" },
    { env, fetchImpl: calmBrain });
  assert.equal(write.level, "deny");
  assert.equal(write.stats, "policy store write");
  assert.equal(write.category, "Gate Self-Protection");
  assert.match(write.message, new RegExp(`\\(matched: the write target ${store.replace(/\//g, "\\/")} inside an executing payload\\)`));
  // the message skeleton is otherwise byte-identical: the remaining guidance sentences verbatim
  assert.match(write.message, /Do not try to work around it in any way; no substitution serves the user's goal here\./);
  assert.match(write.message, /they run it in their own terminal\.$/);
  // the gate-source write through an executing payload keeps the source parens
  const src = await assessAction({ tool: "execute_code", input: { code: "open('src/guard.js', 'w')" }, cwd: REPO },
    { env, fetchImpl: calmBrain });
  assert.equal(src.stats, "gate source write");
  assert.match(src.message, /\(matched: the gate-source write target /);
});

test("e2e: the floor needs no brain — an exec store write denies under a dead brain (degradation floor)", async () => {
  const env = { JEV_API_KEY: "test", GUARD_HOME: scratchHome() };
  const down = async () => { throw new Error("connect ECONNREFUSED"); };
  const r = await assessAction({ tool: "execute_code", input: { code: `open('${join(env.GUARD_HOME, "user-policy.json")}', 'w')` }, cwd: "/proj" },
    { env, fetchImpl: down });
  assert.equal(r.level, "deny");
  assert.equal(r.stats, "policy store write");
});

test("the whole-layer shape: alwaysDeny classifies the family and carries no floor name for self-mod", () => {
  const home = scratchHome();
  const ad = alwaysDeny("execute_code", { code: `open('${join(home, "user-policy.json")}', 'w')` }, { cwd: "/proj", env: { GUARD_HOME: home } });
  assert.equal(ad.family, "self-mod");
  assert.equal(ad.stats, "policy store write");
  assert.ok(!("floor" in ad), "self-mod rows record no floor name (the decision-record shape)");
  assert.equal(alwaysDeny("execute_code", { code: "open('/tmp/scratch/x.md', 'w')" }, { cwd: "/proj", env: { GUARD_HOME: home } }), null);
});
