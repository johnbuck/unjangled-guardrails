#!/usr/bin/env node
// Logged-traffic replay (CAP-5: batteries grow from recorded real traffic).
// Replays every unique command in the session store through the CURRENT gate and reports
// recorded-verdict -> current-verdict transitions per command (hash-keyed; raw commands
// never leave the local store). Resumable: completed rows persist to evidence/ and are
// skipped on re-run. Live brain by default; REPLAY_OFFLINE=1 resolves the deterministic
// layers only (no brain calls — recorded brain verdicts stand for the brain band).
// Run as its own harness: node tools/replay-logged.mjs
import { assessAction } from "../src/guard.js";
import { sessionsDir } from "../src/session.js";
import { backend } from "../src/jev.js";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(REPO, "evidence", `replay-${new Date().toISOString().slice(0, 10)}`);
const isMain = process.argv[1] && process.argv[1] === fileURLToPath(import.meta.url);

// Isolated replay home: replay calls must not write breaker counts or session rows into
// the live gate's state. Backend resolution inherits the real environment (config file
// and env vars) — this harness uses the operator's configured brain exactly as the gate does.
const home = join(dirname(sessionsDir()), "replay-home");
mkdirSync(home, { recursive: true });
const env = { ...process.env, GUARD_HOME: home, GUARD_SESSIONS: join(dirname(sessionsDir()), "replay-sessions") };
const offline = process.env.REPLAY_OFFLINE === "1";
if (!offline && !backend(env)) {
  console.error("no backend configured (env or config file) — run with REPLAY_OFFLINE=1 for the deterministic-layers-only replay");
  process.exit(2);
}
const fetchImpl = offline ? async () => { throw Object.assign(new Error("REPLAY_OFFLINE"), { code: "ECONNREFUSED" }); } : undefined;

// unique commands, newest record wins (tool + full-or-preview text is the identity)
const seen = new Map();
for (const f of readdirSync(sessionsDir())) {
  let s; try { s = JSON.parse(readFileSync(join(sessionsDir(), f), "utf8")); } catch { continue; }
  for (const c of s.calls ?? []) {
    const key = c.tool + "::" + (c.full ?? c.preview ?? "");
    const cur = seen.get(key);
    if (!cur || (c.at ?? 0) > cur.at) seen.set(key, { tool: c.tool, cmd: c.full ?? c.preview ?? "", level: c.level, at: c.at ?? 0 });
  }
}
const hash = (s) => createHash("sha256").update(s).digest("hex").slice(0, 16);
const items = [...seen.entries()].map(([key, v]) => ({ key: hash(key), ...v }));
items.sort((a, b) => (a.key < b.key ? -1 : 1));

mkdirSync(OUT, { recursive: true });
const rowsPath = join(OUT, "rows.jsonl");
const doneRows = (() => { try { return readFileSync(rowsPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } })();
const doneHashes = new Set(doneRows.map((r) => r.h));

async function main() {
  const results = [...doneRows];
  let i = 0;
  const t0 = Date.now();
  for (const item of items) {
    if (doneHashes.has(item.key)) continue;
    i++;
    let r = null, err;
    try {
      const isShell = ["bash", "shell"].includes(item.tool.toLowerCase());
      const input = isShell ? { command: item.cmd } : { file_path: item.cmd, content: "" };
      r = await assessAction({ tool: isShell ? "Bash" : item.tool, input, cwd: REPO, sessionId: "replay-" + item.key }, { env, fetchImpl });
    } catch (e) { err = String(e.message ?? e).slice(0, 120); }
    const now = r === null ? "allow" : (r.level ?? "error");
    const row = { h: item.key, then: item.level ?? "unknown", now: err ? "error" : now, layer: r === null ? "skip" : (r.degraded ? "degraded" : (r.risk !== undefined ? "brain" : "floor/rules")), err };
    results.push(row);
    writeFileSync(rowsPath, JSON.stringify(row) + "\n", { flag: "a" });
    if (i % 50 === 0) console.error(`progress ${i} new (${doneHashes.size + i}/${items.length} total, ${Math.round((Date.now() - t0) / 1000)}s)`);
  }

  const trans = {};
  for (const r of results) { const k = `${r.then} -> ${r.now}`; trans[k] = (trans[k] ?? 0) + 1; }
  const loosened = results.filter((r) => (r.then === "deny" || r.then === "ask") && r.now === "allow");
  const tightened = results.filter((r) => r.then === "allow" && (r.now === "ask" || r.now === "deny"));
  const summary = {
    total: results.length,
    transitions: trans,
    loosened: loosened.length,
    tightened: tightened.length,
    offline,
    durationS: Math.round((Date.now() - t0) / 1000),
    rows: rowsPath,
  };
  writeFileSync(join(OUT, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
  console.log(JSON.stringify(summary, null, 2));
  const bad = results.filter((r) => r.now === "error");
  if (bad.length) { console.error(`error rows: ${bad.length}`); process.exit(1); }
}

// import-safe (calibrate/battery convention): the replay only runs when invoked directly
if (isMain) await main();
