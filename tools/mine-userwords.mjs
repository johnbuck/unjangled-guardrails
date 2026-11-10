#!/usr/bin/env node
// Usage-corpus miner (evaluation-correctness round): walks the local session stores and
// emits every recorded call that has operator words in the same record as a real
// (user words -> command -> recorded verdict) tuple, for the probe's --corpus mode.
// The store's prompts list is the record's CURRENT cap-6 window, not a per-call snapshot —
// tuples are tagged as-observed. Output goes to evidence/ (the sanctioned home for
// internal specifics); the stores themselves are never committed.
// Run: node tools/mine-userwords.mjs [--limit N]   (default: emit all)
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { sessionsDir } from "../src/session.js";
import { fileURLToPath } from "node:url";

const limitIdx = process.argv.indexOf("--limit");
const limit = limitIdx > -1 ? +process.argv[limitIdx + 1] : Infinity;
const hash = (s) => createHash("sha256").update(s).digest("hex").slice(0, 16);

const tuples = new Map();
for (const f of readdirSync(sessionsDir())) {
  let s;
  try { s = JSON.parse(readFileSync(join(sessionsDir(), f), "utf8")); } catch { continue; }
  const user = (s.prompts ?? []).map((p) => p.text).filter(Boolean);
  const intent = (s.intents ?? []).at(-1)?.text ?? "";
  if (!user.length) continue;  // no operator words in the record — nothing to mine
  for (const c of s.calls ?? []) {
    const cmd = c.full ?? c.preview ?? "";
    if (!cmd) continue;
    // Store-hygiene filter (found by the corpus sample): some adapters record permission-
    // response JSON blobs as calls — those are gate verdicts, not commands the gate judged.
    if (cmd.trimStart().startsWith("{")) continue;
    const key = hash(c.tool + "::" + cmd + "::" + user[0]);  // same command under different words = different tuple
    const cur = tuples.get(key);
    if (!cur || (c.at ?? 0) > cur.at) {
      tuples.set(key, { id: key, tool: c.tool, cmd, user, intent, recordedLevel: c.level ?? "unknown", at: c.at ?? 0,
        // hook.js stores only a 100-char preview for ALLOW verdicts (full text only for
        // ask/deny) — flagged so the drift table can carry the truncation caveat per row.
        ...(c.level === "allow" && cmd.length >= 100 ? { truncated: true } : {}) });
    }
  }
}

// Stratified emit when --limit is set: every non-allow recorded verdict first (the scarce,
// interesting classes), then allows newest-first.
let rows = [...tuples.values()].sort((a, b) => a.id < b.id ? -1 : 1);
if (Number.isFinite(limit) && rows.length > limit) {
  const hot = rows.filter((r) => r.recordedLevel === "ask" || r.recordedLevel === "deny");
  const cold = rows.filter((r) => !hot.includes(r)).sort((a, b) => b.at - a.at);
  rows = [...hot, ...cold.slice(0, Math.max(0, limit - hot.length))];
}
const out = new URL("../evidence/usage-userwords-2026-10-16.jsonl", import.meta.url).pathname;
writeFileSync(out, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
const byLevel = {};
for (const r of rows) byLevel[r.recordedLevel] = (byLevel[r.recordedLevel] ?? 0) + 1;
console.log(`evidence: ${out.replace(process.env.HOME ?? "", "~")} — ${rows.length} tuples (${JSON.stringify(byLevel)})`);
