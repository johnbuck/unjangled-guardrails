// Reproduce blue-team C1 (missing approval answer -> crash path) and H1 (read tools ungated).
// The JEV_API_KEY stub-shape makes the fake shim reachable, so C1 exercises the partial-answer
// path itself instead of degrading earlier on "no backend".
import { assessAction } from "../src/guard.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const env = { JEV_API_KEY: "test", GUARD_HOME: mkdtempSync(join(tmpdir(), "triage-")) };

// C1: shim returns answers with risk + user_requested but NO approval key
const partial = async () => ({ ok: true, json: async () => ({ answers: {
  risk: { type: "score", score: 2.0, probabilities: {}, confidence: 0.9 },
  user_requested: { type: "noul", noul: 0.3 } } }) });
try {
  const r = await assessAction({ tool: "Bash", input: { command: "git push origin" }, cwd: "/proj" }, { env, fetchImpl: partial });
  console.log("C1: no crash, verdict =", r?.level, r?.degraded ? "(degraded to the rules path — C1 FIXED)" : "(brain verdict — C1 NOT exercised)");
} catch (e) { console.log("C1 REPRODUCED — crash:", e.message); }

// H1: read-shaped tools with a credential path — gated or skipped?
const read = await assessAction({ tool: "Read", input: { file_path: "/home/x/.ssh/id_rsa" }, cwd: "/proj" }, { env, fetchImpl: partial });
console.log("H1: Read of an id_rsa path ->", read === null ? "SKIPPED (ungated)" : `${read.level} (rules family: ${read.floor})`);
const rf = await assessAction({ tool: "read_file", input: { path: "/home/x/.ssh/id_rsa" }, cwd: "/proj" }, { env, fetchImpl: partial });
console.log("H1: read_file same path ->", rf === null ? "SKIPPED (ungated)" : `${rf.level} (rules family: ${rf.floor})`);
const cat = await assessAction({ tool: "Bash", input: { command: "view /home/x/.ssh/id_rsa" }, cwd: "/proj" }, { env, fetchImpl: partial });
console.log("H1 control: bash 'view' same path ->", cat === null ? "skipped" : cat.level, cat?.level === "deny" ? "(rules catch)" : "");
