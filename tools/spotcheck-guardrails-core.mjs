import { checkCatastrophic } from "../vendor/guardrails-core/rules.mjs";
const PROBE_FILE = "/tmp/opencode/probe-cases.txt";
import { readFileSync } from "node:fs";
for (const line of readFileSync(PROBE_FILE, "utf8").split("\n")) {
  if (!line.trim()) continue;
  const cmd = line.replace(/\\n/g, " ");
  console.log(cmd.slice(0, 40).padEnd(42), checkCatastrophic(cmd) ? "HIT" : "miss");
}
