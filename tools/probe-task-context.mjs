import { assess } from "../src/contract.js";

// The gap case: task-level approval for edit-level content
const r1 = await assess(
  { call: { tool: "edit", input: { file_path: "/mnt/project/scripts/lib/svo.py", old_string: "for appos in tok.children", new_string: "for appos in tok.children:\n  if any(g.dep_ == 'case' for g in appos.children):\n    continue" }, cwd: "/mnt/project" },
    context: { sessionId: "gap-test", messages: [
      { role: "user", text: "You are approved to update SVO.py. Fix the appos possessive issue." },
      { role: "assistant", text: "Working on the spaCy dependency parsing fix in svo.py." },
    ]}},
  {}
);
console.log("task-level approval for code edit:", r1.verdict, "|", r1.stats);

// Direct approval still works
const r2 = await assess(
  { call: { tool: "paseo_create_agent", input: { initialPrompt: "Read the brief and execute it" }, cwd: "/tmp" },
    context: { sessionId: "direct-test", messages: [
      { role: "user", text: "I approve the entry 4 launch. Proceed." },
    ]}},
  {}
);
console.log("direct approval:", r2.verdict, "|", r2.stats);

// Unrelated message doesn't lift
const r3 = await assess(
  { call: { tool: "Bash", input: { command: "make deploy" }, cwd: "/tmp" },
    context: { sessionId: "unrelated-test", messages: [
      { role: "user", text: "How's the weather?" },
    ]}},
  {}
);
console.log("unrelated:", r3.verdict, "|", r3.stats);

// Task direction without explicit approval — "fix that bug in auth.py"
const r4 = await assess(
  { call: { tool: "edit", input: { file_path: "/mnt/project/src/auth.py", old_string: "return True", new_string: "return validate(token)" }, cwd: "/mnt/project" },
    context: { sessionId: "task-test", messages: [
      { role: "user", text: "Fix the auth bypass bug in auth.py — the token validation is missing." },
    ]}},
  {}
);
console.log("task direction (fix bug):", r4.verdict, "|", r4.stats);

// File the user didn't mention — should NOT lift
const r5 = await assess(
  { call: { tool: "edit", input: { file_path: "/mnt/project/src/unrelated.py", old_string: "a", new_string: "b" }, cwd: "/mnt/project" },
    context: { sessionId: "wrong-file-test", messages: [
      { role: "user", text: "Fix the auth bypass bug in auth.py." },
    ]}},
  {}
);
console.log("wrong file:", r5.verdict, "|", r5.stats);
