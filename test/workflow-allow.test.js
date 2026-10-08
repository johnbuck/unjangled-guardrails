// Standing workflow allows, baked into the rules layer (operator ruling 2026-10-08): the Paseo
// orchestration plane and BMAD bookkeeping on the bash plane skip the classifier entirely — no
// brain round-trip, no session ruling needed, no expiry. The observable contract: assessAction
// returns null (guard silent) for allowed shapes and a verdict object for everything else.
// All tests run with an empty env (no backend): a non-skipped call degrades instantly and
// offline, so null-vs-verdict is decided by the skip alone.
import { test } from "node:test";
import assert from "node:assert/strict";
import { assessAction } from "../src/guard.js";
import { isCoordinationTool } from "../src/orchestrate.js";

const bash = (command) => assessAction({ tool: "Bash", input: { command } }, { env: {} });
const paseo = (tool) => assessAction({ tool, input: {} }, { env: {} });

test("coordination skip: prefix-matched paseo plane, both name spellings, legacy aliases", () => {
  assert.equal(isCoordinationTool("mcp__paseo__respond_to_permission"), true);   // the Claude-hook spelling the old set never matched
  assert.equal(isCoordinationTool("mcp__paseo__send_agent_prompt"), true);
  assert.equal(isCoordinationTool("mcp__paseo__browser_navigate"), true);        // browser/terminal families ride the prefix
  assert.equal(isCoordinationTool("paseo_create_agent"), true);                  // adapters that strip the server prefix
  assert.equal(isCoordinationTool("sendmessage"), true);                         // 2026-10-07 aliases stay
  assert.equal(isCoordinationTool("Bash"), false);
  assert.equal(isCoordinationTool("mcp__playwright__browser_click"), false);     // other MCP servers are not the paseo plane
  assert.equal(isCoordinationTool("mcp__paseo_evil__x"), false);                 // a lookalike server name is not the paseo plane — normal flow
});

test("paseo tool calls skip the classifier with no brain configured", async () => {
  assert.equal(await paseo("mcp__paseo__respond_to_permission"), null);
  assert.equal(await paseo("mcp__paseo__browser_snapshot"), null);
});

test("BMAD script family skips the classifier", async () => {
  assert.equal(await bash("uv run /home/u/ug/_bmad/scripts/resolve_config.py --project-root /home/u/ug --key core.output_folder"), null);
  assert.equal(await bash("uv run --no-cache /home/u/ug/_bmad/scripts/render_skill.py --project-root /home/u/ug --skill /home/u/.claude/skills/bmad-build"), null);
  assert.equal(await bash("uv run /home/u/ug/_bmad/method/scripts/tickets.py --project-root /home/u/ug find 2.1"), null);
  assert.equal(await bash("python3 /home/u/.claude/skills/bmad-ticket/scripts/read_toml.py --file /home/u/ug/_bmad/custom/ticketing-store-config.toml -k tickets"), null);
});

test("git bookkeeping confined to _bmad-output/ skips the classifier", async () => {
  assert.equal(await bash("git add _bmad-output/initiative-v1-harden-share/x.md && git commit -m \"feat: the plan record\" _bmad-output/initiative-v1-harden-share/x.md && git push origin main"), null);
  assert.equal(await bash("git status --short -- _bmad-output/ && git add _bmad-output/a.md && git commit -m \"msg\" _bmad-output/a.md && git push origin main"), null);
  assert.equal(await bash("git add /home/u/ug/_bmad-output/epic/x.md && git restore --staged /home/u/ug/_bmad-output/epic/x.md"), null);
  assert.equal(await bash("git status"), null);
  assert.equal(await bash("git diff -- _bmad-output/a.md"), null);
});

test("a push or pathspec-less commit is not bookkeeping: it keeps the normal flow and its rulings", async () => {
  // a lone push publishes whatever the branch carries — never confined by this allow
  assert.ok(await bash("git push"));
  assert.ok(await bash("git push origin main"));
  // pathspec-less commit takes the whole staged tree
  assert.ok(await bash("git add _bmad-output/a.md && git commit -m \"msg\""));
  // a push before any confined write in the chain
  assert.ok(await bash("git push origin main && git add _bmad-output/a.md"));
});

test("near-misses do not ride the skip: they take the normal flow", async () => {
  // mixed pathspecs: not confined to _bmad-output
  assert.ok(await bash("git add src/guard.js _bmad-output/a.md && git commit -m \"mixed\""));
  // traversal escapes the confinement
  assert.ok(await bash("git add _bmad-output/../../.ssh/config"));
  // -a/--all stages repo-wide
  assert.ok(await bash("git commit -a -m \"done\""));
  // command substitution: the shape check cannot confine what it cannot see
  assert.ok(await bash("git add _bmad-output/$(boom)"));
  assert.ok(await bash("git add _bmad-output/`boom`"));
  // no _bmad anchor on the script path
  assert.ok(await bash("uv run /tmp/evil.py --project-root /home/u/ug"));
  // a segment that is neither family
  assert.ok(await bash("uv run /home/u/ug/_bmad/scripts/resolve_config.py --key k && head -5 /home/u/.ssh/id_ed25519"));
  // decorated (piped) forms keep today's behavior
  assert.ok(await bash("uv run /home/u/ug/_bmad/scripts/resolve_config.py --project-root /home/u/ug 2>&1 | head -5"));
});

test("the secret floor still denies inside the normal flow", async () => {
  const r = await bash("cat /home/u/.ssh/id_ed25519");
  assert.ok(r, "expected a verdict");
  assert.equal(r.level, "deny");
});
