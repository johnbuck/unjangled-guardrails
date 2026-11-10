// The shared evidence guard's collision contract (epic-github-field-reports ticket 1.20, the
// closing sweep) — the deterministic pins for the fix that retired the setup evidence-race the
// 1.8/1.12/1.13/1.16/1.7 close-outs documented and deferred. The race lived in the five local
// guard copies interleaving on the same repo-anchored evidence bytes (one guard's truncate-
// rewrite read as a momentary-empty file by a sibling's row-reader; one guard's created-file
// rmSync pulling the file out from under a sibling mid-read); the fix is the helper's
// cross-process mkdir lock held across each guarded section plus the atomic rename rewrite.
// These pins prove the mechanism deterministically — mutual exclusion across real processes,
// the named timeout error, the stale-holder break, the byte-equivalent subtract semantics, the
// created-file rule, mode preservation with zero temp stragglers, release-on-restore, and the
// calibrate-style names narrowing — on temp dirs and throwaway lock paths, never the repo's
// real evidence files.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { evidenceGuard, withEvidenceLock } from "./evidence-guard.mjs";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const date = () => new Date().toISOString().slice(0, 10);
const tempDir = () => mkdtempSync(join(tmpdir(), "ug-evguard-"));

// ── the lock ─────────────────────────────────────────────────────────────────────────────────

test("mutual exclusion across processes: a live holder blocks the acquire with the named error, and the next acquire waits it out", async () => {
  const scratch = tempDir();
  const lockPath = join(scratch, "cross-process.lock");
  const marker = join(scratch, "held.marker");
  // A real child process acquires the lock, marks that it holds it, and holds it briefly —
  // the shape of a sibling suite's guarded section.
  const child = spawn(process.execPath, ["--input-type=module", "-e", `
    const { writeFileSync } = await import("node:fs");
    const { withEvidenceLock } = await import(${JSON.stringify(pathToFileURL(join(REPO, "test", "evidence-guard.mjs")).href)});
    withEvidenceLock(() => {
      writeFileSync(${JSON.stringify(marker)}, "held");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1200);
    }, { lockPath: ${JSON.stringify(lockPath)} });
  `], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));
  const exited = new Promise((res) => child.on("close", res));
  const deadline = Date.now() + 5000;
  while (!existsSync(marker) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
  assert.ok(existsSync(marker), `child never marked the lock held${stderr ? ` — child stderr: ${stderr}` : ""}`);
  // While the child holds: a short-budget acquire fails with the one clear line, naming the path.
  assert.throws(
    () => withEvidenceLock(() => assert.fail("must not run under a live holder"), { lockPath, waitMs: 150, retryMs: 25 }),
    /evidence guard lock is held by another process \(.*\) — retry in a moment/,
  );
  // Once the child releases: the generous-budget acquire proceeds (it waited the holder out).
  assert.equal(withEvidenceLock(() => "acquired", { lockPath, waitMs: 10_000, retryMs: 25 }), "acquired");
  await exited;
  assert.equal(child.exitCode, 0, `child exited nonzero${stderr ? ` — stderr: ${stderr}` : ""}`);
});

test("a stale holder (a crashed section's lingering lock dir) is broken by mtime, not waited out", () => {
  const lockPath = join(tempDir(), "stale.lock");
  mkdirSync(lockPath);  // the dead holder's leftover — never released
  const twoHoursAgo = new Date(Date.now() - 2 * 3600_000);
  utimesSync(lockPath, twoHoursAgo, twoHoursAgo);
  const t0 = Date.now();
  assert.equal(withEvidenceLock(() => "broke the stale lock", { lockPath, staleMs: 60_000, waitMs: 10_000, retryMs: 25 }), "broke the stale lock");
  assert.ok(Date.now() - t0 < 1000, "the stale break must be immediate, not a wait-out");
});

test("release-on-restore: the next guard on the same file set acquires immediately, and a double restore is a no-op", () => {
  const dir = tempDir();
  const guard = evidenceGuard({ dir });
  guard();
  guard();  // idempotent — neither throws nor releases anyone else's lock
  const t0 = Date.now();
  const second = evidenceGuard({ dir });  // same file set → same lock key: proves the release
  second();
  assert.ok(Date.now() - t0 < 2000, "the second guard must acquire immediately after the first restore");
});

// ── the restore's byte-equivalent subtract semantics (the landed discipline, unchanged) ──────

test("subtract is multiplicity-aware: appended lines drop, snapshot duplicates survive at their snapshot count, bytes exact, via atomic rename with the file's own mode and zero temp stragglers", () => {
  const dir = tempDir();
  const file = join(dir, `setup-${date()}.jsonl`);
  const before = '{"row":"a"}\n{"row":"b"}\n{"row":"a"}\n';  // a duplicate of a is already in the snapshot
  writeFileSync(file, before);
  chmodSync(file, 0o640);  // force the mode regardless of the process umask — the rename must carry it
  const restore = evidenceGuard({ dir });
  writeFileSync(file, '{"row":"c"}\n{"row":"a"}\n', { flag: "a" });  // this run appended: a new row AND a duplicate
  restore();
  assert.equal(readFileSync(file, "utf8"), before, "c drops, the appended duplicate drops, both snapshot a's and b stay — bytes exact");
  // the rename path: the file keeps its own mode and no guard temp remains in the directory
  assert.equal(statSync(file).mode & 0o777, 0o640, "mode preserved through the temp-and-rename rewrite");
  assert.ok(readdirSync(dir).every((n) => !n.includes(".guard-")), "no .guard-* temp straggler");
});

test("the created-file rule: a file this run created is removed on restore (under the lock, so no sibling is mid-read)", () => {
  const dir = tempDir();
  const file = join(dir, `setup-${date()}.jsonl`);
  const restore = evidenceGuard({ dir });
  writeFileSync(file, '{"row":"this-run"}\n');
  restore();
  assert.equal(existsSync(file), false, "the file this run created is gone — the guard leaves no straggler");
});

test("the names narrowing (calibrate's shape): exactly the named file is guarded, siblings untouched", () => {
  const dir = tempDir();
  const calibrateFile = join(dir, `calibrate-${date()}.jsonl`);
  const setupFile = join(dir, `setup-${date()}.jsonl`);
  writeFileSync(calibrateFile, '{"row":"cal"}\n');
  writeFileSync(setupFile, '{"row":"setup"}\n');
  const restore = evidenceGuard({ dir, names: [`calibrate-${date()}.jsonl`] });
  writeFileSync(calibrateFile, '{"row":"this-run"}\n', { flag: "a" });
  writeFileSync(setupFile, '{"row":"not-my-file"}\n', { flag: "a" });
  restore();
  assert.equal(readFileSync(calibrateFile, "utf8"), '{"row":"cal"}\n', "the named file's appended row is subtracted");
  assert.equal(readFileSync(setupFile, "utf8"), '{"row":"setup"}\n{"row":"not-my-file"}\n', "the sibling the guard does not name is untouched");
});
