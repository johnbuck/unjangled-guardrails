// The shared evidence guard — one collision-proof copy of the subtract-only restore the
// spawn-based suites each used to carry as a local block (ticket 1.20, the epic's closing
// sweep; the lineage: setup.test.js's original recipe, copied by install-empty-policy-warning,
// setup-degradation-posture, detect, and narrowed to one file by calibrate). What it protects:
// the repo-anchored evidence files a spawned `setup`/`calibrate` appends to — a simulated-brain
// test run must leave no rows there, while a solo real run's rows are real artifacts. The
// restore drops exactly the lines THIS run appended (multiplicity-aware diff against the
// snapshot) and keeps every line that was already in the file — a concurrent session's rows
// included — or removes the file outright when this run created it.
//
// The collision the five copies raced on (documented by the 1.8/1.12/1.13/1.16/1.7 close-outs,
// reproduced live pre-fix): `node --test` runs test FILES concurrently, so several suites'
// guards interleaved on the same bytes — one guard's in-place truncate-rewrite left the file
// momentarily empty under another suite's row-reader (JSON.parse of "" — the "undefined" is not
// valid JSON transient), and one guard's created-file rmSync pulled the file out from under a
// sibling mid-read (ENOENT). Two primitives fix it, both the house's own canonized shapes:
//
//   1. a cross-process mutation lock — the mkdir-lock pattern of withStoreLock (src/rulings.js):
//      mkdir is the atomic acquire on POSIX, a dead holder's directory is detectable by mtime
//      and broken as stale, a live waiter retries with a bounded deadline. Held from snapshot
//      through restore, so no two guarded sections ever interleave. Keyed on the guarded FILE
//      SET (the setup pair shares one lock; calibrate's single file gets its own — unrelated
//      suites never serialize against each other) and placed under the OS tmpdir, so it is
//      machine-global: one `node --test` run's concurrent files AND two suite processes from
//      concurrent sessions on the same host both serialize.
//   2. an atomic temp-and-rename rewrite — the atomicWrite/R10 pattern: the restored bytes land
//      via rename over the final path, so a reader sees the old content or the new one, never a
//      momentary-empty file. This half also covers the writer the lock CANNOT cover: a real
//      operator run takes no test lock, and the rename hides the rewrite from it too.
//
// The constants are tuned to a guarded section's real span — one or two spawned CLI runs,
// seconds: staleMs far above any healthy section (only a crashed holder is broken), waitMs
// generous against the worst live queue (at most one waiting section per sibling file, each a
// spawned-setup span), retry a short sleep. API shape is the landed one —
// `const restore = evidenceGuard(); … finally { restore(); }` — with calibrate's narrowing via
// `names`; the subtraction algorithm is byte-equivalent to the landed copies.
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, rmdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const LOCK_STALE_MS = 60_000;
const LOCK_WAIT_MS = 60_000;
const LOCK_RETRY_MS = 25;

// The lock directory for a guarded file set: under the OS tmpdir (machine-global across suite
// processes and concurrent sessions), keyed by the sorted absolute paths so disjoint file sets
// never contend.
const lockPathFor = (files) =>
  join(tmpdir(), `ug-evidence-guard-${createHash("sha1").update([...files].sort().join("\n")).digest("hex").slice(0, 16)}`);

// The mkdir acquire — withStoreLock's loop, verbatim in shape: EEXIST means a holder; a holder
// whose lock dir mtime is older than staleMs is dead and broken; a live holder is waited out
// with a bounded deadline and one clear error. Atomics.wait is the synchronous sleep the house
// lock uses (main-thread legal in Node).
function acquireLock(lock, { staleMs = LOCK_STALE_MS, waitMs = LOCK_WAIT_MS, retryMs = LOCK_RETRY_MS } = {}) {
  const deadline = Date.now() + waitMs;
  for (;;) {
    try { mkdirSync(lock); return; }  // the acquire: mkdir succeeds exactly once
    catch (err) {
      if (err.code !== "EEXIST") throw err;
      try {
        if (Date.now() - statSync(lock).mtimeMs > staleMs) { rmdirSync(lock); continue; }  // stale holder: break it
      } catch { continue; }  // the lock vanished under us — re-attempt the acquire
      if (Date.now() > deadline) throw new Error(`evidence guard lock is held by another process (${lock}) — retry in a moment`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, retryMs);
    }
  }
}

// R10's shape at test scope: never rewrite the evidence file in place — a crash or a concurrent
// read mid-truncation is exactly the transient this guard exists to make impossible. The temp
// lands in the same directory (rename is atomic within one filesystem), carries the file's own
// mode, and is unlinked if the write fails; the leftover-name check is unique per call.
function replaceAtomically(file, data) {
  const mode = statSync(file).mode & 0o777;
  const tmp = `${file}.guard-${process.pid}-${randomUUID().slice(0, 8)}`;
  try {
    writeFileSync(tmp, data, { mode });
    renameSync(tmp, file);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* nothing to clean up */ }
    throw err;
  }
}

// Run fn() holding an arbitrary lock path — the unit-test surface for the collision pins
// (tiny timers, throwaway paths). Released in a finally even when fn() throws.
export function withEvidenceLock(fn, opts = {}) {
  const { lockPath = lockPathFor([join(REPO, "evidence")]) } = opts;
  acquireLock(lockPath, opts);
  try { return fn(); }
  finally { try { rmdirSync(lockPath); } catch { /* a stale-breaker took it */ } }
}

// The guard. Snapshots the guarded files under the lock and returns the restore; the lock is
// HELD across the caller's whole section (the spawned run and the row-reads between snapshot
// and restore — that span is what must never interleave with a sibling's restore), and the
// restore releases it. Defaults: the repo's evidence dir and the setup/live-verify pair; a
// suite guarding a different file set passes `names` (calibrate's one-file narrowing).
export function evidenceGuard({ dir = join(REPO, "evidence"), names } = {}) {
  const date = new Date().toISOString().slice(0, 10);
  const fileNames = names ?? [`setup-${date}.jsonl`, `live-verify-claude-${date}.jsonl`];
  const files = fileNames.map((n) => join(dir, n));
  const lock = lockPathFor(files);
  acquireLock(lock);
  const before = files.map((f) => (existsSync(f) ? readFileSync(f, "utf8") : null));
  let restored = false;
  return () => {
    if (restored) return;  // idempotent — a double restore neither throws nor releases twice
    restored = true;
    try {
      files.forEach((f, i) => {
        if (!existsSync(f)) return;
        const now = readFileSync(f, "utf8");
        if (before[i] === null) { rmSync(f, { force: true }); return; }  // this run created the file
        if (now === before[i]) return;
        const counts = new Map();
        for (const l of before[i].split("\n")) counts.set(l, (counts.get(l) ?? 0) + 1);
        const kept = now.split("\n").filter((l) => {
          const c = counts.get(l) ?? 0;
          if (c > 0) { counts.set(l, c - 1); return true; }  // a snapshot line (or a duplicate of one): keep
          return false;                                       // appended during the run: subtract
        });
        const out = kept.join("\n");
        if (out !== now) replaceAtomically(f, out);
      });
    } finally { try { rmdirSync(lock); } catch { /* a stale-breaker took it */ } }
  };
}
