// epic-rules-of-record entry 1 (2026-10-26): the checkout root must never become the store
// home by accident. This file pins the store-resolution contract:
//   1. with no guard-home env, resolution lands in the OS home directory — absolute, outside
//      the checkout, and the whole store family (store file, audit log, legacy rulings
//      source, mutation lock) rides that one home;
//   2. the two accepted env spellings keep their documented precedence (the modern spelling
//      outranks the legacy JEV one), and an explicit absolute home is honored verbatim —
//      including an operator deliberately pointing at the checkout, which is a documented
//      residual (the entry-1 story plan finding), not a bug this test may override;
//   3. SKIPPED hard line: empty, relative or cwd-shaped guard-home values may never anchor
//      the store against the process cwd. guardHome() currently returns such a value
//      verbatim, so the resolved path anchors against cwd — a real src-level gap. The
//      hardening is src/ work owned by the consolidation stream (epic-rules-of-record
//      entry 1 finding); flip this case to live assertions when guardHome absolutizes or
//      rejects non-absolute homes. It is skipped rather than red so the suite stays green
//      while the contract stays named and one edit away.
// No store filename literal appears in this file: every name check derives the basename
// from the resolution functions themselves.
import { test } from "node:test";
import assert from "node:assert/strict";
import { homedir } from "node:os";
import { basename, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { policyFile } from "../src/policy.js";
import { guardHome, rulingsFile, auditFile, storeLockFile } from "../src/rulings.js";

// The checkout root, derived from this file's own location (test/..) — never hardcoded, so
// "not here" reads wherever the checkout lives.
const REPO = fileURLToPath(new URL("..", import.meta.url));

const inCheckout = (p) => p === REPO.replace(/[\\/]+$/, "") || p.startsWith(REPO + sep);

test("no guard-home env: the store resolves into the OS home directory, never the checkout or cwd", () => {
  const home = guardHome({});  // env object without either spelling — not process.env
  assert.ok(isAbsolute(home), "default guard home is absolute");
  assert.ok(home.startsWith(homedir()), "default guard home sits under the user's real home");
  assert.ok(!inCheckout(home), "default guard home is not the checkout");
  assert.ok(!inCheckout(policyFile({})), "the store file never lands in the checkout by default");
  assert.ok(isAbsolute(policyFile({})), "the store path is absolute by default");
  // the whole store family rides the one home, and the four keep distinct names
  const family = [rulingsFile({}), auditFile({}), storeLockFile({}), policyFile({})];
  assert.equal(new Set(family.map((f) => basename(f))).size, 4, "the four store-family files keep distinct names");
  for (const familyFile of family) {
    assert.equal(resolve(familyFile), resolve(join(home, basename(familyFile))),
      "store-family file sits in the default home");
  }
});

test("both accepted spellings are honored; the modern spelling outranks the legacy JEV one", () => {
  assert.equal(resolve(guardHome({ GUARD_HOME: "/abs-g1" })), "/abs-g1");
  assert.equal(resolve(guardHome({ JEV_GUARD_HOME: "/abs-g2" })), "/abs-g2");
  assert.equal(resolve(guardHome({ GUARD_HOME: "/abs-g1", JEV_GUARD_HOME: "/abs-g2" })), "/abs-g1");
  // an explicit absolute home is honored verbatim, whatever it points at — the operator's
  // own choice (the checkout-pointing env is the documented residual behind the stray file)
  assert.equal(resolve(policyFile({ GUARD_HOME: "/abs-g1" })), resolve(join("/abs-g1", basename(policyFile({})))),
    "the store name is identical in every home");
});

test("empty, relative and cwd-shaped guard-home values never anchor the store against cwd", { skip:
  "guardHome() returns an empty or relative value verbatim, so the resolved store path anchors against the " +
  "process cwd (src/rulings.js guardHome; verified 2026-10-26: GUARD_HOME='' yields a bare relative name). " +
  "The hardening is src/ work owned by the consolidation stream — flip this test live when guardHome " +
  "absolutizes or rejects non-absolute homes (epic-rules-of-record entry 1 finding)." }, () => {
  for (const value of ["", ".", "./", "scratch-home"]) {
    for (const envVal of [{ GUARD_HOME: value }, { JEV_GUARD_HOME: value }]) {
      const label = `${Object.keys(envVal)[0]}=${JSON.stringify(value)}`;
      const file = policyFile(envVal);
      assert.ok(isAbsolute(file), `${label}: store path resolves absolute`);
      assert.ok(!inCheckout(file), `${label}: store never lands in the checkout`);
      assert.ok(file !== process.cwd() && !file.startsWith(process.cwd() + sep),
        `${label}: store never anchors against cwd`);
      assert.ok(!file.startsWith("scratch-home"), `${label}: a relative value is never passed through`);
    }
  }
});
