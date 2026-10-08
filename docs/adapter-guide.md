# The adapter-author guide

How to bring Unjangled Guardrails to a harness it does not yet support, by writing an
adapter — and only an adapter. This is the stranger's contribution path: a bounded task
with no core changes, defined by `src/contract.js`, proven by the conformance suite and
live verification, and enforced at import time.

Read alongside:

- `src/contract.js` — the contract module, the only surface you may import
- `test/contract.test.js` — the import lint that enforces that boundary
- `docs/harness-matrix.md` — how each existing harness composes, dialect by dialect
- the architecture spine (AD-1, the seam; AD-2, verdict taxonomy — internal planning
  artifact, may not ship in every tree; every rule you need from it is restated in this
  guide, cited as AD-1/AD-2 where it bites)

## 1. What an adapter is

An adapter is a thin translation layer between one harness's native surface and the
Adapter Contract. It does two things and nothing else:

1. **In:** when the harness is about to run a tool call, translate that call (plus
   whatever conversation context the harness exposes) into a contract payload and hand
   it to the core.
2. **Out:** take the contract decision back and express it through the harness's own
   blocking, prompting, and message mechanisms.

Everything else — the semantic brain, the operator rulings store, the orchestrator, the
deterministic floor — lives in the core. One install is the whole plugin; your adapter
carries no logic of its own. If you find yourself writing policy in the adapter, you are
building the wrong thing: the verdict was already decided, and it arrived as data.

**The seam is enforced, not aspirational.** Architecture decision AD-1 says adapters may
call the core *only* through the versioned contract in `src/contract.js`; the core
exports nothing else to adapter code. The import lint in `test/contract.test.js`
(`ADAPTER_ALLOWLIST`, `lintImports`) reads every adapter file and fails any import that
lands in `src/` outside the documented allowlist. Today's adapters sit on a shrinking
allowlist of legacy imports — entry 3 of the epic shrinks it to contract-only — but a
**new** adapter has no such grace: import `src/contract.js` and nothing else. If a new
adapter needed anything deeper, that would be a contract gap, and contract gaps are fixed
in `src/contract.js` (as additive, MINOR bumps), never worked around in adapter code.

## 2. The contract surface

Everything below is defined in `src/contract.js` at `CONTRACT_VERSION` `1.0.0`. The
exports are: `CONTRACT_VERSION`, `VERDICTS`, `assess`, `buildConversationContext`,
`scan`, `askBlocked`, `isDecision`, `isScanResult`.

### Payload in

`assess(payload, opts)` judges a tool call. The payload (`AssessPayload`) carries:

- **`call`** (`ToolCall`) — `{ tool, input, cwd?, agent?, sessionId? }`. `tool` is the
  name as your harness spells it (the core lowercases on entry); `input` is the
  harness-native input shape, passed through opaquely. Do not normalize policy-relevant
  detail away — ruling globs and the brain judge the call, not a wrapper you invented.
- **`context`** — either an already-built `ConversationContext` (the four fields below)
  or a `ConversationContextSpec` for `buildConversationContext` to build:
  `{ sessionId?, transcriptPath?, intent?, messages? }`. `messages` entries are
  `{ role: "user" | "assistant", text }` extracted from your harness's session — this is
  how pi, OpenCode, and the ACP proxy carry the operator's words. The built context has:
  - `user_recent_messages` — recent operator messages (deduped, tail-clipped)
  - `assistant_intent` — the agent's stated intent for the turn
  - `recent_tool_calls` — the last few calls and their verdicts
  - `flagged_untrusted_content` — provenance refs for content flagged untrusted earlier
    in the session (kind, source, probability, excerpt)

  **Context carriage is load-bearing.** The brain needs the operator's own words to
  honor them; a conformance case drops context and *must fail* — an adapter that loses
  context is broken by design (AD-1). If your harness exposes a session or transcript,
  wire it in.
- **`provenance`** (`Provenance`, optional) — `{ fromUntrustedContent?, refs? }`.
  **Reserved in 1.0:** the core derives provenance itself from session flags; a
  populated field here is accepted and carried in `detail`, not yet consulted.

### Decision out

`assess` resolves to a `Decision` — or `null`. A `Decision` carries:

- `verdict` — exactly one of `VERDICTS`: `"deny"`, `"ask"`, `"allow"` (AD-2). Frozen
  enum; never reinterpret it.
- `category` — the reason category (e.g. `"Dangerous Action"`, `"Injected
  Instruction"`, `"Credential Exposure"`, `"Gate Self-Protection"`, `"Approval Needed"`)
- `stats` — human-readable classifier stats line
- `ruling` — the operator ruling citation that shaped this decision, or `null`
- `guidance` — the agent-guidance sentence(s) alone (for hosts that render them
  separately); `""` when none
- `message` — the full rendered ruling (header + guidance), for whatever your harness
  surfaces to the model
- `detail` — the full underlying assessment; additive, ignore unknown fields

`null` is **not** an allow. `assess` returns `null` when the core skips the call
(read-shaped tools below the gate, skip-listed tools); null means "no verdict, the
harness default applies". The fail-safe direction is always toward deny (AD-2).

### Scan result out

`scan({ text, tool?, source?, task? }, opts)` scans post-tool content — text the model
is about to read — before it reads it. It resolves to a `ScanResult` (`flagged`, `kind`,
`probability`, `confidence?`, `message`, `detail`) or `null` when the core skips the
scan (never-scanned tools, skip list, below minimum length). Null is "no scan ran",
never "clean".

### Shape guards

`isDecision(d)` and `isScanResult(r)` verify every promised field is present and typed.
Use them in your adapter's own tests; the conformance suite uses them on you.

### Version compatibility

`CONTRACT_VERSION` is SemVer over the contract surface:

- **PATCH** — wording/docs only. No action needed.
- **MINOR** — additive: a new optional payload field, a new decision or scan-result
  field, a new exported helper. Two obligations bind you: **ignore fields you don't
  know**, and **never require a field you didn't declare at your own version**. A MINOR
  mismatch is logged, not fatal.
- **MAJOR** — a field removed or renamed, a type changed, the verdict enum changed, or
  fail-safe semantics changed. An adapter records the version it was written against and
  **refuses to run** against a different MAJOR.

Write the version you target into your adapter and check it at startup; that check is
part of what the conformance suite looks for.

## 3. Build steps

### Step 1 — implement the translation

Find your harness's pre-tool-call and post-tool-result events and write two mappings:

**Inbound — harness event → payload.** Extract the tool name, the native input, and
whatever context the harness exposes (session messages, transcript, intent). Call
`assess({ call, context }, opts)` — or pre-build with `buildConversationContext` if your
harness's session shape needs bespoke extraction. Existing examples of every shape live
in the adapters: `src/hook.js` (JSON-stdin hooks), `src/opencode.js` (plugin API),
`extensions/unjangled-guardrails.ts` (pi extension), `src/acp.js` (the ACP proxy).
`docs/harness-matrix.md` documents each harness's dialect quirks — read the row nearest
yours before inventing a mapping.

**Outbound — decision → your harness's native mechanism.** Every harness can block a
call somehow (throw an error, return a block action, refuse in a permission callback);
the matrix's Deny row shows what each existing adapter uses. Map verdicts like this:

| Contract verdict / result | Host has a prompt surface | Host has none |
|---|---|---|
| `allow` | proceed | proceed |
| `ask` | your harness's native prompt; the user decides | **deny** via `askBlocked(decision)` |
| `deny` | block (native deny mechanism) | block |
| `assess` → `null` | no verdict; harness default applies | same — null is never allow |
| Decision with `category` `"Credential Exposure"` | **deny, unconditionally** — a leak deny is a deny everywhere; never route it through a prompt, a ruling lift, or any adapter-side softening | **deny** |
| `scan` → `null` | no scan ran; proceed | same — null is never clean |
| `scan` → flagged (`kind` `injection` / `canary` / `unknown`) | surface `message` to the model per your harness's mechanism (annotation, system note) | deny where your harness cannot attach context |
| anything unknown / undefined shape | resolve toward the safe side (deny) | deny |

The fixed rows are fail-safe semantics (AD-2), not preferences: **ask maps to deny where
no prompt surface exists** (`askBlocked` returns a deny carrying the ask-blocked
guidance — the decision routes through the user in conversation instead), and
**context-leak verdicts are denies everywhere**. Never weaken either mapping in adapter
code; the conformance suite drives the ask-blocked case explicitly and an adapter that
proceeds on a host with no prompt fails it.

Two error-handling rules from the existing adapters, both load-bearing:

- **Brain-down is not adapter business.** The core falls back to its deterministic
  floor (AD-6) and still returns an ordinary `Decision`; your adapter needs no special
  case. What your harness *can* configure is fail-closed vs fail-open for a thrown
  transport error — that posture lives in core configuration (`GUARD_FALLBACK`),
  not in adapter logic.
- **Surface the message, don't rewrite it.** The message catalog (`docs/messages.md`)
  is the contract's voice. Prefix it with your harness's toast/notification mechanism
  if you like (the existing adapters do), but the text the model sees must be the
  decision's `message`/`guidance` as issued.

### Step 2 — pass the conformance suite

`tools/conformance/` (landing now — entry 2 of epic-adapter-seam) is the simulated-
harness suite: a scripted stand-in harness driving **every** adapter through the full
contract case set — every verdict class, context carriage (the context-drop variant must
fail), citation carriage, guidance carriage, and the ask-blocked fail-safe mapping —
with a deterministic simulated brain and zero classifier calls. **Its exact interface is
still settling; write your adapter to the contract, then run the suite and follow its
case failures.** Passing it is the mechanical compatibility proof (AD-1): it is the
reason your adapter can be written against this document alone, without a shared brain
or network access.

For your own unit tests, copy the pattern in `test/contract.test.js`: a mock brain via
`fetchImpl`, the `opts` helper, and `isDecision`/`isScanResult` on everything your
adapter produces. Tests are `node:test`; adapters are plain ESM — zero-build, no
bundling step (see the spine's Conventions).

### Step 3 — live-verify

The conformance suite proves the contract; live verification proves the harness. The
verify command (landing now — entry 4) is `unjangled-guardrails verify <harness>`: it
drives the **real** harness with a safe call (must pass) and a known deny (must stop),
and records a per-harness evidence artifact. Like the conformance runner, its exact
interface is still settling; the two-case shape — safe passes, known deny stops — is
what it proves and what your adapter must make true. Run it on your harness and keep the
evidence artifact with your contribution: no claim without its artifact is a repo rule.

### Step 4 — register

Two registrations make an adapter official:

1. **The import lint's adapter list.** Add your adapter file to `ADAPTER_ALLOWLIST` /
   `ADAPTER_FILES` in `test/contract.test.js` (contract-only — your entry's allowlist
   is empty) so the lint covers it from day one and stays covering it.
2. **The fleet manifest.** The operator-maintained manifest (`docs/fleet-manifest.md`,
   named by the spine's Conventions and CAP-4) records every gated, live-verified
   harness. Add your harness there with its live-verify evidence — that is what turns
   "it works on my machine" into fleet coverage.

## 4. What you may never do

- **Reach past the contract.** No import from `src/guard.js`, `src/orchestrate.js`,
  `src/session.js`, `src/context.js`, or anything else in the core (AD-1). The import
  lint fails the build on it; that is the point. If the contract can't express what you
  need, propose the additive change to `src/contract.js` instead.
- **Weaken the fail-safe mapping.** No adapter proceeds on an ask where the host has no
  prompt surface; no adapter passes a context-leak verdict through; no adapter resolves
  an unknown shape toward allow (AD-2). The mapping table in step 1 is fixed.
- **Name an agent-executable unlock.** Deny messages name exactly three overrule paths
  (CAP-6, AD-3): operator rulings, operator terminal sessions, and the operator's own
  words recognized at the 0.85-certainty bar. Never add a fourth — no "run this command
  to bypass", no env-var recipe addressed to the agent. Authority is operator-only by
  construction; your message text must not offer the agent a key.
- **Phone home.** The gate originates no remote traffic except the operator-chosen
  brain endpoint: no telemetry, no update checks, no corpus sync, ever (AD-4). An
  adapter that adds a beacon is not a contribution; it is a vulnerability.
- **Invent verdict semantics per dialect.** `VERDICTS` is three strings and a frozen
  enum. The matrix's dialect quirks are about *mechanisms* (throw vs block action vs
  permission callback), never about *meaning*.

## 5. Worked sketch — a hypothetical new adapter end-to-end

Suppose the harness is **exampleterm**: a terminal agent exposing a `preToolCall` hook
(receives `{ tool, args, sessionId }`, blocks by throwing) and a `toolResult` event
(receives `{ tool, sessionId, text }`), plus a session API returning recent messages.

**One new file, `adapters/exampleterm.js`** (plain ESM, zero-build):

```js
// Exampleterm adapter — contract-only (AD-1). Imports src/contract.js and nothing else.
import { CONTRACT_VERSION, assess, scan, askBlocked, isDecision } from "../src/contract.js";

const TARGET = "1.0.0";
const [tmaj, tmin] = TARGET.split(".");
const [cmaj, cmin] = CONTRACT_VERSION.split(".");
if (tmaj !== cmaj) throw new Error(
  `unjangled-guardrails: contract MAJOR ${CONTRACT_VERSION} != adapter target ${TARGET}; refusing to run`);
if (tmin !== cmin) console.error(`unjangled-guardrails: contract MINOR ${CONTRACT_VERSION}; adapter targets ${TARGET}`);

// harness event → payload → decision → native mechanism
export async function onPreToolCall(evt) {
  const messages = (await exampletermSession(evt.sessionId))          // harness API, no core import
    .map((m) => ({ role: m.role, text: m.text }))
    .filter((m) => m.role === "user" || m.role === "assistant");
  const decision = await assess({
    call: { tool: evt.tool, input: evt.args, sessionId: evt.sessionId },
    context: { sessionId: evt.sessionId, messages },
  });
  if (decision === null) return;                     // no verdict — harness default applies
  if (!isDecision(decision)) throw new Error("unjangled-guardrails: non-contract decision; refusing"); // fail-safe (AD-2)
  if (decision.verdict === "deny") {
    // Covers "Credential Exposure" too: a leak deny denies everywhere — never softened, never lifted here.
    throw new Error(decision.message);
  }
  if (decision.verdict === "ask") {
    // exampleterm has no prompt surface: ask → deny (askBlocked), per AD-2. If a later
    // version grows a prompt API, call it here instead — but only for ask.
    throw new Error(askBlocked(decision).message);
  }
  // allow: proceed
}

export async function onToolResult(evt) {
  const r = await scan({ text: evt.text, tool: evt.tool });
  if (r === null) return;                            // no scan ran — never treat as clean
  if (r.flagged) exampletermAnnotate(evt, r.message); // kind is injection/canary/unknown; surface the message
}
```

**Two notes on what the sketch deliberately omits.** No policy: every judgment above is
a verdict that arrived from the core. No `remember()` of past calls: today's adapters
feed the session store (`src/session.js`) so the *next* call's context is richer — but
that module is outside the contract, and the lint will refuse the import; the contract
path is exactly what the sketch does, supplying `messages` through the
`ConversationContextSpec`, with session-store carriage evolving as an additive MINOR.

**Then, in order:** add `adapters/exampleterm.js` to the import-lint list in
`test/contract.test.js` (empty allowlist — it must lint clean on contract-only imports);
write unit tests on the mock-brain pattern from `test/contract.test.js`; pass
`tools/conformance/`; run `unjangled-guardrails verify exampleterm` (once entry 4
lands) and keep the evidence artifact; add exampleterm to `docs/fleet-manifest.md`.
Total surface: one file, two mappings, no core changes — the FR-B3 promise made
procedural.

---

*The contract is the interface and the lint is the fence. Everything you need lives in
`src/contract.js`; everything you must not do fails a test before it ships.*
