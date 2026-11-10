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

Everything below is defined in `src/contract.js` at `CONTRACT_VERSION` `1.5.0`. The
1.0 core exports are: `CONTRACT_VERSION`, `VERDICTS`, `assess`,
`buildConversationContext`, `scan`, `askBlocked`, `isDecision`, `isScanResult`; 1.1
added the adapter-support helpers (pass-throughs over session/skill plumbing — see the
module's adapter-support section); 1.2 added `capturePromptRuling` (§7); 1.3 added
`expirePromptSession` (§8); 1.4 added `promptCaptureTier` (§7, the ask-surface
tier read); 1.5 added `recordHarnessStore` (§9, the harness store registry).

### Payload in

`assess(payload, opts)` judges a tool call. The payload (`AssessPayload`) carries:

- **`call`** (`ToolCall`) — `{ tool, input, cwd?, agent?, sessionId? }`. `tool` is the
  name as your harness spells it (the core lowercases on entry); `input` is the
  harness-native input shape, passed through opaquely. Do not normalize policy-relevant
  detail away — ruling globs and the brain judge the call, not a wrapper you invented.
  `cwd` is the harness-exposed working directory as the **fallback**: for bash/terminal-
  shaped calls the core derives the call's own working folder from the input's workdir-
  style field (`cwd`/`workdir`/`working_dir`/`directory`, in that precedence) when it
  carries one, so project scope matches where the call runs — pass your harness's session
  cwd, and do not strip those input fields (CAP-6).
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

Ask-user tools are the one classified lane: `scan` resolves `null` for the ask-user
family (Hermes `clarify`, Claude Code `AskUserQuestion`, pi `ask_user_question` —
`ASK_USER_RESULT_TOOLS` in the core) because the result is the operator's own typed
answer, user words rather than untrusted output — the identical text from any other
tool keeps the full scan. Record the answer so it reaches the user-words lane: call
`sessionRememberUserAnswer(sessionId, tool, resultText)` from your post-tool surface
(no-op for every other tool) and the session's context mining carries it into
`user_recent_messages` from then on.

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

## 6. OpenCode v2: the isolated-HOME procedure (host isolation)

OpenCode 2.x is a different loader generation. It accepts only a default-exported
`{ id, setup }` definition — the adapter `install opencode --v2` writes — and rejects a
named re-export with `SchemaError(Missing key at ["default"])`. The 1.x loader is the
mirror image: it treats every export as a plugin function and throws on object exports.
One HOME therefore belongs to exactly one generation, and everything in this section
exists to keep an evaluation of v2 from colliding with the HOME a live 1.x service owns.

### The guard behavior

Before writing, `install opencode` fingerprints any existing adapter in either scanned
plugin dir (`~/.config/opencode/plugins/` and `~/.opencode/plugins/`) by its export
shape — the shape IS the generation fingerprint, and detection only reads. A HOME that
already holds the other generation's adapter, or an adapter matching neither shape, refuses the
install until the operator overrides:

    Unjangled Guardrails: install opencode: refusing to write the v2 adapter — the target HOME already holds:
      <HOME>/.config/opencode/plugins/unjangled-guardrails.js (v1 adapter)
    Mixing generations is the silent mismatch the loading probe proved harmful: ...

The refusal writes nothing and exits 1. Re-running with `--force` writes the requested
generation anyway, and the warning prints on the forced run either way. A
matching-generation install behaves exactly as before: silent, byte-identical rewrite.

### The isolated-HOME command line

To run v2 without touching the HOME the live 1.x service owns, boot it under a
bind-mounted shadow HOME (bubblewrap), pointed at a throwaway copy of the committed
fixture (`test/fixtures/opencode-v2-home/` — copy it first; the committed tree is
copy-only). Command shapes, with placeholders:

    # 0. names
    V2BIN=<path-to-opencode-v2>            # wherever the v2 binary is parked
    CHECKOUT=<your-checkout>               # this repository
    W=/tmp/guard-v2                        # the throwaway tree

    # 1. copy the binary OUT of the home tree (its real path dies under the shadow),
    #    and seed the throwaway HOME from the committed fixture
    mkdir -p "$W/bin" && cp "$V2BIN" "$W/bin/opencode-v2"
    cp -a "$CHECKOUT/test/fixtures/opencode-v2-home" "$W/home"

    # 2. install the v2 adapter into the COPY, inside the namespace, with the checkout
    #    read-bound where the adapter will import it from (the adapter bakes its import
    #    path at write time)
    bwrap --dev-bind / / \
      --ro-bind "$CHECKOUT" "$W/repo" \
      --bind "$W/home" "$HOME" \
      --chdir "$HOME" \
      node "$W/repo/src/cli.js" install opencode --v2 --home "$HOME"

    # 3. boot v2 in the same shadow
    env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/local/bin TERM=dumb \
      timeout 60 bwrap --dev-bind / / \
      --ro-bind "$CHECKOUT" "$W/repo" \
      --bind "$W/home" "$HOME" \
      --chdir "$HOME" \
      "$W/bin/opencode-v2" run --standalone \
      --model opencode/ling-3.1-flash-free "Reply with the single word ok and nothing else."

The load-bearing parts — none optional:

- **`--standalone` is mandatory.** Without it, `run` needs the host-wide managed service
  port, which a live 1.x service already holds; a non-standalone run can reach live host
  state. Standalone keeps the service in-process inside the namespace.
- **The bind shadow scopes its guarantee to the filesystem.** Every path the child
  resolves under the HOME tree lands in the copy, whatever `$HOME`/`XDG_*` say. The
  network is NOT isolated — loopback stays reachable — which is exactly why the
  `--standalone` mandate exists.
- **Copy the binary out of the home tree first**; under the shadow its original path no
  longer resolves to the binary, and nothing should write near the parked original.
- **Install inside the namespace**, with the checkout ro-bound at the path the adapter will
  import from. The same shadow then serves the boot.
- **The `env -i` scrub** keeps provider keys and session environment out of the run (a
  recorded flake class). **`timeout 60`** leashes the boot; on a spawn hang (leash
  expiry with no setup evidence) retry ONCE at 90s — a second hang is a finding, not a
  flake.
- **Model failures after boot are expected and irrelevant**: plugin evaluation and
  setup happen before any model call, so the load observation completes regardless of
  the run's exit code.
- **Prove the isolation, don't assume it.** The committed harness runs this procedure
  on demand — containment plus the ownership guard, with the real HOME's integrity
  asserted inside the test (watermark, directory mtimes, a read-only zero-session query
  against the live 1.x store when one exists):

      GUARD_TEST_OPENCODE_V2="$V2BIN" node --test test/isolation.test.js

  Missing prerequisites (no bwrap, no timeout(1), no binary wired) record clean skips, not failures.

### Coexistence guidance

- **One HOME, one generation, always.** Mixing is the silent mismatch the loading probe
  proved harmful: a 1.x host given a v2 adapter SchemaErrors on every boot; a v2 host given
  a 1.x adapter silently loses the gate.
- **The ownership guard is the tripwire, not the strategy.** On a machine with a live
  1.x service, give v2 its own shadow HOME (the procedure above) and leave the live
  profile alone. The v2 adapter also positively signals entry at setup ("v2 adapter
  active") and reports sibling 1.x-shaped adapters it finds in the scanned plugin dirs, so
  a mixed host announces itself in-band.
- **`install opencode --v2 --force` is the deliberate reconciliation** of a HOME the
  operator owns — the warning prints either way, and the other generation's loader
  misbehaves until the takeover is actually finished on both sides.

## 7. Prompt capture (1.2.0): turning an answered ask into a ruling

When your harness owns the ask prompt and a human resolves it, the choice can become a
gate ruling in-process — the copy-paste `ruling add` hint from the ask message, minus
the copy-paste. `capturePromptRuling` is the ONLY constructor of
`prompt:<harness>` provenance: no env var or CLI argv can mint it, and
`GUARD_OPERATOR_CLI` escape grants still record `env-escape`, never `prompt:*`.

```js
import { capturePromptRuling } from "../src/contract.js";  // contract-only, like everything else

const cap = capturePromptRuling(
  { choice, harness: "yourharness", sessionId, tool, input, cwd },
  { env });
// choice: "once" | "session" | "always" — the option the human picked on your prompt
```

**Call it only with a choice a human made on your prompt.** A forged answer mints
standing allows; the per-session cap, the off-by-default tier, dedupe, and the audit
row are the survivability story, not permission. The knobs and semantics:

- `GUARD_PROMPT_RULINGS` — `off` (the **default**) | `session` | `project`. Tier off:
  the export is a no-op that consumes the choice as allow-once — nothing persists
  (operator ruling 2026-11-06). Tier `session`: session and always choices mint
  `session:<sessionId>` expiring in 24h. Tier `project`: a session choice still mints
  session scope; an always choice mints `project:<cwd>` (the operator opt-in).
- `GUARD_PROMPT_RULINGS_CAP` (default 20) — the per-session write cap, the
  forged-response bounder. Repeat grants of an entry that already exists dedupe
  (`existed: true`) without a write and never count against it.
- Patterns are derived inside the core from the asked `tool`/`input`, under the
  capture surface's own constraints (explicit bash command, at most 3 segments, no
  glob or quote characters in a segment): hand in the call, not a pattern. The
  copy-paste hint generalizes its patterns (CAP-7); the captured mint deliberately
  stays exact — the human approved this one call. Where the constraints refuse,
  capture declines.
- Allow-effect only, never global scope, never deny-effect; the scope is built from
  the payload's `sessionId`/`cwd`, never from a caller-supplied scope string.

Two outcomes both mean "proceed with this one call":

- `{ captured: false, outcome: "once", reason }` — declined (tier off, choice `once`,
  pattern constraints, the cap, a missing session/cwd). Nothing was written.
- a throw — a store failure (corrupt or locked). Nothing was written; catch it and
  proceed. **A capture failure never changes the ask outcome** — an allow-once stays
  once.

`{ captured: true, existed, ruling }` means the ruling is in the store and the next
covered call lifts through the ordinary ruling consult — nothing else for the adapter
to do. The ruling carries `via: "prompt:<harness>"` so `rulings list` and the audit
file distinguish prompt-captured entries from operator-terminal ones.

One lifetime edge: a repeat capture whose matching prompt entry has **expired**
supersedes — the dead entry is removed and the fresh capture mints with a new 24h
clock (`existed: false`). A supersede is a write, so the per-session cap applies to
it; a repeat of a still-live entry keeps the story-1 dedupe (`existed: true`, no
write, cap bypassed). An expired **operator**-minted match keeps the inherited dedupe
(capture never removes operator entries) — the recorded residual.

### The ask surface wiring: pi (1.4.0)

The first surface that feeds the capture path is the pi extension
(`extensions/unjangled-guardrails.ts`). Its rules are the template for any surface
that owns its own ask dialog:

- **Choose the dialog by tier, read the tier through the contract.**
  `promptCaptureTier(env)` returns `"off" | "session" | "project"` — the SAME parse
  the mint honors (an adapter-side copy could drift: a four-option ask on a tier the
  core reads as off would promise what the capture would decline). Tier off (the
  default): the binary confirm, byte-identical to the pre-capture ask. Tier on and
  the host has a UI: `ctx.ui.select(title, options)` with exactly **Allow once /
  Allow for this session / Allow always / Reject**.
- **The label is the whole contract.** `Allow once` → choice `once` (nothing
  persists); `Allow for this session` → `session`; `Allow always` → `always`. The
  core is the ceiling — under the session tier an `always` choice still mints
  session scope with the 24h expiry; under the project tier it mints `project:<cwd>`.
  `Reject`, a dialog cancel, and any label outside the three allows keep the
  pre-capture reject outcome unchanged.
- **One session id across mint, consult, and cleanup.** pi's session identity is
  `ctx.sessionManager.getSessionId()`; the capture mint, the assess payload's ruling
  consult, and the story-2 `session_shutdown` cleanup all key on it, so a minted
  grant both lifts the next call and dies at session end.
- **Capture failure never changes the ask outcome.** A declined capture (tier off,
  pattern constraints, the cap) or a thrown one (corrupt store) leaves the
  allow-once standing; the surface surfaces nothing (§7's rule above).
- **Headless never prompts.** The fail-closed ask-blocks block fires before any
  dialog regardless of tier (harness-matrix pi row). Deny verdicts never reach the
  ask at all.

### The ask surface wiring: ACP (the gate-owned options array)

The second surface that feeds the capture path is the ACP proxy (`src/acp.js`).
Where pi owns a dialog, the proxy owns the **options array** of its
`session/request_permission` request — the client (Zed, JetBrains, Paseo) renders
whatever options the gate sends, so the gate grows the array itself:

- **Read the tier through the contract, per ask.** `promptCaptureTier(env)` (the
  proxy's own env) decides the shape. Tier off (the default): the byte-identical
  two-option array (`Allow once` / `Reject`) — same optionIds, names, kinds, order.
  Tier `session`: the session option is inserted between them. Tier `project`:
  the always option is appended before Reject. Both new options are ACP v1 kind
  `allow_always` — the spec says agents state remembered-decision scope **in the
  option name** ("Allow for this session"), duplicate kinds are legal, and
  `optionId` is an unconstrained opaque string the proxy itself maps back.
- **A closed optionId→choice map.** `allow`→`once`, `session`→`session`,
  `always`→`always`, consulted with `Object.hasOwn` so a forged prototype-key
  optionId (`constructor`) reads undefined, never an inherited truthy value.
  Reject, `cancelled`, and every unknown/forged optionId keep the reject-once
  outcome unchanged — an option the gate never offered can neither proceed nor
  mint.
- **The forged-response story is the core's, not the surface's.** The ACP agent
  child can fake client responses on its own stdout (the spec's stated threat:
  today that lifts one call). The surface maps any answered `session`/`always`
  exactly as a human answer; the bounds live in the core — off-by-default tier,
  the per-session write cap (`GUARD_PROMPT_RULINGS_CAP`), dedupe, the audit row,
  the 24h session expiry, and the story-2 session-end cleanup. A forged `always`
  under tier `session` still mints only session scope (the tier is the ceiling).
- **One session id across mint, consult, and cleanup** — the ACP session id: the
  capture mint keys on it, the assess payload's `call.sessionId` carries it (the
  consult-side half, the same fix pi landed — without it a minted session grant
  can never lift), and `session/cancel` expires by it.
- **No client-side persistence.** Memory ownership stays the agent side, i.e. the
  gate store — the proxy never echoes options back, caches answers, or re-sends
  a prior choice.
- **Capture failure never changes the ask outcome.** A declined capture (tier,
  pattern constraints, the cap) or a thrown one (corrupt store) leaves the
  allow-once standing, surfaced nothing (§7's rule, §8's cancel coarseness
  unchanged).

## 8. Session lifetime (1.3.0): expiring grants when the session ends

Prompt-captured session grants die two ways (operator ruling 2026-11-06): at the
24h mint-time cap (the backstop, §7 — it holds for every path that never announces)
and when the harness announces the session ended. The second half is
`expirePromptSession`:

```js
import { expirePromptSession } from "../src/contract.js";

expirePromptSession(sessionId, env, { harness: "yourharness" });  // → { removed: n }
```

It removes ONLY that session's prompt-captured (`prompt:*`) session-scope **allow**
entries — operator-minted 7d session rulings, project-scope captures, deny entries,
and every other session are never touched. It never mints anything, so it runs
un-gated on operator authority (the answered-prompt channel's mirror: cleanup needs
no proof of presence); the audit row (`op: "expire-prompt-session"`) names the
announcing channel as `via: "session-end:<harness>"`. A cleanup that removes nothing
writes nothing — repeated end signals are safe to forward blindly. A corrupt or
locked store **throws**: catch it, warn on your own surface, keep going — the grants
then die by the 24h cap, fail-safe. An ephemeral session (no id) is your skip.

The three wirings this shipped with (each in the adapter's own file):

- **Claude Code** (`src/hook.js`): the `SessionEnd` hook event. If a session id is
  extractable (`session_id`/`conversation_id`/`sessionId`), the cleanup runs and the
  hook answers `null` (Claude Code discards SessionEnd output); a cleanup failure
  warns on stderr and still answers `null` — the hook never crashes.
- **pi** (`extensions/unjangled-guardrails.ts`): the `session_shutdown` event. Reasons
  `quit`/`new`/`resume`/`fork` end the session runtime — cleanup fires. Reason
  `reload` is the one reason the SAME session continues (fresh extension instances):
  skipped, so a `/reload` never kills a live session's grants. Failures surface as a
  UI notify warning, never a throw.
- **ACP** (`src/acp.js`): `session/cancel` — the one session-end-ish signal the proxy
  sees in v1. Two duties: every pending `session/request_permission` for that session
  resolves `cancelled` (the spec's answer-pending duty; the ask path treats it as
  reject-once), and the store-side cleanup runs. The cancel still forwards to the
  agent untouched. A client that cancels mid-session loses that session's prompt
  grants — extra asks later, never extra allows (accepted ACP v1 coarseness).

## 9. Store visibility (1.5.0): recording where your harness's policy lives

A harness that sets `GUARD_HOME` in the gate's spawn env (the Hermes adapter must —
it is the fork root the plugin spawns `node $GUARD_HOME/src/cli.js hook` from) makes
the gate resolve a different `user-policy.json` than an operator terminal without it.
That split used to be invisible from every side. The registry half of the fix is an
adapter duty:

```js
import { recordHarnessStore } from "../src/contract.js";  // contract-only, like everything else

recordHarnessStore("yourharness", env);  // ONCE, at your process entry
```

- Call it once from the process entry that serves the harness — never per tool call,
  never from library code. The registry (`<default guard home>/harness-stores.json`,
  anchored at the DEFAULT home so every terminal finds it regardless of its own
  `GUARD_HOME`) records `{ home, spell, at }` per harness name.
- It never throws and returns `false` when it did not record — an env without
  `PATH`/`HOME` (a probe, not a deployment) or a store root under the OS tmpdir (a
  scratch fixture) records nothing. Call it bare; ignore the result.
- The reward, on the operator side: `policy where` prints your harness's store
  (divergences marked), and every `policy`/`ruling`/`lane` command in a terminal
  resolving a different store warns by name.

Wired today: the hook's `main` (claude/codex/copilot/gemini/cursor/hermes — agent as
detected or `--agent`), the ACP proxy (`"acp"`), and both opencode plugin entries
(`"opencode"`). The pi extension's in-process entry does not record yet — a registered
pi install shows in `policy where` as "no runtime record" until it does.

## 10. The sub-agent context relay (1.7.0): the operator's words ride the child's judgment

A sub-agent's tool calls are judged with the operator's overall directive and goal
present (CAP-4, epic-github-field-reports entry 3 / GitHub issue 3 — operator ruling
2026-11-09 and its same-day refinement). The repro: `delegate_task` children held on
routine asks and could only stop, because the operator's approval lived in the parent
session's user-words lane and nothing relayed it to the child's judgment.

**What to do:** when your harness exposes a sub-agent's parent session natively, pass it
as `parentSessionId` in the `ConversationContextSpec`:

```ts
import { assess } from "../src/contract.js";  // contract-only, like everything else

const context = {
  sessionId: childSessionId,
  ...(parentLinkFromYourHarness ? { parentSessionId: parentLinkFromYourHarness } : {}),
  messages: messagesFrom(branch),
};
```

Wired today: the pi extension reads `PI_SUBAGENT_ORCHESTRATOR_SESSION_ID` from the
child process env (pi-subagents sets it on every spawned child; ambient extensions load
in children by default, so the guard rides). Claude Code `Task` children share the
parent's `session_id`, so the store is already shared — no field needed. Hermes
`delegate_task` children expose no parent link to the gate; per the ruling Hermes keeps
the policy mitigation (the opt-in `examples/user-policy.git-work.json` from ticket 1.13)
and the gate adds no machinery for it. OpenCode and ACP expose no parent link today —
the field is there when a live harness name lands.

**What rides:** only the parent's `prompts` bucket — operator-authored words (harness
prompt events and ask-user tool results, the 1.6.0 lane). The join is read-only and
live at every consult: nothing is written to the child's store, so an approval the
operator types in the parent chat mid-delegation reaches the child's next consult
without any orchestrator action. The parent's `flags`, `calls`, and `intents` never
ride — a parent-session injection flag must not surface in the child's untrusted
evidence, and the parent's agent words are not operator words.

**What it never does:** mint. The relay creates no ruling, no policy entry, and no
verdict rule — `decide()` is untouched and the brain's `user_requested` judgment stays
the only lifter. Words that do not name the call lift nothing (the ask stands), and
every deny floor is blind to words of any provenance. The relay channel is unforgeable
in the gate's trust model: the prompts bucket is written only by harness prompt events
and the ask-user tool family (tool identity), never by an agent surface or tool output —
so no agent can plant words into the lane the relay reads. Named residual: the
orchestrator controls which session id it names as parent, so it can point a child at
another session's genuine operator words (a directive given for different work); the
brain's `user_requested` criteria ("an earlier directive counts only for calls that are
ordinary, necessary steps of exactly what was asked") bound that cross-task lift — the
same accepted family as the orchestrator-authored task text the doctrine already
blesses as the Paseo relay model.

**Ask routing is not this.** Where the harness has native permission routing (Paseo:
a child's ask reaches the orchestrator's conversation, where the operator sits), that
is the route — the gate builds no second grant channel. The relay is the context half:
it makes the judgment informed; routing makes the ask answered. Where neither exists,
the operator's standing policy is the answer (the Hermes ruling). The spawn-tool family
(`isSubagentSpawnTool`: `delegate_task`, `task`, `agent`, `subagent` — the observed
spellings) is shared vocabulary for adapters naming the spawn shapes; membership keys
no verdict path.
