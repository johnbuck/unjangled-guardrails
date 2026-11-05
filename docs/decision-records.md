# Decision records

The gate records every verdict it produces — ask, deny, and allow — as a redacted, versioned
row. Asks and denies land in `decisions-candidates.jsonl` in the gate home — the corpus
candidates the operator curates by hand (FR-E1); allows land in the sibling bulk store
`decisions-allows.jsonl`, so routine high-volume allow traffic can never evict the scarce
ask/deny corpus from its trim window (2026-10-26, ticket 5). This file documents the row
schema and the export document format. The schema is v:1 and matches `src/record.js`
field-for-field; `test/decision-records-doc.test.js` fails when the doc and the code diverge.

## The recording pipeline

**What records.** Every ask, every deny, and every allow the gate produces. Denies: Always-Deny
floor hits, brain denies, lane/dir/ruling-modified verdicts, brain-down degraded denies. Allows:
plain brain allows, the user-words lift, lane/dir pass effects, ruling overrides, brain-down
degraded fail-open allows. A row carries the core's verdict: on hosts without a prompt surface
the ask converts to deny host-side, and the row still records the ask.

**Where.** `decisions-candidates.jsonl` (ask/deny) and `decisions-allows.jsonl` (allow), both
inside the gate home. The gate home resolves as `GUARD_HOME`, else `JEV_GUARD_HOME`, else
`~/.unjangled-guardrails`. Each file is JSONL — one row per line, mode 0600. The store is
chosen by the row's `level`: an allow row is written only to the allow store, an ask or deny
row only to the candidates store — neither store's window ever contains the other's rows.

**Off-switch.** On by default — agents share the gate home and need no env setup.
`GUARD_RECORD_DECISIONS=0|false|no|off` disables recording entirely.

**Failure posture.** Fail-open by contract. Any recording failure logs at most one warning
per minute and the verdict ships untouched.

**Trim.** Per store. The candidates store: past 1,000,000 bytes (1 MB) it rewrites to the
newest 400 rows. The allow store (bulk volume, operator-tunable-on-request): past 2,000,000
bytes (2 MB) it rewrites to the newest 2000 rows. Append is atomic per row; the trim is
last-writer-wins under concurrency — a row lost between the trim's read and write is
accepted, corruption is not. Both stores are operator-owned; the trim only bounds growth.

**Gitignore.** `decisions-candidates.jsonl` and `decisions-allows.jsonl` are gitignored. A
gate home shaped like a repo checkout never commits rows; everywhere else the stores stay
operator-local too.

## The v:1 row schema

The recorder stamps the base fields, then spreads the caller's fields after them. Fields
the caller leaves `undefined` are absent from the row — JSON drops them.

| field | type | semantic |
|---|---|---|
| `v` | number | schema version; always 1 |
| `at` | string | recording time, ISO 8601 UTC |
| `level` | string | the verdict — `ask`, `deny`, or `allow` |
| `category` | string | the reason category, by deciding path: the family label (`Dangerous Action`, `Credential Exposure`, `Injected Instruction`) where the verdict set one; the operator-rule reason text on lane/dir/ruling rows; degraded denies always carry `Credential Exposure` (forced fail-closed classification); the fallbacks are `Dangerous Action` for a plain deny and `Approval Needed` for a plain ask; a degraded row with no family records the degraded reason text (reachable via a lane/dir ask effect over a degraded allow). On allow rows the same verdict-time expression runs: plain brain/lane/dir/ruling allows and the user-words lift carry the `Approval Needed` fallback; a ruling override over a deny carries the pre-override family label; a degraded allow records the posture's why text — the ruling text (`by ruling <id> (the brain is unreachable, but the ruling needs none)`) when an allow ruling acted under the brain-down posture, the posture text otherwise |
| `governing` | string | the decisive layer: `floor` (Always-Deny), `brain`, `lane`, `dir`, `ruling`, `degraded` (brain down), or `escalator` — a consulted-but-no-op layer never claims provenance. When the brain is down, a lane/dir/ruling effect can still decide the verdict over the posture's fallback: the row then carries that effect layer as `governing` with `degraded: true` and no `risk` (the brain never scored). `escalator` is the retired offline indirection escalator (retired 2026-10-25, see docs/rules-retirement.md); rows recorded under it are valid history — the store's legacy window carries them and the validator accepts them |
| `stats` | string | the stats line, by deciding path: floor rows carry the floor rule's description (`read-path gate: …`, `catastrophic command`, `credential-source floor: …`, the self-protection legs `policy store write` / `gate source write`, …); brain rows carry `risk X/3, approval p=…, confidence …`; retired escalator rows carry `offline escalator, no brain call`; degraded rows carry `brain down, rules mode; fail-closed` (deny) or `brain down, rules mode` / `brain down, layered mode` (allow-derived) |
| `what` | string | the masked display summary (tool + command preview); secret-shape masked at intake no matter what the caller already did |
| `command` | string | the command preview, value-masked and truncated to 200 chars; absent on credential-source floor denies (the floor's own stats name it) |
| `why` | string | the deciding path's reason text, where that path sets one — floor rows, untrusted-content and leak denies, lane/dir operator rules, ruling rows, and degraded rows carry it; plain brain ask-band and deny-line rows carry none. Allow rows carry it the same way: the user-words lift (`the user explicitly asked for it`), a lane/dir pass, a ruling override, and degraded allows name their deciding path; a plain brain allow carries none. On a degraded allow the reason text names the ruling when one acted — and that text is the id's only carrier there: the `ruling` field rides on governing-ruling rows only, because the degraded posture applies the ruling internally and does not propagate the id |
| `floor` | string | the Always-Deny floor name, where the deciding floor has one; floor rows only. The Gate Self-Protection family (`src/always-deny.js` `selfModFamily`) carries no floor name — its guard.js call writes `floor: undefined`, which JSON drops — so a floor row with no `floor` field is that family's recorded shape; its `stats` line names the leg instead (`policy store write`, `gate source write`, `guard's own store/config/sessions`) |
| `ruling` | string | the deciding ruling's id; ruling rows only — an ask/deny hard-block deny or a ruling override that landed as an allow |
| `risk` | number | the brain-path risk score, out of 3 — the brain's score whatever layer decided the verdict; rides on every brain-path row (`brain`, `lane`, `dir`, `ruling`), absent on `floor` rows (the floor decides before the brain is consulted) and absent when degraded |
| `degraded` | boolean | `true` when the row was produced with the brain down — whatever governing layer the verdict ended on (a lane/dir/ruling modifier over the posture's fallback carries it too) |
| `rulingHint` | string | the ask's unblock-hint text, secret-shape masked at intake; present when one exists. Ask rows only — the hint is computed on the ask band, so an allow row never carries one |
| `segments` | array | attribution rows of `{text, risk}` — the brain's classification segments; attribution runs only on ask/deny verdicts, so an allow row never carries one |

`level`, `category`, `governing`, `stats`, `what` ride on every row; the rest are
conditional on the deciding layer.

### What a valid document satisfies (validator contract)

`validateDecisionDocument` (in `src/decision-export.js`, alongside the exporter) enforces
exactly this, and any consumer may rely on it:

- Header: `schema_version` is exactly 1; `generated_at` is an ISO 8601 UTC timestamp in
  the recorder's `toISOString` form (`YYYY-MM-DDTHH:MM:SS.sssZ`); `source` is a non-empty
  string; `row_count` is an integer equal to `rows.length`; `redaction_statement` is the
  pinned guarantee verbatim; `rows` is an array.
- Every row: a JSON object; `v` exactly 1; `at` an ISO 8601 UTC timestamp (`…Z`); `level`
  `ask`, `deny`, or `allow`; `governing` one of `floor|brain|lane|dir|ruling|degraded|escalator`;
  `category`, `stats`, `what` non-empty strings. `floor` and `ruling`, when present, are
  non-empty strings — and ride only on floor rows / ruling rows respectively; a floor row
  carries `floor` where its deciding floor has a name, and the self-protection family
  records none (its stats line names the leg). `risk`, a
  number 0–3, rides on non-degraded brain-path rows (`brain`, `lane`, `dir`, `ruling`) and
  on no others (floor rows predate the brain; escalator rows decided pre-brain, offline).
  Degraded precedence outranks the effect layer: a `degraded: true` row carries no risk
  whatever its governing string says, and a non-degraded lane/dir/ruling row without one
  fails. `degraded`, when present, is a
  boolean — `true` on degraded rows. `command`, `why`, and `rulingHint` are strings when
  present; `segments` is an array of `{text, risk}` objects.
- Extra fields are not rejected: "verbatim" describes the export-vs-store pass-through
  (nothing added, nothing stripped between the store and the document), not a closed field
  set. Rows carrying fields this schema does not name are still valid v:1 rows; new fields
  are a future format version's business.

The validator reports named errors (`header: …`, `rows[i]: …`) and never throws.

## Redaction guarantees

Rows are masked at intake, not at display: every `what` runs the secret-shape mask inside
the recorder no matter what the caller already did — this is an at-rest store, so
display-grade redaction is not enough. `rulingHint` runs the same mask at intake — the
unblock hint embeds raw command segments. `command` runs the value mask (secret shapes plus
credential spans) before truncation. What never appears at rest or in an export: a raw
credential value — tokens, passwords, keys. Structure displays; values do not.

## Export document format v1

The export emits one JSON document. The header identifies the store (or stores) and the
format; the rows are v:1 rows verbatim — the schema above, nothing added, nothing stripped.

The default export reads BOTH stores — the ask/deny candidates store and the allow store —
and merges them into one document sorted by `at`, oldest first; rows with equal `at` keep
the candidates row first (the sort is stable and the candidates rows enter the merge
first). A store that does not exist yet is an empty window, not an error — a fresh install
has neither file. `row_count` is the merged total; `source` names both stores. `--from
<path>` pins the export to one file: that file only, strict (missing file is an error),
`source` is that path alone. Missing-row provenance is not reconstructed: a merged export
reads the two windows, it does not re-derive which store a row came from.

```json
{
  "schema_version": 1,
  "generated_at": "2026-10-25T00:00:00.000Z",
  "source": "/path/to/decisions-candidates.jsonl + /path/to/decisions-allows.jsonl",
  "row_count": 42,
  "redaction_statement": "every credential-shaped value was masked at intake; this document carries masked values only",
  "rows": []
}
```

| header field | semantic |
|---|---|
| `schema_version` | the document format version; 1 |
| `generated_at` | export time, ISO 8601 UTC |
| `source` | the store the export read — both stores joined with ` + ` on a default (merged) export, the single path under `--from` |
| `row_count` | the number of rows in `rows` |
| `redaction_statement` | the fixed redaction guarantee, verbatim — an export of credential-shaped rows carries masked values only |

## Reading the store

Operator-readable today: one JSON object per line, every field explained by the table
above. The format is versioned for future machine consumers — a new major version means a
deliberate row-shape change, never a silent drift. Each store is bounded: the candidates
store keeps the newest 400 rows under its 1 MB cap, the allow store the newest 2000 under
its 2 MB cap, so a store — and any export of it — covers the current window only. Rows
past the trim are gone; there is no backfill.
