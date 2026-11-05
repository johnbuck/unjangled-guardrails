# opencode-v2-home — committed opencode HOME fixture

A minimal opencode user-HOME layout for install tests and the parity battery:

    .config/opencode/plugins/   where `install opencode` writes the plugin adapter
    .local/share/opencode/      where the opencode process writes its state and logs

Empty directories carry a `.gitkeep` placeholder each (git does not track empty
dirs). This file doubles as the root placeholder.

Rules for users of this fixture:

- Never install INTO this committed tree. Copy it to a temp directory first and
  target the copy, e.g. `installFor("opencode", { home: <copy> })` or
  `unjangled-guardrails install opencode --v2 --home <copy>`. The committed tree
  must stay byte-identical across test runs (idempotence is checked against a
  copy, not here).
- `install opencode` (default) writes the v1 adapter — a named re-export of
  `UnjangledGuardrails`; `install opencode --v2` writes the v2 adapter, which
  default-exports `UnjangledGuardrailsV2` (the `{id, setup}` definition the
  v2.0.24 loader requires). Same filename either way: one host = one adapter.
- The layout mirrors the recorded isolated-HOME probe procedure
  (evidence/opencode-v2-plugin-loading-probe-2026-10-07.md): point a bind-mounted
  shadow home at a copy of this fixture AFTER running the install into it.
