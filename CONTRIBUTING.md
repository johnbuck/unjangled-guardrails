# Contributing

```bash
git clone https://github.com/leepokai/jev-guard && cd jev-guard
npm test                       # node:test with a fake Jev; no API key needed
jev-guard key "…" && node src/cli.js check Bash '{"command":"rm -rf /"}'   # live check
```

- Plain ESM JavaScript, no build step, no runtime dependencies. Keep it that way.
- One core (`src/guard.js`), thin adapters. A new host means a new dialect in `src/hook.js` or a new file next to `src/opencode.js`, plus a manifest at the root and a row in the README table — not a fork of the policy.
- Policy changes (questions, thresholds) need numbers: run the calibration set in the README against the live API and paste the table in the PR.
- Every non-trivial change leaves a test in `test/guard.test.js`.
