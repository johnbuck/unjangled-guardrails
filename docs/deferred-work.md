# Deferred work

Items consciously left out of shipped changes, with the reason and the shape of the fix.

## Generalize path-argument extraction beyond the fixed families (dir entries, 2026-10-20)

Directory entries (docs/policy.md, "Directory entries") bind only the calls whose path
arguments the v1 extractor sees: the fixed file-shaped families (the read/write/search/list
spellings, bare or on an mcp `__` final segment) via the
`path`/`file_path`/`filePath`/`PATH`/`notebook_path` keys, and bash commands' absolute/tilde
tokens. Unlisted path-carrying tools — an MCP `move_file` (`source`/`dest`), `directory_tree`,
anything with its own argument spelling — contribute nothing, take the plain verdict, and a
dir DENY does not bind them. The docs state this as part of the entry's trust decision.

Fix shape: derive path-shaped keys per tool instead of the fixed list — from the harness tool
schemas where available, with a conservative fallback convention — then re-run the confined
matrix plus a deny-binding row for a previously-unlisted tool (the current rows all use listed
shapes, so the generalization would pass vacuously without one).

Source: review of the dir-targets feature (2026-10-20, commits 5d998d2 + b873c10). Owner: the
operator's next policy pass; the docs scoping above is the interim contract.
