import { scanContent } from "../src/guard.js";
const filler = "The quick brown fox jumps over the lazy dog. Ordinary documentation text with no instructions. ".repeat(1);
for (const n of [4000, 12000, 60000]) {
  const text = filler.repeat(Math.ceil(n / filler.length)).slice(0, n);
  const env = { ...process.env };
  if (n === 60000) delete env.GUARD_MAX_STATE_CHARS; // default-budget path (now local-backend-aware)
  const r = await scanContent({ text, tool: "WebFetch", source: "https://example.com/x" }, { env });
  console.log(`chars=${n}  ->  ${r ? (r.flagged ? "FLAGGED" : "CLEAN(scanned)") : "SKIPPED(no scan)"}`);
}
