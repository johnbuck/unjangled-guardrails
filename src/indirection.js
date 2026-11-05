// Context-body extractor for the deny-layer context-body floor (operator doctrine
// 2026-10-25: nothing deterministic reaches the ask band; dangerous denies naming the
// piece, everything else goes to the brain). The bodies of executing command contexts —
// substitution, subshell, backtick, and the double-quoted forms that still execute — run
// as commands and their output lands in the conversation, so the credential floor reads
// them like any command: echo $(cat prod.env) keeps its doctrine deny instead of hiding
// the verb inside the context. No ask is ever produced from this module.
// (The indirection escalator that previously lived here retired 2026-10-25 — it asked on
// inscrutable shapes, contradicting the ratified ask-band doctrine; superseded-by-doctrine
// in docs/rules-retirement.md.)

// Span of one command context: $( ) / ( ) up to the matching close paren (paren counting
// only), or ` ` up to the first close backtick. i is the index of the OPEN character.
function span(raw, i, close) {
  let d = close === ")" ? 1 : 0;
  let text = "";
  i++;
  while (i < raw.length) {
    const c = raw[i];
    if (close === "`") { if (c === "`") return { text, end: i, closed: true }; text += c; i++; continue; }
    if (c === "(") d++;
    else if (c === ")") { d--; if (d === 0) return { text, end: i, closed: true }; }
    text += c;
    i++;
  }
  return { text, end: i, closed: false };
}

// The bodies of every executing command context in raw, outermost first, nested bodies
// included via recursion. Quote state mirrors splitTopLevel (single quotes are literal;
// double-quoted $( ) and backticks still execute).
export function commandContextBodies(raw) {
  const bodies = [];
  const walk = (text) => {
    let quote = "";
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quote === "'") { if (c === "'") quote = ""; continue; }
      if (quote === '"') {
        // inside double quotes $( ) and backticks still execute — their bodies are contexts
        if (c === "$" && text[i + 1] === "(") { const b = span(text, i + 1, ")"); bodies.push(b.text); walk(b.text); i = b.end; continue; }
        if (c === "`") { const b = span(text, i, "`"); bodies.push(b.text); walk(b.text); i = b.end; continue; }
        if (c === "\\") i++; else if (c === '"') quote = "";
        continue;
      }
      if (c === "\\") { i++; continue; } // backslash-escaped chars are literal: \$ is text, not a context open
      if (c === "'") { quote = "'"; continue; }
      if (c === '"') { quote = '"'; continue; }
      if (c === "$" && text[i + 1] === "(") { const b = span(text, i + 1, ")"); bodies.push(b.text); walk(b.text); i = b.end; continue; }
      if (c === "(") { const b = span(text, i, ")"); bodies.push(b.text); walk(b.text); i = b.end; continue; }
      if (c === "`") { const b = span(text, i, "`"); bodies.push(b.text); walk(b.text); i = b.end; continue; }
    }
  };
  walk(raw);
  return bodies;
}
