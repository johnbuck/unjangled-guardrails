// GENERATED from vendor/guardrails-core/guardrails.verbatim.js — do not edit by hand.
// Provenance: OpenCode guardrails plugin (dotfiles opencode/plugins/guardrails.js,
// sha256-verified verbatim copy). Regenerate with tools/extract-guardrails-core.mjs.
export const CATASTROPHIC = [
    /\brm\b(?=[^\n|;]*(?:-\w*r|--recursive))(?=[^\n|;]*(?:-\w*f|--force))[^\n|;]*\s(?:\/\*?|~\/?|\$\{?HOME\}?\/?|\/home\/?)(?=\s|["';|]|$)/i,
    /\bfind\s+(?:\/|~\/?|\$\{?HOME\}?\/?|\/home\/?)(?=\s|$)[^\n]*(?:-delete|-exec\s+rm)\b/,
    /(?:>|>>|\btee\b|\bof=)\s*["']?\/dev\/(?:sd|nvme|vd|hd|mmcblk|disk|loop)/,
    /\b(?:wipefs|blkdiscard|shred|truncate|mkfs\S*|sgdisk)\b[^\n]*\/dev\/(?:sd|nvme|vd|mmcblk)/,
    /\bmv\b[^\n]*\s\/dev\/null\b/,
    /\bchown\b[^\n]*\s(?:-R|--recursive)\b[^\n]*\s\/(?:\s|$)/,
    /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
    /\bgit\s+push\b[^\n]*(?:--force\b|\s-f\b|\s\+[\w./-]+(?::|\s|$))/,
    /\bchmod\b[^\n]*(?:-R|--recursive|-\w*R)\b[^\n]*(?:[0-7]*777|a\+?rwx)\b/,
    /\b(?:ba|z|k)?sh\b[^\n]*-c\s+["']?\$\((?:curl|wget)\b/,
    /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:(?:ba|z|k)?sh|python[\d.]*|perl|ruby|node)\b/,
  ];
export const SECRET_SHAPE = [
    /sk-(?:proj-|live-)?[A-Za-z0-9]{20,}/, /sk_live_[A-Za-z0-9]{20,}/,
    /gh[pousr]_[A-Za-z0-9]{20,}/, /github_pat_[A-Za-z0-9_]{20,}/, /glpat-[A-Za-z0-9_-]{20,}/,
    /AKIA[0-9A-Z]{16}/, /AIza[0-9A-Za-z_-]{30,}/, /xox[baprs]-[A-Za-z0-9-]{10,}/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  ];
export function checkCatastrophic(cmd) {
  return CATASTROPHIC.some((r) => r.test(cmd))
    ? "a catastrophic-command rule matched (mass deletion, device overwrite, force push, recursive 777, or pipe-to-shell)"
    : null;
}
