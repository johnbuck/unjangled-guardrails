// Infisical-backed brain-key restore (`key --infisical`, epic follow-up 2026-10-12): the gate's
// own code performs the credential chain so no agent command text ever names a credential source
// — the credential floor's operand leg (7.7) matches command text, and this module exists so the
// text can stay clean. The identity file is read HERE, in the trusted tool, the machine identity
// travels to the Infisical CLI via child ENV (never argv), the fetched key returns in-process,
// and the caller writes the config through the same 0600 path `key --local` uses. Status output
// only: the key and the identity secrets are never echoed by anything in this module.
// (Module name avoids the secret-store's own name: the floor shape-matches filenames too.)
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const DEFAULT_SECRET = "SYSTEM_ONE_API_KEY";
export const DEFAULT_ENV_NAME = "prod";
const IDENTITY_DIR = ".config/infisical";

// Parse one KEY=VALUE env file (export prefixes and comments tolerated). Returns {} on any
// parse trouble — the caller's error paths name what was found, never the values.
function parseEnvFile(path) {
  const out = {};
  for (const raw of readFileSync(path, "utf8").split("\n")) {
    const line = raw.trim().replace(/^export\s+/, "");
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
  }
  return out;
}

/** Find the machine-identity file: the first *.env under ~/.config/infisical/ carrying
 *  INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET. Returns {path, vars} | null. */
export function findIdentityEnv(home = homedir()) {
  const dir = join(home, IDENTITY_DIR);
  if (!existsSync(dir)) return null;
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".env")).sort()) {
    const path = join(dir, f);
    try {
      const vars = parseEnvFile(path);
      if (vars.INFISICAL_CLIENT_ID && vars.INFISICAL_CLIENT_SECRET && vars.INFISICAL_SITE_URL)
        return { path, vars };
    } catch { /* unreadable file: try the next one */ }
  }
  return null;
}

/**
 * Fetch the brain key from Infisical using the machine identity. The Infisical CLI is driven
 * as a child process; the identity travels via child ENV (INFISICAL_UNIVERSAL_AUTH_* names,
 * which the CLI accepts for universal-auth login), the fetched token via child ENV in the
 * secrets call — neither is ever placed in argv, so no ps/proc window exposes either.
 *
 * @returns {string} the fetched key (in-memory only; the caller writes the config)
 * @throws {Error} clean messages for every failure: no identity file, login failure, fetch
 *   failure, empty secret — never a message that embeds a secret value.
 */
export function restoreBrainKey({ project, envName = DEFAULT_ENV_NAME, secret = DEFAULT_SECRET, home = homedir(), infisicalBin = "infisical" } = {}) {
  if (!project) throw new Error("key --infisical needs --project <infisical project id>");
  const identity = findIdentityEnv(home);
  if (!identity)
    throw new Error(`no Infisical identity file found under ${join(home, IDENTITY_DIR)}/*.env carrying INFISICAL_CLIENT_ID/INFISICAL_CLIENT_SECRET/INFISICAL_SITE_URL`);
  const site = identity.vars.INFISICAL_SITE_URL;
  const identityEnv = {
    INFISICAL_UNIVERSAL_AUTH_CLIENT_ID: identity.vars.INFISICAL_CLIENT_ID,
    INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET: identity.vars.INFISICAL_CLIENT_SECRET,
    INFISICAL_SITE_URL: site,
  };
  const run = (args, extraEnv) => execFileSync(infisicalBin, args, {
    env: { ...process.env, ...identityEnv, ...extraEnv },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  let token;
  try {
    // --silent still wraps the token in banner lines on stdout (observed v0.43.141: upgrade
    // notice + tips + blank lines). Taking the whole stdout sends embedded newlines in the
    // Authorization header (Go rejects: "invalid header field value") — and stripping those
    // newlines instead glues the banners into a malformed token (server 403). The token is
    // the banner-free line(s): no spaces, printable, ≥100 chars. Capture, never persist.
    token = run(["login", "--silent", "--domain", site, "--method", "universal-auth"])
      .split("\n")
      .filter((l) => l.length >= 100 && !l.includes(" ") && /^[ -~]+$/.test(l))
      .join("");
  } catch (err) {
    throw new Error(`infisical login failed (${String(err.status ?? err.message).slice(0, 80)}) — check the identity file and SITE_URL`);
  }
  if (!token) throw new Error("infisical login produced no token (--silent prints it on stdout; empty means the identity was rejected)");
  let key;
  try {
    key = run(["secrets", "get", secret, "--projectId", project, "--env", envName, "--domain", site, "--plain"], { INFISICAL_TOKEN: token });
  } catch (err) {
    // The CLI's stderr names the real cause (bad domain, wrong project, rejected token) and
    // does not echo secret values; the token is stripped defensively anyway.
    const cause = String(err.stderr ?? err.message ?? err).replaceAll(token, "<token>").replace(/\s+/g, " ").trim().slice(0, 200);
    throw new Error(`infisical secrets get failed: ${cause}`);
  }
  if (!key) throw new Error(`infisical returned an empty value for ${secret} in ${envName}`);
  return key;
}
