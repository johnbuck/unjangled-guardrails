// One fetch, two backends: TypeSafe's API when JEV_API_KEY is set, Vercel AI Gateway otherwise.
// Question ids are ours; types are TypeSafe's (noul / choice / score). Gateway calls noul "boolean".
const TYPESAFE_URL = "https://api.typesafe.ai/v1/systemone";
const GATEWAY_URL = "https://ai-gateway.vercel.sh/v4/ai/evaluation-model";

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const CONFIG_FILE = join(homedir(), ".unjangled-guardrails", "config.json");
export const LEGACY_CONFIG_FILE = join(homedir(), ".jev-guard", "config.json");

// Env first (CLIs inherit the shell); then ~/.unjangled-guardrails/config.json written by `unjangled-guardrails key`, which is what
// GUI hosts such as Cursor or Zed need since they don't see your shell profile.
// SYSTEMONE_URL selects the `local` backend (self-hosted Jev-compatible /v1/systemone service, e.g. the SemIf
// shim) and wins over every cloud credential: with it set, the guard can never phone home.
// Back-compat (operator ruling 2026-10-07): every pre-rename JEV_* name still works, read after the new name.
export function backend(env = process.env) {
  const localUrl = env.SYSTEMONE_URL ?? env.JEV_BASE_URL;
  if (localUrl) return { kind: "local", url: localUrl, key: env.SYSTEMONE_KEY ?? env.JEV_API_KEY_LOCAL };
  if (env.JEV_API_KEY) return { kind: "typesafe", key: env.JEV_API_KEY };
  if (env.AI_GATEWAY_API_KEY) return { kind: "gateway", key: env.AI_GATEWAY_API_KEY, auth: "api-key" };
  if (env.VERCEL_OIDC_TOKEN) return { kind: "gateway", key: env.VERCEL_OIDC_TOKEN, auth: "oidc" };  // `vercel env pull`; expires in ~12h
  const cfg = readConfig(env);
  if (cfg.localBaseUrl) return { kind: "local", url: cfg.localBaseUrl, key: cfg.localApiKey };
  if (cfg.jevApiKey) return { kind: "typesafe", key: cfg.jevApiKey };
  if (cfg.aiGatewayApiKey) return { kind: "gateway", key: cfg.aiGatewayApiKey, auth: "api-key" };
  return null;
}

export function readConfig(env = process.env) {
  try { return JSON.parse(readFileSync(env.GUARD_CONFIG ?? env.JEV_GUARD_CONFIG ?? CONFIG_FILE, "utf8")); } catch {}
  try { return JSON.parse(readFileSync(LEGACY_CONFIG_FILE, "utf8")); } catch {}
  return {};
}

/** @returns {Promise<Record<string, {p?: number, choice?: string, score?: number, probabilities?: Record<string, number>, confidence?: number}>>} */
export async function ask(state, questions, { env = process.env, fetchImpl = fetch, signal, timeoutMs } = {}) {
  const b = backend(env);
  if (!b) throw new Error("no backend: set SYSTEMONE_URL for a local Jev-compatible service, or run `unjangled-guardrails key <key>` / set JEV_API_KEY / AI_GATEWAY_API_KEY");
  const gw = b.kind === "gateway";
  const lc = b.kind === "local";
  const model = env.SYSTEMONE_MODEL ?? env.JEV_MODEL;
  const q = gw ? mapValues(questions, (x) => (x.type === "noul" ? { ...x, type: "boolean" } : x)) : questions;
  // One budget for the whole call, retries included: every host kills a hook at ~30 s, and a hook that dies
  // never reaches the fail-closed branch. Default 20 s leaves room for process start-up.
  const budget = AbortSignal.timeout(timeoutMs ?? +((env.GUARD_TIMEOUT_MS ?? env.JEV_GUARD_TIMEOUT_MS) || 20_000));
  const abort = signal ? AbortSignal.any([signal, budget]) : budget;
  const request = () => fetchImpl(lc ? `${b.url.replace(/\/+$/, "")}/v1/systemone` : gw ? GATEWAY_URL : TYPESAFE_URL, {
    method: "POST",
    headers: lc
      ? { ...(b.key ? { Authorization: `Bearer ${b.key}` } : {}), "Content-Type": "application/json" }
      : gw
      ? { Authorization: `Bearer ${b.key}`, "Content-Type": "application/json", "ai-gateway-protocol-version": "0.0.1",
          "ai-gateway-auth-method": b.auth, "ai-evaluation-model-specification-version": "4", "ai-model-id": model ?? "typesafe-ai/jev" }
      : { Authorization: `Bearer ${b.key}`, "Content-Type": "application/json" },
    body: JSON.stringify(lc
      ? { state, ...(model ? { model } : {}), questions }   // local: no sampling controls, no boolean mapping; no SYSTEMONE_MODEL -> the shim's SYSTEM_ONE_DEFAULT_MODEL answers
      : gw
      ? { state, questions: q, providerOptions: { gateway: { zeroDataRetention: true } } }
      : { state, model: model ?? "jev-latest", questions: q }),
    signal: abort,
  });
  let res;
  for (let attempt = 0; ; attempt++) {
    try {
      res = await request();
      if (res.ok || (res.status !== 429 && res.status < 500) || attempt === 2) break;
      await res.text().catch(() => {});  // release the socket before retrying
    } catch (err) {
      if (abort.aborted || attempt === 2) throw err;  // network blips (ECONNRESET, DNS) retry; aborts and the last attempt don't
    }
    await sleep(600 * 2 ** attempt, abort);
  }
  if (!res.ok) throw new Error(`${b.kind} HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const body = await res.json();
  // A malformed answer is a degrade trigger like any other (Story 11). Absent individual
  // answers are tolerated (optional questions degrade to p=0); no answers at all is not.
  if (!body?.answers || typeof body.answers !== "object" || !Object.keys(body.answers).length)
    throw new Error("malformed answer: the backend response carries no answers");
  const conf = body.providerMetadata?.typesafe?.confidence ?? {};
  return mapValues(body.answers, (a, id) => ({
    p: a.noul ?? a.probability, choice: a.choice, score: a.score, probabilities: a.probabilities,
    confidence: a.confidence ?? conf[id],
  }));
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    const t = setTimeout(() => { signal.removeEventListener("abort", onAbort); resolve(); }, ms);
    const onAbort = () => { clearTimeout(t); reject(signal.reason); };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function mapValues(obj, fn) {
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, fn(v, k)]));
}
