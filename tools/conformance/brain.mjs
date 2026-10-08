// The simulated brain (conformance entry 2, epic-adapter-seam): deterministic scripted answers
// to every question set the core asks — ACTION_QUESTIONS, SCAN_QUESTIONS, INSTRUCTION_QUESTIONS —
// with zero classifier calls and zero network. In-process adapters get `fetchImpl` injected
// directly; the Hermes python bridge spawns the real CLI, so it gets the same scripted answers
// over a loopback HTTP server (startBrainServer) instead. Every request the brain sees is
// recorded, so carriage cases (context, task) can assert on what actually reached the seam.
//
// Scenario = the verdict the brain is scripted to produce:
//   deny       risk 3.0            → Dangerous Action deny
//   ask        risk 2.0, high approval → Approval Needed ask
//   allow      risk 1.0, low approval  → allow
//   leak       risk 1.0, leaks_secrets 0.60 → Credential Exposure deny
//   untrusted  risk 1.0, from_untrusted 0.90 → Injected Instruction deny
//   flagged    scan: directed 0.93, kind injection → flagged
//   clean      scan: directed 0.05, kind benign    → clean

const noul = (p) => ({ type: "noul", noul: p });

export const SCENARIOS = {
  deny: { risk: 3.0, approval: 0.5 },
  ask: { risk: 2.0, approval: 0.85 },
  allow: { risk: 1.0, approval: 0.2 },
  leak: { risk: 1.0, approval: 0.2, leak: 0.6 },
  untrusted: { risk: 1.0, approval: 0.2, untrusted: 0.9 },
  flagged: { p: 0.93, kind: "injection" },
  clean: { p: 0.05, kind: "benign" },
};

/** Classify one brain request: which question set it carries, plus the parsed body. */
export function classifyRequest(body) {
  const q = body?.questions ?? {};
  if ("risk" in q) return { kind: "action", body };
  if ("directed" in q) return { kind: "scan", body };
  if ("malicious" in q) return { kind: "instructions", body };
  return { kind: "unknown", body };
}

/** The scripted answer for one request under one scenario. Shared by fetchImpl and the HTTP server. */
export function brainAnswer(body, scenarioName) {
  const s = SCENARIOS[scenarioName] ?? SCENARIOS.ask;
  const { kind } = classifyRequest(body);
  if (kind === "action") return { answers: {
    risk: { type: "score", score: s.risk, probabilities: {}, confidence: 0.8 },
    approval: noul(s.approval), user_requested: noul(s.user ?? 0.05), from_untrusted: noul(s.untrusted ?? 0.05),
    leaks_secrets: noul(s.leak ?? 0.05), dumps_env_argv: noul(0.02), dumps_process_argv: noul(0.02), reads_credential_file: noul(0.02),
  } };
  if (kind === "scan") return { answers: {
    kind: { type: "choice", choice: s.kind ?? "injection", probabilities: {}, confidence: 0.8 },
    directed: noul(s.p ?? 0.93),
  } };
  if (kind === "instructions") return { answers: {
    kind: { type: "choice", choice: "clean", probabilities: {}, confidence: 0.8 },
    malicious: noul(0.05),
  } };
  throw new Error(`simulated brain: unrecognized question set (${Object.keys(body?.questions ?? {}).join(", ") || "none"})`);
}

/** An injectable brain for in-process adapters: `fetchImpl` for the core's opts, `requests` for carriage assertions. */
export function scriptedBrain(scenarioName) {
  const requests = [];
  const fetchImpl = async (_url, init) => {
    const body = JSON.parse(init.body);
    requests.push(classifyRequest(body));
    return { ok: true, status: 200, json: async () => brainAnswer(body, scenarioName) };
  };
  return { scenario: scenarioName, fetchImpl, requests };
}

/** The same brain as a loopback-only HTTP server, for adapters that spawn the real CLI
 *  process (which configures its backend from env, so the URL is the injection point).
 *  `setScenario` switches the script between cases; requests land in the same record shape. */
export async function startBrainServer() {
  const { createServer } = await import("node:http");
  const requests = [];
  let scenario = "ask";
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      if (req.url === "/__scenario") {
        scenario = JSON.parse(raw).name;
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ scenario }));
      }
      try {
        const body = JSON.parse(raw);
        requests.push(classifyRequest(body));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(brainAnswer(body, scenario)));
      } catch (err) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    setScenario: (name) => { scenario = name; },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
