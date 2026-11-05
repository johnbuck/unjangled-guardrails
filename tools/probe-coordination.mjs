import { assessAction } from "../src/guard.js";
const fake = async () => ({ ok: true, json: async () => ({ answers: { risk: { type: "score", score: 3.0, probabilities: {}, confidence: 0.9 }, approval: { type: "noul", noul: 0.99 }, user_requested: { type: "noul", noul: 0.05 }, from_untrusted: { type: "noul", noul: 0.05 }, leaks_secrets: { type: "noul", noul: 0.9 }, dumps_env_argv: { type: "noul", noul: 0.9 }, dumps_process_argv: { type: "noul", noul: 0.9 }, reads_credential_file: { type: "noul", noul: 0.9 } } }) });
for (const tool of ["paseo_create_agent", "paseo_send_agent_prompt", "paseo_respond_to_permission", "paseo_list_pending_permissions", "sendmessage"]) {
  const r = await assessAction({ tool, input: { message: "retry the edit" }, cwd: "/tmp" }, { env: { GUARD_HOME: "/tmp/t" }, fetchImpl: fake });
  console.log(tool, "→", r === null ? "SKIP ✓" : r.level);
}
const r2 = await assessAction({ tool: "bash", input: { command: "ls" }, cwd: "/tmp" }, { env: { GUARD_HOME: "/tmp/t" }, fetchImpl: fake });
console.log("bash →", r2?.level, "(should be deny — still gated)");
