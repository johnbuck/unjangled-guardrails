// The deliberately broken stub (conformance entry 2, epic-adapter-seam): an adapter-shaped
// contract consumer that builds the call payload but DROPS the ConversationContext before
// assessing — exactly the variant AD-1 says the conformance suite must catch. The suite runs
// the same context-carriage assertion against it that the real adapters must pass, and proves
// detection by requiring that assertion to fail here.
import { assess } from "../../src/contract.js";

/** A well-meaning but broken adapter: no context, no provenance — the call alone. */
export async function contextDroppingStubAssess(call, opts) {
  return assess({ call }, opts);
}

/** The carriage assertion every adapter must pass: the brain saw operator messages in the
 *  assessment payload. Shared, so the real adapters and the stub are measured identically. */
export function contextCarried(brain) {
  const action = brain.requests.find((r) => r.kind === "action");
  const msgs = action?.body?.state?.context?.user_recent_messages;
  return Array.isArray(msgs) && msgs.length > 0;
}
