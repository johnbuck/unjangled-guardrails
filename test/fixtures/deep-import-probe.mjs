// Deliberate deep-import probe for the contract import lint (AD-1). This file is NOT an
// adapter and never runs: it exists so the lint test can prove it fails a file that imports
// a core module past the contract, the way a misbehaving adapter would.
import { failClosed } from "../../src/orchestrate.js";
import { assessAction } from "../../src/guard.js";
export { failClosed, assessAction };
