import { readCoseContent } from "./core/check_signature.js";
// Public API re-exports from the refactored core modules.
export { default as Runner } from "./core/Runner.js";
export { pickSecurityEntry } from "./core/match_pattern_runner.js";
export { createQrScanner } from "./core/create_scanner.js";
export { readCoseContent };

// Helper that trims raw input before verification.
export async function readCoseContentDirectly(cose) {
  const text = typeof cose === "string" ? cose.trim() : "";
  return await readCoseContent(text);
}
