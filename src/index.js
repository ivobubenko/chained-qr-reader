import { readCoseContent } from "./core/functions/check_signature.js";
// Public API re-exports from the refactored core modules.
export { FunctionChainer } from "./core/class/FunctionChainer.js";
export { createQrScanner } from "./core/functions/create_scanner.js";
export { readCoseContent };
export { preventXss } from "./core/functions/xss.js";
export { createUiIframe } from "./ui/iframe.js";
export { createUiDiv } from "./ui/div.js";

// Helper that trims raw input before verification.
export async function readCoseContentDirectly(cose) {
  const text = typeof cose === "string" ? cose.trim() : "";
  return await readCoseContent(text);
}
