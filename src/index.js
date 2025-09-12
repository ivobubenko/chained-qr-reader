import { BrowserQRCodeReader } from "@zxing/browser";
//import Worker from "web-worker:./worker.js";
import { readCoseContent } from "./core/check_signature";

// Removed unused import sanitizeContent
export { default as Runner } from "./Runner.js";
export { readCoseContent };
export async function readCoseContentDirectly(cose) {
  const text = typeof cose === "string" ? cose.trim() : "";
  return await readCoseContent(text);
}

const startsWithPattern = (pattern, text) => {
  const s = String(text ?? "");
  if (typeof pattern === "string") return s.startsWith(pattern);
  if (pattern instanceof RegExp) {
    const f = pattern.flags.replace(/g/g, "");
    return new RegExp("^" + pattern.source, f).test(s);
  }
  return false;
};

export const pickSecurityEntry = (entries, text) =>
  entries?.find((e) => startsWithPattern(e.pattern, text));

/**  
  securityChain:
    [{
      pattern: String,
      securityFunctionChain: class
    }]
*/
export async function createQrScanner(videoElement, onSuccess, securityChain) {
  // const worker = new Worker();
  const codeReader = new BrowserQRCodeReader();
  try {
    const devices = await BrowserQRCodeReader.listVideoInputDevices();
    const firstCamera = devices[0]?.deviceId;
    if (!firstCamera) throw new Error("No camera found");

    codeReader.decodeFromVideoDevice(
      firstCamera,
      videoElement,
      async (result, err, controls) => {
        if (result) {
          const text =
            typeof result.text === "string" ? result.text.trim() : "";
          try {
            onSuccess(text);
          } catch (error) {
            console.error(error);
          }
        } else if (err && err.name !== "NotFoundException") {
          console.error(err);
        }
      }
    );
  } catch (err) {
    console.error("[Main Thread] Failed to start scanner:", err);
  }
}
