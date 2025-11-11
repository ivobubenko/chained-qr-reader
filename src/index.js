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

export async function createQrScanner(videoElement, onSuccess, securityChain, options = {}) {
  const { deviceId: requestedDeviceId, onError } = options ?? {};
  const codeReader = new BrowserQRCodeReader();
  try {
    const devices = await BrowserQRCodeReader.listVideoInputDevices();
    const fallbackDeviceId = devices[0]?.deviceId;
    const targetDeviceId = requestedDeviceId ?? fallbackDeviceId;
    if (!targetDeviceId) throw new Error("No camera found");

    const controls = codeReader.decodeFromVideoDevice(
      targetDeviceId,
      videoElement,
      async (result, err) => {
        if (result) {
          const text = typeof result.text === "string" ? result.text.trim() : "";
          try {
            onSuccess(text);
          } catch (error) {
            console.error(error);
          }
        } else if (err && err.name !== "NotFoundException") {
          console.error(err);
          if (typeof onError === "function") onError(err);
        }
      }
    );

    return () => {
      try {
        controls?.stop?.();
      } catch (stopErr) {
        console.warn("Failed to stop QR controls", stopErr);
      }
      try {
        codeReader.reset();
      } catch (resetErr) {
        console.warn("Failed to reset QR reader", resetErr);
      }
    };
  } catch (err) {
    console.error("[Main Thread] Failed to start scanner:", err);
    if (typeof onError === "function") onError(err);
    throw err;
  }
}
