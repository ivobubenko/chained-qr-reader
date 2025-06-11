import { BrowserQRCodeReader } from "@zxing/browser";
import Worker from "web-worker:./worker.js";
// Removed unused import sanitizeContent

export async function createQrScanner(videoElement, onSuccess) {
  const worker = new Worker();
  console.log(worker);
  const codeReader = new BrowserQRCodeReader();

  worker.onmessage = (event) => {
    console.log("WE ARE SOOO BACK", event);
    if (onSuccess) onSuccess(event.data);
  };

  worker.onerror = (event) => {
    console.error("[Main Thread] Worker Error:", event);
  };

  try {
    const devices = await BrowserQRCodeReader.listVideoInputDevices();
    const firstCamera = devices[0]?.deviceId;

    if (!firstCamera) throw new Error("No camera found");
    codeReader.decodeFromVideoDevice(firstCamera, videoElement, (result) => {
      if (result) {
        worker.postMessage(result.getText());
      }
    });
  } catch (err) {
    console.error("[Main Thread] Failed to start scanner:", err);
  }
}
