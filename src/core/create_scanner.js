import { BrowserQRCodeReader } from "@zxing/browser";

// Camera-based QR scanner. Returns a cleanup function that stops scanning.
export async function createQrScanner(videoElement, onSuccess, options = {}) {
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
        codeReader.reset();
        controls?.stop?.();
      } catch (resetErr) {}
    };
  } catch (err) {
    console.error("Failed to start scanner:", err);
    if (typeof onError === "function") onError(err);
    throw err;
  }
}
