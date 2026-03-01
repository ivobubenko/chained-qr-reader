import { BrowserQRCodeReader } from "@zxing/browser";

// Camera-based QR scanner. Returns a cleanup function that stops scanning.
export async function createQrScanner(videoElement, onSuccess, options = {}) {
  const { deviceId: requestedDeviceId, onError } = options ?? {};
  const codeReader = new BrowserQRCodeReader();
  try {
    const devices = await BrowserQRCodeReader.listVideoInputDevices().catch(() => []);
    const fallbackDeviceId = devices[0]?.deviceId;
    const normalizedRequestedDeviceId =
      typeof requestedDeviceId === "string" ? requestedDeviceId.trim() : requestedDeviceId;
    const targetDeviceId = normalizedRequestedDeviceId || fallbackDeviceId || undefined;

    const controls = await codeReader.decodeFromVideoDevice(
      targetDeviceId,
      videoElement,
      async (result, err) => {
        if (result) {
          const text = typeof result.text === "string" ? result.text.trim() : "";
          try {
            onSuccess(text);
          } catch (error) {}
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
    const error = err instanceof Error ? err : new Error(String(err ?? "Unknown camera error"));
    try {
      onError?.(error);
    } catch {}
    throw error;
  }
}
