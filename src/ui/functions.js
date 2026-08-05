import { createQrScanner } from "../core/functions/create_scanner.js";

export const toMessage = (error) => {
  const raw = String(error?.message || error || "").trim();
  const msg = raw || "Failed to start camera.";
  if (/notallowederror|permission/i.test(msg)) {
    return "Camera permission denied. Allow camera access in the browser settings.";
  }
  if (/notfounderror|no camera|videoinput/i.test(msg)) {
    return "No camera found on this device.";
  }
  if (/secure context|https|insecure/i.test(msg)) {
    return "Camera requires HTTPS (or localhost).";
  }
  return msg;
};

export const setMessage = (message, text = "") => {
  const value = String(text || "").trim();
  message.textContent = value;
  message.style.display = value ? "block" : "none";
};

export const setState = ({ running, btnStart, btnStop, btnSwitch, devices }) => {
  btnStart.disabled = running;
  btnStop.disabled = !running;
  btnSwitch.disabled = devices.length < 2;
};

const handleScan = async ({ text, onSuccess, settings, messageChannel }) => {
  const value = typeof text === "string" ? text.trim() : "";
  let result = { text: value };

  result = (await onSuccess.check(value)) || { text: value };

  window.parent.postMessage(
    { type: settings.parentMessageType, channel: messageChannel, text: value, result },
    settings.parentTargetOrigin
  );
};

export const createScannerHandlers = ({
  video,
  message,
  btnStart,
  btnStop,
  btnSwitch,
  onSuccess,
  settings,
  messageChannel,
  onScan,
  mapError = toMessage,
}) => {
  const state = {
    devices: [],
    idx: 0,
    stopScanner: null,
  };

  const toUiErrorMessage = (error) =>
    typeof mapError === "function" ? mapError(error) : toMessage(error);
  const setUiMessage = (text = "") => setMessage(message, text);
  const setUiState = (running) =>
    setState({
      running,
      btnStart,
      btnStop,
      btnSwitch,
      devices: state.devices,
    });

  const stop = () => {
    if (typeof state.stopScanner === "function") {
      state.stopScanner();
      state.stopScanner = null;
    }
    video.srcObject = null;
    setUiState(false);
  };

  const loadDevices = async () => {
    if (!navigator.mediaDevices?.enumerateDevices) {
      state.devices = [];
      return;
    }
    const list = await navigator.mediaDevices.enumerateDevices();
    state.devices = list.filter((device) => device.kind === "videoinput");
    if (state.devices.length && state.idx >= state.devices.length) state.idx = 0;
  };

  const start = async () => {
    setUiMessage("");

    if (!window.isSecureContext) {
      setUiMessage("Camera requires HTTPS (or localhost).");
      setUiState(false);
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      setUiMessage("Camera API not available in this browser context.");
      setUiState(false);
      return;
    }

    stop();
    await loadDevices();
    const deviceId = state.devices[state.idx]?.deviceId;
    const onError = (error) => setUiMessage(toUiErrorMessage(error));
    const onScannerResult = (text) => {
      const handler =
        typeof onScan === "function"
          ? onScan
          : (value) => handleScan({ text: value, onSuccess, settings, messageChannel });
      Promise.resolve(handler(text)).catch((error) => {
        setUiMessage(toUiErrorMessage(error));
      });
      return text;
    };

    try {
      state.stopScanner = await createQrScanner(video, onScannerResult, {
        deviceId,
        onError,
      });
    } catch (error) {
      const raw = String(error?.message || error || "");
      const shouldRetryWithoutDevice =
        !!deviceId && /notfounderror|overconstrained|video source/i.test(raw);
      if (!shouldRetryWithoutDevice) throw error;
      state.stopScanner = await createQrScanner(video, onScannerResult, { onError });
    }

    if (typeof state.stopScanner !== "function") {
      throw new Error("Failed to start camera.");
    }

    await loadDevices();
    setUiState(true);
  };

  const nextCamera = async () => {
    await loadDevices();
    if (state.devices.length < 2) return;
    state.idx = (state.idx + 1) % state.devices.length;
    await start();
  };

  return {
    start,
    stop,
    nextCamera,
    setUiMessage,
  };
};

export const relayIframeScanResult = async ({
  event,
  iframe,
  expectedOrigin,
  messageType,
  messageChannel,
  onSuccess,
  parentMessageType,
  parentTargetOrigin,
}) => {
  if (event.source !== iframe.contentWindow) return;
  // A sandboxed srcdoc iframe without allow-same-origin runs in an opaque
  // origin, which the browser reports as the literal string "null". The
  // authenticating check is the source comparison above (only the exact
  // embedded window passes); the origin check additionally pins the sender to
  // either the opaque scanner origin or the expected application origin.
  if (event.origin !== "null" && event.origin !== expectedOrigin) return;
  const data = event.data;
  if (!data || data.type !== messageType || data.channel !== messageChannel) return;

  const text = typeof data.text === "string" ? data.text.trim() : "";
  const result = await onSuccess.check(text);

  window.parent.postMessage(
    {
      type: parentMessageType,
      channel: messageChannel,
      text,
      result,
    },
    parentTargetOrigin
  );
};
