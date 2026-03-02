import { createQrScanner } from "../core/create_scanner.js";
import { pickSecurityEntry } from "../core/match_pattern_runner.js";

const defaultOptions = {
  parentTargetOrigin: "*",
  parentMessageType: "secure-qr-scan-result",
  containerStyle:
    "width:100%;max-width:600px;display:flex;flex-direction:column;gap:10px;align-items:center;",
  videoStyle: "width:100%;max-width:600px;height:auto;background:#000;border-radius:8px;",
  controlsStyle: "display:flex;gap:8px;flex-wrap:wrap;justify-content:center;",
  buttonStyle: "padding:10px 14px;border-radius:8px;border:1px solid #ddd;background:#fff;",
  messageStyle:
    "margin:0;max-width:600px;font:12px/1.4 sans-serif;color:#d00;text-align:center;display:none;",
};

export async function createUiDiv(onSuccess, options = {}) {
  if (typeof document === "undefined") throw new Error("Browser environment required");
  const settings = { ...defaultOptions, ...(options || {}) };

  const messageChannel = Math.random().toString(36).slice(2);

  const container = document.createElement("div");
  container.style.cssText = settings.containerStyle;

  const video = document.createElement("video");
  video.playsInline = true;
  video.autoplay = true;
  video.muted = true;
  video.setAttribute("webkit-playsinline", "");
  video.style.cssText = settings.videoStyle;

  const controls = document.createElement("div");
  controls.style.cssText = settings.controlsStyle;

  const btnSwitch = document.createElement("button");
  btnSwitch.type = "button";
  btnSwitch.textContent = "Switch camera";
  btnSwitch.style.cssText = settings.buttonStyle;

  const btnStart = document.createElement("button");
  btnStart.type = "button";
  btnStart.textContent = "Start";
  btnStart.style.cssText = settings.buttonStyle;

  const btnStop = document.createElement("button");
  btnStop.type = "button";
  btnStop.textContent = "Stop";
  btnStop.style.cssText = settings.buttonStyle;

  const message = document.createElement("p");
  message.style.cssText = settings.messageStyle;

  controls.append(btnSwitch, btnStart, btnStop);
  container.append(video, controls, message);

  let devices = [];
  let idx = 0;
  let stopScanner = null;

  const setMessage = (text = "") => {
    const value = String(text || "").trim();
    message.textContent = value;
    message.style.display = value ? "block" : "none";
  };

  const setState = (running) => {
    btnStart.disabled = running;
    btnStop.disabled = !running;
    btnSwitch.disabled = devices.length < 2;
  };

  const toMessage = (error) => {
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

  const loadDevices = async () => {
    if (!navigator.mediaDevices?.enumerateDevices) {
      devices = [];
      return;
    }
    const list = await navigator.mediaDevices.enumerateDevices();
    devices = list.filter((d) => d.kind === "videoinput");
    if (devices.length && idx >= devices.length) idx = 0;
  };

  const stop = () => {
    if (typeof stopScanner === "function") {
      stopScanner();
      stopScanner = null;
    }
    video.srcObject = null;
    setState(false);
  };

  const handleScan = async (text) => {
    const value = typeof text === "string" ? text.trim() : "";
    const entry = pickSecurityEntry(onSuccess, value);
    const hasSecurityChain = entry === undefined ? false : true;
    const result = hasSecurityChain
      ? await entry.securityChain.with({ text: value }).run()
      : { text: value };

    window.parent.postMessage(
      { type: settings.parentMessageType, channel: messageChannel, text: value, result },
      settings.parentTargetOrigin
    );
  };

  const start = async () => {
    setMessage("");

    if (!window.isSecureContext) {
      setMessage("Camera requires HTTPS (or localhost).");
      setState(false);
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      setMessage("Camera API not available in this browser context.");
      setState(false);
      return;
    }

    stop();
    await loadDevices();
    const deviceId = devices[idx]?.deviceId;
    const onError = (error) => setMessage(toMessage(error));

    try {
      stopScanner = await createQrScanner(
        video,
        (text) => {
          handleScan(text).catch((error) => {
            setMessage(toMessage(error));
          });
          return text;
        },
        {
          deviceId,
          onError,
        }
      );
    } catch (error) {
      const raw = String(error?.message || error || "");
      const shouldRetryWithoutDevice =
        !!deviceId && /notfounderror|overconstrained|video source/i.test(raw);
      if (!shouldRetryWithoutDevice) throw error;
      stopScanner = await createQrScanner(
        video,
        (text) => {
          handleScan(text).catch((handleError) => {
            setMessage(toMessage(handleError));
          });
          return text;
        },
        { onError }
      );
    }

    if (typeof stopScanner !== "function") {
      throw new Error("Failed to start camera.");
    }

    await loadDevices();
    setState(true);
  };

  const nextCamera = async () => {
    await loadDevices();
    if (devices.length < 2) return;
    idx = (idx + 1) % devices.length;
    await start();
  };

  btnStart.addEventListener("click", () =>
    start().catch((error) => {
      setMessage(toMessage(error));
      setState(false);
    })
  );
  btnStop.addEventListener("click", () => stop());
  btnSwitch.addEventListener("click", () =>
    nextCamera().catch((error) => {
      setMessage(toMessage(error));
      setState(false);
    })
  );

  setState(false);
  container.stop = stop;
  return container;
}
