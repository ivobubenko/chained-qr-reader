import { pickSecurityEntry } from "../core/match_pattern_runner";
export async function createUiIframe(
  onSuccess,
  options = {
    scannerModuleUrls: [new URL("./secure-qr-scanner.es.js", import.meta.url).href],
    expectedOrigin: window.location.origin,
    parentTargetOrigin: "*",
    parentMessageType: "secure-qr-scan-result",
    iframeStyle:
      "width:100%;max-width:600px;min-height:360px;border:0;display:block;background:transparent;",
  }
) {
  if (typeof document === "undefined") throw new Error("Browser environment required");

  const iframe = document.createElement("iframe");

  const messageType = "secure-qr-scan";
  const messageChannel = Math.random().toString(36).slice(2);

  iframe.title = "QR Scanner";
  iframe.allow = "camera *; autoplay *";
  iframe.referrerPolicy = "no-referrer";
  iframe.loading = "eager";
  iframe.sandbox = "allow-scripts allow-same-origin";
  iframe.style.cssText = options.iframeStyle;

  iframe.srcdoc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover" />
<style>
  body{margin:0;padding:12px;font-family:sans-serif;display:flex;flex-direction:column;gap:10px;align-items:center}
  video{width:100%;max-width:600px;height:auto;background:#000;border-radius:8px}
  .c{display:flex;gap:8px;flex-wrap:wrap;justify-content:center}
  button{padding:10px 14px;border-radius:8px;border:1px solid #ddd;background:#fff}
  .m{margin:0;max-width:600px;font:12px/1.4 sans-serif;color:#d00;text-align:center;display:none}
</style>
</head>
<body>
  <video id="v" playsinline webkit-playsinline muted autoplay></video>
  <div class="c">
    <button id="sw" type="button">Switch camera</button>
    <button id="st" type="button">Start</button>
    <button id="sp" type="button" disabled>Stop</button>
  </div>
  <p class="m" id="m"></p>

<script type="module">
  const scannerModuleUrls = ${JSON.stringify(options.scannerModuleUrls)};
  const messageType = ${JSON.stringify(messageType)};
  const messageChannel = ${JSON.stringify(messageChannel)};
  const parentOrigin = ${JSON.stringify(options.expectedOrigin)};
  const video = document.getElementById("v");
  const btnSwitch = document.getElementById("sw");
  const btnStart = document.getElementById("st");
  const btnStop = document.getElementById("sp");
  const message = document.getElementById("m");

  const setMessage = (text = "") => {
    const value = String(text || "").trim();
    message.textContent = value;
    message.style.display = value ? "block" : "none";
  };

  const toMessage = (error) => {
    const raw = String(error?.message || error || "").trim();
    const msg = raw || "Failed to start camera.";
    if (/notallowederror|permission/i.test(msg)) {
      return "Camera permission denied. Allow camera access in the browser and iframe settings.";
    }
    if (/notfounderror|no camera|videoinput/i.test(msg)) {
      return "No camera found on this device.";
    }
    if (/secure context|https|insecure/i.test(msg)) {
      return "Camera requires HTTPS (or localhost).";
    }
    return msg;
  };

  let createQrScanner = null;
  let moduleLoadError = null;
  for (const url of scannerModuleUrls) {
    try {
      const mod = await import(url);
      if (typeof mod?.createQrScanner === "function") {
        createQrScanner = mod.createQrScanner;
        break;
      }
    } catch (error) {
      moduleLoadError = error;
    }
  }
  if (typeof createQrScanner !== "function") {
    setMessage(moduleLoadError ? toMessage(moduleLoadError) : "Scanner module failed to load.");
  }

  let devices = [];
  let idx = 0;
  let stopScanner = null;

  const setState = (running) => {
    btnStart.disabled = running;
    btnStop.disabled = !running;
    btnSwitch.disabled = devices.length < 2;
  };

  const stop = () => {
    if (typeof stopScanner === "function") {
      stopScanner();
      stopScanner = null;
    }
    video.srcObject = null;
    setState(false);
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

  const start = async () => {
    setMessage("");
    if (typeof createQrScanner !== "function") {
      setMessage(moduleLoadError ? toMessage(moduleLoadError) : "Scanner module unavailable.");
      setState(false);
      return;
    }
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
    const onScan = (text) => {
      window.parent.postMessage({ type: messageType, channel: messageChannel, text }, parentOrigin);
      return text;
    };
    const onError = (error) => setMessage(toMessage(error));

    try {
      stopScanner = await createQrScanner(video, onScan, {
        deviceId,
        onError,
      });
    } catch (error) {
      const raw = String(error?.message || error || "");
      const shouldRetryWithoutDevice =
        !!deviceId && /notfounderror|overconstrained|video source/i.test(raw);
      if (!shouldRetryWithoutDevice) throw error;
      stopScanner = await createQrScanner(video, onScan, { onError });
    }
    if (typeof stopScanner !== "function") {
      throw new Error("Failed to start camera.");
    }
    await loadDevices();
    setState(typeof stopScanner === "function");
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
</script>
</body>
</html>`;

  window.addEventListener("message", async (event) => {
    if (event.source !== iframe.contentWindow) return;
    if (event.origin !== options.expectedOrigin) return;
    const data = event.data;
    if (!data || data.type !== messageType || data.channel !== messageChannel) return;

    const text = typeof data.text === "string" ? data.text.trim() : "";

    const entry = pickSecurityEntry(onSuccess, text);
    const hasSecurityChain = entry === undefined ? false : true;
    const result = hasSecurityChain ? await entry.securityChain.with({ text }).run() : { text };

    window.parent.postMessage(
      { type: options.parentMessageType, channel: messageChannel, text, result },
      options.parentTargetOrigin
    );
  });
  return iframe;
}
