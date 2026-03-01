import { pickSecurityEntry } from "../core/match_pattern_runner";
export async function createUiIframe(
  onSuccess,
  options = {
    scannerModuleUrls: [
      new URL("./secure-qr-scanner.es.js", import.meta.url).href,
      new URL("../index.js", import.meta.url).href,
    ],
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
  iframe.allow = "camera; autoplay";
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
</style>
</head>
<body>
  <video id="v" playsinline webkit-playsinline muted autoplay></video>
  <div class="c">
    <button id="sw" type="button">Switch camera</button>
    <button id="st" type="button">Start</button>
    <button id="sp" type="button" disabled>Stop</button>
  </div>

<script type="module">
  const scannerModuleUrls = ${JSON.stringify(options.scannerModuleUrls)};
  const messageType = ${JSON.stringify(messageType)};
  const messageChannel = ${JSON.stringify(messageChannel)};
  const parentOrigin = ${JSON.stringify(options.expectedOrigin)};
  const video = document.getElementById("v");
  const btnSwitch = document.getElementById("sw");
  const btnStart = document.getElementById("st");
  const btnStop = document.getElementById("sp");

  let createQrScanner = null;
  for (const url of scannerModuleUrls) {
    try {
      const mod = await import(url);
      if (typeof mod?.createQrScanner === "function") {
        createQrScanner = mod.createQrScanner;
        break;
      }
    } catch {}
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
    const list = await navigator.mediaDevices.enumerateDevices();
    devices = list.filter((d) => d.kind === "videoinput");
    if (devices.length && idx >= devices.length) idx = 0;
  };

  const start = async () => {
    if (typeof createQrScanner !== "function") {
      setState(false);
      return;
    }
    stop();
    await loadDevices();
    const deviceId = devices[idx]?.deviceId;
    stopScanner = await createQrScanner(
      video,
      (text) => {
        window.parent.postMessage({ type: messageType, channel: messageChannel, text }, parentOrigin);
        return text;
      },
      { deviceId }
    );
    await loadDevices();
    setState(typeof stopScanner === "function");
  };

  const nextCamera = async () => {
    await loadDevices();
    if (devices.length < 2) return;
    idx = (idx + 1) % devices.length;
    await start();
  };

  btnStart.addEventListener("click", () => start().catch(() => setState(false)));
  btnStop.addEventListener("click", () => stop());
  btnSwitch.addEventListener("click", () => nextCamera().catch(() => {}));

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
