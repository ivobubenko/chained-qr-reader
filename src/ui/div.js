import { createScannerHandlers, toMessage } from "./functions.js";

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

  const { start, stop, nextCamera, setUiMessage } = createScannerHandlers({
    video,
    message,
    btnStart,
    btnStop,
    btnSwitch,
    onSuccess,
    settings,
    messageChannel,
  });

  const handleError = (error) => {
    setUiMessage(toMessage(error));
    stop();
  };

  btnStart.addEventListener("click", () => start().catch(handleError));
  btnStop.addEventListener("click", () => stop());
  btnSwitch.addEventListener("click", () => nextCamera().catch(handleError));

  stop();
  container.stop = stop;
  return container;
}
