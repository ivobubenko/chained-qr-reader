import { createIframeSrcdoc } from "./iframeHtmlTemplate.js";
import { relayIframeScanResult } from "./functions.js";

const defaultOptions = {
  scannerModuleUrls: [new URL("./secure-qr-scanner.es.js", import.meta.url).href],
  parentTargetOrigin: "*",
  parentMessageType: "secure-qr-scan-result",
  iframeStyle:
    "width:100%;max-width:600px;min-height:360px;border:0;display:block;background:transparent;",
};

export async function createUiIframe(onSuccess, options = {}) {
  if (typeof document === "undefined") throw new Error("Browser environment required");
  const settings = { ...defaultOptions, ...(options || {}) };
  const expectedOrigin =
    typeof settings.expectedOrigin === "string" && settings.expectedOrigin.trim()
      ? settings.expectedOrigin
      : window.location.origin;

  const iframe = document.createElement("iframe");

  const messageType = "secure-qr-scan";
  const messageChannel = Math.random().toString(36).slice(2);

  iframe.title = "QR Scanner";
  iframe.allow = "camera *; autoplay *";
  iframe.referrerPolicy = "no-referrer";
  iframe.loading = "eager";
  iframe.sandbox = "allow-scripts allow-same-origin";
  iframe.style.cssText = settings.iframeStyle;

  iframe.srcdoc = createIframeSrcdoc({
    scannerModuleUrls: settings.scannerModuleUrls,
    messageType,
    messageChannel,
    expectedOrigin,
  });

  window.addEventListener("message", async (event) => {
    await relayIframeScanResult({
      event,
      iframe,
      expectedOrigin,
      messageType,
      messageChannel,
      onSuccess,
      parentMessageType: settings.parentMessageType,
      parentTargetOrigin: settings.parentTargetOrigin,
    });
  });

  return iframe;
}
