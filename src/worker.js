import { sanitizeContent } from "./core/sanatize_content";
import { basicUrlChecks } from "./core/check_url";
import { extractUrls } from "./core/extract_urls";
console.log(sanitizeContent);

self.onmessage = (event) => {
  console.log("[Worker] Received message:", event.data);
  const purified = sanitizeContent(event.data);
  const urls = extractUrls(purified);
  console.log(urls);

  self.postMessage(purified);
};
