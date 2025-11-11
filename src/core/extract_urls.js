export function extractUrls(text) {
  if (typeof text !== "string") return [];

  // RFC-3986-ish pattern for http/https URLs
  const urlPattern = /\bhttps?:\/\/(?:[^\s()<>]+|\((?:[^\s()<>]+|\([^)]*\))*\))+/gi;

  const seen = new Set();
  const urls = [];

  for (const match of text.matchAll(urlPattern)) {
    const url = match[0];
    if (!seen.has(url)) {
      seen.add(url);
      urls.push(url);
    }
  }
  return urls;
}
