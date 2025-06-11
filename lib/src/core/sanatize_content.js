import { filterXSS } from "xss";

export function sanitizeContent(rawInputString) {
  if (typeof rawInputString !== "string") {
    throw new TypeError("sanitizeContent expects a string input");
  }

  let canonicalString = rawInputString
    .normalize("NFC")
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");

  if (/^\w+:/i.test(canonicalString) && !/^https?:/i.test(canonicalString)) {
    throw new Error("Refused URL scheme");
  }

  const xssSafeString = filterXSS(canonicalString, { whiteList: {} });

  return xssSafeString.trim();
}
