const HTML_ESCAPE_MAP = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "`": "&#96;",
};

const HTML_ESCAPE_REGEX = /[&<>"'`]/g;

export function preventXss(value = "") {
  return String(JSON.stringify(value)).replace(HTML_ESCAPE_REGEX, (char) => HTML_ESCAPE_MAP[char]);
}
