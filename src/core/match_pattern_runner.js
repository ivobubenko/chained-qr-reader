// Match a string prefix or a regex anchored at the start of the text.
const startsWithPattern = (pattern, text) => {
  const s = String(text ?? "");
  if (typeof pattern === "string") return s.startsWith(pattern);
  if (pattern instanceof RegExp) {
    const f = pattern.flags.replace(/g/g, "");
    return new RegExp("^" + pattern.source, f).test(s);
  }
  return false;
};

// Select the first entry whose pattern matches the incoming text prefix.
export const pickSecurityEntry = (entries, text) =>
  entries?.find((e) => startsWithPattern(e.pattern, text));
