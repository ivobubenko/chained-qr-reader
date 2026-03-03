import Runner from "./Runner.js";
export class FunctionChainer {
  _securityChain;
  constructor(
    options = [
      {
        pattern: "",
        functions: [],
      },
    ]
  ) {
    const securityChain = [];
    for (const option of options) {
      const runner = new Runner();
      for (const fn of option.functions) {
        runner.execute(fn.fn, fn.context);
      }
      securityChain.push({ pattern: option.pattern, securityChain: runner });
    }
    this._securityChain = securityChain;
  }

  pickSecurityEntry(value) {
    const text = String(value ?? "");
    return this._securityChain?.find(({ pattern }) => {
      if (typeof pattern === "string") return pattern === "" || text.startsWith(pattern);
      if (pattern instanceof RegExp) return pattern.test(text);
      return false;
    });
  }

  async check(text) {
    const value = typeof text === "string" ? text.trim() : "";
    const entry = this.pickSecurityEntry(value);
    if (!entry) return { text: value };
    return await entry.securityChain.with({ text: value }).run();
  }
}
