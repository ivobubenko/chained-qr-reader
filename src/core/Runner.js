export default class Runner {
  constructor() {
    this._steps = [];
    this._base = {};
    this._previousResult = {};
  }
  // Add a step to the pipeline with optional static context overrides.
  execute(fn, options = {}) {
    if (typeof fn !== "function") throw new TypeError("step must be a function");
    this._steps.push({ fn, options });
    return this;
  }
  end() {
    return this.toString();
  }
  with(vars = {}) {
    this._base = { ...this._base, ...vars };
    return this;
  }
  // Execute steps sequentially, merging object results into the context.
  async run() {
    let ctx = { ...this._base };
    let prev;
    for (const { fn, options } of this._steps) {
      const state = { ...ctx, ...options, prev };
      const out = await Promise.resolve(fn(state));
      prev = out;
      if (out && typeof out === "object") ctx = { ...ctx, ...out };
    }
    return ctx;
  }
}
