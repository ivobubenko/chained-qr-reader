// Adversarial test cases for the browser-side verifier, matching the security
// test matrix in the manuscript revision: S1 (valid token), S2 (modified
// payload / invalid signature), S3 (unsigned payload), S4 (malformed token),
// S5 (unknown key), S6 (rotated key), S7 (expired token), S8 (not-yet-valid
// token), S10 (iframe sandbox configuration), S11 (postMessage abuse),
// S12 (JWKS unavailable). S9 (malicious HTML/script content) is covered by the
// preventXss output-escaping tests in core.test.js.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deflate } from "pako";
import { encode as cborEncode } from "cbor-x";

const toBase64Url = (u8) =>
  Buffer.from(u8).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

const ensureBase64Helpers = () => {
  if (typeof Uint8Array.fromBase64 === "function") return;
  Uint8Array.fromBase64 = (input, { alphabet } = {}) => {
    let base64 = String(input);
    if (alphabet === "base64url") {
      base64 = base64.replace(/-/g, "+").replace(/_/g, "/");
      const pad = base64.length % 4;
      if (pad) base64 = base64 + "=".repeat(4 - pad);
    }
    return Uint8Array.from(Buffer.from(base64, "base64"));
  };
};

const NOW_S = Math.floor(Date.now() / 1000);
const KEY_A = { kid: "key-a", kty: "EC", crv: "P-256", x: "xa", y: "ya", alg: "ES256" };
const KEY_B = { kid: "key-b", kty: "EC", crv: "P-256", x: "xb", y: "yb", alg: "ES256" };

// Builds a QR1 token with a real CBOR protected header, so kid is parseable.
const buildToken = ({ kid, iat = NOW_S - 60, exp = NOW_S + 3600 } = {}) => {
  const header = new Map([[1, -7]]);
  if (kid !== undefined) header.set(4, kid);

  const claims = new Map([
    [1, "https://issuer.example/"],
    [4, exp],
    [6, iat],
    [7, new Uint8Array([0x0a, 0x0b])],
    [
      -70000,
      new Map([
        ["t", "txt"],
        ["c", new TextEncoder().encode(JSON.stringify({ ok: true }))],
      ]),
    ],
  ]);

  const cose = [cborEncode(header), {}, cborEncode(claims), new Uint8Array(64)];
  return `QR1:${toBase64Url(deflate(cborEncode(cose)))}`;
};

// Each test gets a fresh module instance, because the JWKS cache is module state.
const loadVerifier = async () => {
  vi.resetModules();
  return import("../src/core/functions/check_signature.js");
};

// verifyFor decides which JWK counts as the correct signer for this test run.
const stubEnvironment = ({ keys = [KEY_A], jwksOk = true, verifyFor = () => true } = {}) => {
  const subtle = {
    importKey: vi.fn(async (_fmt, jwk) => jwk),
    verify: vi.fn(async (_alg, key) => verifyFor(key)),
  };
  vi.stubGlobal("crypto", { subtle });
  vi.stubGlobal("window", { crypto: { subtle } });
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      jwksOk
        ? { ok: true, status: 200, json: async () => ({ keys }) }
        : { ok: false, status: 500, json: async () => ({}) }
    )
  );
};

const read = async (verifier, text) =>
  verifier.readCoseContent({ text, jwkBase: "https://issuer.example/" });

describe("verifier security behaviour", () => {
  beforeEach(() => ensureBase64Helpers());
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  // S1 — the baseline positive case.
  it("S1 accepts a valid, current token", async () => {
    stubEnvironment();
    const verifier = await loadVerifier();
    const result = await read(verifier, buildToken());
    expect(result.verified).toBe(1);
  });

  // S7 — a valid signature does not make an expired token acceptable.
  it("S7 rejects an expired token and says why", async () => {
    stubEnvironment();
    const verifier = await loadVerifier();
    const result = await read(verifier, buildToken({ exp: NOW_S - 3600 }));
    expect(result.verified).toBe(-1);
    expect(result.reason).toBe("token_expired");
  });

  // S8 — a token issued in the future is not yet usable.
  it("S8 rejects a not-yet-valid token", async () => {
    stubEnvironment();
    const verifier = await loadVerifier();
    const result = await read(verifier, buildToken({ iat: NOW_S + 3600, exp: NOW_S + 7200 }));
    expect(result.verified).toBe(-1);
    expect(result.reason).toBe("token_not_yet_valid");
  });

  // S5 — a kid absent from the JWKS document must not fall back to another key.
  it("S5 rejects a token whose kid is not in the JWKS document", async () => {
    stubEnvironment({ keys: [KEY_A, KEY_B] });
    const verifier = await loadVerifier();
    await expect(read(verifier, buildToken({ kid: "key-unknown" }))).rejects.toThrow(
      "key_not_found"
    );
  });

  // S6 — during rotation the JWKS document holds both keys, and a token signed
  // by the second one must verify. Before the fix only the first key was tried.
  it("S6 verifies a token signed by the second key in the JWKS document", async () => {
    stubEnvironment({ keys: [KEY_A, KEY_B], verifyFor: (key) => key.kid === "key-b" });
    const verifier = await loadVerifier();
    const result = await read(verifier, buildToken({ kid: "key-b" }));
    expect(result.verified).toBe(1);
  });

  it("S6 also verifies during rotation when the token carries no kid", async () => {
    stubEnvironment({ keys: [KEY_A, KEY_B], verifyFor: (key) => key.kid === "key-b" });
    const verifier = await loadVerifier();
    const result = await read(verifier, buildToken());
    expect(result.verified).toBe(1);
  });

  // S12 — an unreachable key endpoint must reject, not degrade into acceptance.
  it("S12 fails closed when the JWKS endpoint is unavailable", async () => {
    stubEnvironment({ jwksOk: false });
    const verifier = await loadVerifier();
    await expect(read(verifier, buildToken())).rejects.toThrow("jwks_http_500");
  });

  // S2 — a payload whose signed bytes were modified after signing must fail
  // signature verification.
  it("S2 rejects a token whose signature does not verify", async () => {
    stubEnvironment({ verifyFor: () => false });
    const verifier = await loadVerifier();
    const result = await read(verifier, buildToken());
    expect(result.verified).toBe(-1);
  });

  // S3 — plain unsigned content must not enter the COSE verification path.
  it("S3 rejects an unsigned payload without the QR1 prefix", async () => {
    stubEnvironment();
    const verifier = await loadVerifier();
    await expect(read(verifier, "https://example.com/plain-unsigned")).rejects.toThrow(
      "Could not decode QR"
    );
  });

  // S4 — a structurally broken token (truncated / corrupted encoding) must be
  // rejected with a decode error, not partially processed.
  it("S4 rejects a malformed or truncated token", async () => {
    stubEnvironment();
    const verifier = await loadVerifier();
    const truncated = buildToken().slice(0, 40);
    await expect(read(verifier, truncated)).rejects.toThrow();
    await expect(read(verifier, "QR1:!!!not-base64url!!!")).rejects.toThrow();
  });
});

describe("iframe isolation and postMessage contract", () => {
  beforeEach(() => ensureBase64Helpers());
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  const loadUi = async () => {
    vi.resetModules();
    return import("../src/ui/functions.js");
  };

  const makeRelayArgs = (overrides = {}) => {
    const contentWindow = {};
    const posted = [];
    vi.stubGlobal("window", {
      parent: { postMessage: (msg, origin) => posted.push({ msg, origin }) },
      location: { origin: "https://app.example" },
    });
    const check = vi.fn(async (text) => ({ verified: 1, text }));
    return {
      posted,
      check,
      args: {
        event: {
          source: contentWindow,
          origin: "null",
          data: { type: "secure-qr-scan", channel: "chan1", text: "QR1:abc" },
        },
        iframe: { contentWindow },
        expectedOrigin: "https://app.example",
        messageType: "secure-qr-scan",
        messageChannel: "chan1",
        onSuccess: { check },
        parentMessageType: "secure-qr-scan-result",
        parentTargetOrigin: "https://app.example",
        ...overrides,
      },
    };
  };

  // S10 — the scanner iframe must not combine allow-scripts with
  // allow-same-origin, so the scanner runs in an opaque origin.
  it("S10 configures the sandbox without allow-same-origin", async () => {
    const iframeStub = { style: {}, addEventListener: vi.fn() };
    vi.stubGlobal("document", { createElement: vi.fn(() => iframeStub) });
    vi.stubGlobal("window", {
      addEventListener: vi.fn(),
      location: { origin: "https://app.example" },
    });
    vi.resetModules();
    const { createUiIframe } = await import("../src/ui/iframe.js");
    const iframe = await createUiIframe({ check: async () => ({}) });
    expect(iframe.sandbox).toBe("allow-scripts");
    expect(iframe.sandbox).not.toContain("allow-same-origin");
  });

  // S11 — messages that do not come from the embedded scanner window, or that
  // carry a foreign origin, type, or channel, must be ignored.
  it("S11 ignores postMessage events from a foreign window", async () => {
    const { relayIframeScanResult } = await loadUi();
    const { posted, check, args } = makeRelayArgs();
    await relayIframeScanResult({ ...args, event: { ...args.event, source: {} } });
    expect(check).not.toHaveBeenCalled();
    expect(posted).toHaveLength(0);
  });

  it("S11 ignores postMessage events from a foreign origin", async () => {
    const { relayIframeScanResult } = await loadUi();
    const { posted, check, args } = makeRelayArgs();
    await relayIframeScanResult({
      ...args,
      event: { ...args.event, origin: "https://attacker.example" },
    });
    expect(check).not.toHaveBeenCalled();
    expect(posted).toHaveLength(0);
  });

  it("S11 ignores postMessage events with a wrong type or channel", async () => {
    const { relayIframeScanResult } = await loadUi();
    const { posted, check, args } = makeRelayArgs();
    await relayIframeScanResult({
      ...args,
      event: { ...args.event, data: { ...args.event.data, channel: "other" } },
    });
    await relayIframeScanResult({
      ...args,
      event: { ...args.event, data: { ...args.event.data, type: "other" } },
    });
    expect(check).not.toHaveBeenCalled();
    expect(posted).toHaveLength(0);
  });

  it("relays a valid scanner message from the opaque origin", async () => {
    const { relayIframeScanResult } = await loadUi();
    const { posted, check, args } = makeRelayArgs();
    await relayIframeScanResult(args);
    expect(check).toHaveBeenCalledWith("QR1:abc");
    expect(posted).toHaveLength(1);
    expect(posted[0].msg.type).toBe("secure-qr-scan-result");
  });
});

describe("checkValidity", () => {
  it("tolerates a modestly skewed device clock", async () => {
    const verifier = await loadVerifier();
    const payload = { iat: NOW_S, exp: NOW_S + 10 };
    expect(verifier.checkValidity(payload, (NOW_S + 40) * 1000)).toBeNull();
    expect(verifier.checkValidity(payload, (NOW_S + 130) * 1000)).toBe("token_expired");
  });
});
