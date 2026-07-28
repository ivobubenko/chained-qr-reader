// Adversarial test cases for the browser-side verifier, matching the security
// test matrix in the manuscript revision: S5 (unknown key), S6 (rotated key),
// S7 (expired token), S8 (not-yet-valid token), S12 (JWKS unavailable).

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

  it("accepts a valid, current token", async () => {
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

  it("rejects a token whose signature does not verify", async () => {
    stubEnvironment({ verifyFor: () => false });
    const verifier = await loadVerifier();
    const result = await read(verifier, buildToken());
    expect(result.verified).toBe(-1);
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
