// End-to-end interoperability with the signing service.
//
// The signing service encodes CBOR with a different library than this verifier
// uses. Two defects were found this way and this test guards both:
//
//   1. The Sig_structure must be re-encoded exactly as the signer produced it.
//      By default cbor-x wraps a Uint8Array in tag 64, a cbor-x extension, while
//      the signer emits a plain CBOR byte string. The re-encoded structure then
//      differs from the signed bytes and no signature verifies.
//
//   2. The kid in the COSE protected header must match the kid published in the
//      JWKS document, which is the base64url encoding of the SHA-256 digest of
//      the SPKI public key.
//
// The token below is therefore built the way the signing service builds it:
// plain byte strings, kid as the UTF-8 bytes of the published identifier, and a
// real ECDSA P-256 signature in IEEE P1363 form.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import crypto from "node:crypto";
import { deflate } from "pako";
import { Encoder } from "cbor-x";

// Plain byte strings, matching what the signing service emits.
const cbor = new Encoder({ tagUint8Array: false });

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

// DER to IEEE P1363, as the signing service does with the KMS response.
const derToP1363 = (der, size = 32) => {
  const b = Buffer.from(der);
  let i = 0;
  if (b[i++] !== 0x30) throw new Error("invalid DER");
  const len = () => {
    let l = b[i++];
    if (l & 0x80) {
      const n = l & 0x7f;
      l = 0;
      for (let k = 0; k < n; k++) l = (l << 8) | b[i++];
    }
    return l;
  };
  len();
  if (b[i++] !== 0x02) throw new Error("invalid r");
  const rLen = len();
  const r = b.subarray(i, (i += rLen));
  if (b[i++] !== 0x02) throw new Error("invalid s");
  const sLen = len();
  const s = b.subarray(i, (i += sLen));
  const strip = (x) => {
    let j = 0;
    while (j < x.length && x[j] === 0) j++;
    return x.subarray(j);
  };
  const pad = (x) => {
    const y = strip(x);
    if (y.length >= size) return y.subarray(y.length - size);
    const out = Buffer.alloc(size);
    y.copy(out, size - y.length);
    return out;
  };
  return new Uint8Array(Buffer.concat([pad(r), pad(s)]));
};

const buildServiceToken = ({ iat, exp } = {}) => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const der = publicKey.export({ format: "der", type: "spki" });

  // keys-publisher: kid is the base64url SHA-256 digest of the SPKI key.
  const publishedKid = crypto.createHash("sha256").update(der).digest("base64url");
  const jwk = crypto
    .createPublicKey({ key: der, format: "der", type: "spki" })
    .export({ format: "jwk" });
  const jwks = { keys: [{ ...jwk, kid: publishedKid, use: "sig", alg: "ES256" }] };

  const now = Math.floor(Date.now() / 1000);
  const claims = new Map([
    [1, "https://issuer.example"],
    [2, "TUKE_FEI"],
    [6, iat ?? now - 60],
    [4, exp ?? now + 3600],
    [7, crypto.getRandomValues(new Uint8Array(16))],
    [
      -70000,
      new Map([
        ["t", "txt"],
        ["c", new TextEncoder().encode(JSON.stringify("hello"))],
      ]),
    ],
    [
      -70010,
      new Map([
        ["id", "TUKE_FEI"],
        ["alias", "FEI"],
      ]),
    ],
  ]);

  const payloadBytes = cbor.encode(claims);
  const kid = new TextEncoder().encode(publishedKid);
  const protectedBytes = cbor.encode(new Map([[1, -7], [4, kid]]));
  const toSign = cbor.encode([
    "Signature1",
    new Uint8Array(protectedBytes),
    new Uint8Array(0),
    new Uint8Array(payloadBytes),
  ]);

  const sigDer = crypto.createSign("SHA256").update(toSign).sign({ key: privateKey });
  const signature = derToP1363(sigDer, 32);
  const cose = cbor.encode([
    new Uint8Array(protectedBytes),
    new Map(),
    new Uint8Array(payloadBytes),
    signature,
  ]);

  return { token: `QR1:${toBase64Url(deflate(cose))}`, jwks, publishedKid };
};

const loadVerifier = async () => {
  vi.resetModules();
  return import("../src/core/functions/check_signature.js");
};

describe("interoperability with the signing service", () => {
  beforeEach(() => {
    ensureBase64Helpers();
    vi.stubGlobal("window", { crypto: globalThis.crypto });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("verifies a token produced the way the signing service produces one", async () => {
    const { token, jwks } = buildServiceToken();
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, status: 200, json: async () => jwks })));

    const verifier = await loadVerifier();
    const result = await verifier.readCoseContent({
      text: token,
      jwkBase: "https://jwks.example/",
    });

    expect(result.verified).toBe(1);
    expect(result.payload.org).toEqual({ id: "TUKE_FEI", alias: "FEI" });
  });

  it("resolves the key by the kid published in the JWKS document", async () => {
    const { token, jwks, publishedKid } = buildServiceToken();
    // A decoy key precedes the correct one, so selecting the first key would fail.
    const decoy = { ...jwks.keys[0], kid: "some-other-key" };
    const withDecoy = { keys: [decoy, jwks.keys[0]] };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: true, status: 200, json: async () => withDecoy }))
    );

    const verifier = await loadVerifier();
    const result = await verifier.readCoseContent({
      text: token,
      jwkBase: "https://jwks.example/",
    });

    expect(publishedKid).not.toBe("some-other-key");
    expect(result.verified).toBe(1);
  });

  it("rejects a service token after its expiry", async () => {
    const now = Math.floor(Date.now() / 1000);
    const { token, jwks } = buildServiceToken({ iat: now - 7200, exp: now - 3600 });
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, status: 200, json: async () => jwks })));

    const verifier = await loadVerifier();
    const result = await verifier.readCoseContent({
      text: token,
      jwkBase: "https://jwks.example/",
    });

    expect(result.verified).toBe(-1);
    expect(result.reason).toBe("token_expired");
  });
});
