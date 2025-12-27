import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { pickSecurityEntry } from "../src/index.js";
import { readCoseContent, getPayload } from "../src/core/check_signature.js";
import { deflate } from "pako";
import { encode as cborEncode } from "cbor-x";

const toBase64Url = (u8) =>
  Buffer.from(u8)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

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

const buildQr1 = (payloadBytes) => {
  const cose = [new Uint8Array([0x01]), {}, payloadBytes, new Uint8Array([0x02])];
  const encoded = cborEncode(cose);
  const zipped = deflate(encoded);
  return `QR1:${toBase64Url(zipped)}`;
};

describe("pickSecurityEntry", () => {
  it("matches string and regex patterns", () => {
    const entries = [{ pattern: "ABC" }, { pattern: /^QR[0-9]/ }, { pattern: "XYZ" }];
    expect(pickSecurityEntry(entries, "QR1:payload")).toEqual(entries[1]);
    expect(pickSecurityEntry(entries, "ABC123")).toEqual(entries[0]);
    expect(pickSecurityEntry(entries, "none")).toBeUndefined();
  });
});

describe("check_signature", () => {
  beforeEach(() => {
    ensureBase64Helpers();
    const subtle = {
      importKey: vi.fn().mockResolvedValue({}),
      verify: vi.fn().mockResolvedValue(true),
    };
    vi.stubGlobal("crypto", { subtle });
    vi.stubGlobal("window", { crypto: { subtle } });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          keys: [{ kid: "1", kty: "EC", crv: "P-256", x: "x", y: "y", alg: "ES256" }],
        }),
      })
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("parses payload claims into a flat object", () => {
    const content = { foo: "bar" };
    const payloadClaims = new Map([
      [1, "issuer"],
      [2, "org-123"],
      [4, 1712345678],
      [6, 1712340000],
      [7, new Uint8Array([0x01, 0x02])],
      [
        -70000,
        new Map([
          ["t", "test"],
          ["c", new TextEncoder().encode(JSON.stringify(content))],
        ]),
      ],
      [-70010, new Map([["id", "org-123"], ["alias", "ORG"]])],
    ]);
    const payloadBytes = cborEncode(payloadClaims);
    const result = getPayload(payloadBytes);

    expect(result).toEqual({
      iss: "issuer",
      orgId: "org-123",
      iat: 1712340000,
      exp: 1712345678,
      jti: "0102",
      type: "test",
      content,
      org: { id: "org-123", alias: "ORG" },
    });
  });

  it("verifies and returns decoded payload from QR1 content", async () => {
    const payloadClaims = new Map([
      [1, "issuer"],
      [2, "org-123"],
      [4, 1712345678],
      [6, 1712340000],
      [7, new Uint8Array([0x0a, 0x0b])],
      [
        -70000,
        new Map([
          ["t", "test"],
          ["c", new TextEncoder().encode(JSON.stringify({ ok: true }))],
        ]),
      ],
      [-70010, new Map([["id", "org-123"], ["alias", "ORG"]])],
    ]);
    const payloadBytes = cborEncode(payloadClaims);
    const text = buildQr1(payloadBytes);

    const result = await readCoseContent({
      text,
      jwkBase: "https://issuer.example/",
    });

    expect(result.verified).toBe(1);
    expect(result.payload).toMatchObject({
      iss: "issuer",
      orgId: "org-123",
      type: "test",
      org: { id: "org-123", alias: "ORG" },
    });
  });
});
