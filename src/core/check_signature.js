import { inflate } from "pako";
import { decode as cborDecode, encode as cborEncode } from "cbor-x";

let cache = { exp: 0, keys: [] };
const pickKey = (keys, kid) => {
  if (kid) return keys.find((k) => k.kid === kid);
  const pref = keys.find((k) => (k.alg || "").startsWith("PS")) || keys[0];
  return pref;
};

let JWKS_BASE;
const loadKeys = async () => {
  if (!JWKS_BASE) throw new Error("JWKS_BASE missing");
  if (Date.now() < cache.exp && cache.keys.length) return cache.keys;
  const res = await fetch(`${JWKS_BASE}.well-known/jwks.json`);
  if (!res.ok) throw new Error(`jwks_http_${res.status}`);
  const { keys } = await res.json();
  // TTL -> TO BE DONE
  cache = {
    exp: Date.now() + 3600 * 1000,
    keys: Array.isArray(keys) ? keys : [],
  };
  return cache.keys;
};

const decodeSign1 = (cose) => {
  if (cose.startsWith("QR1:")) {
    const zipped = Uint8Array.fromBase64(cose.slice(4), {
      alphabet: "base64url",
    });
    let bytes = inflate(zipped);
    return cborDecode(bytes);
  } else {
    throw new Error("Could not decode QR");
  }
};
const importPublicKey = async (jwk) => {
  const algorithm = { name: "ECDSA", namedCurve: jwk.crv || "P-256" };
  return crypto.subtle.importKey("jwk", jwk, algorithm, true, ["verify"]);
};
const getPublicKey = async (kid) => {
  const keys = await loadKeys();
  const jwk = pickKey(keys, kid);
  if (!jwk) throw new Error("key_not_found");
  return importPublicKey(jwk);
};

const toBstr = (x) => Uint8Array.from(x);
const verifySignature = async (cose) => {
  const [protHdr, unprotHdr, payload, signature] = decodeSign1(cose);
  const sigStructure = [
    "Signature1",
    toBstr(protHdr),
    new Uint8Array(0),
    toBstr(payload),
  ];
  const toSign = cborEncode(sigStructure);
  const sigP1363 = toBstr(signature);
  const publicKey = await getPublicKey();
  const response = await window.crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    publicKey,
    sigP1363,
    toSign
  );
  return response ? 1 : -1;
};

const td = new TextDecoder();

const pick = (m, k) => (m instanceof Map ? m.get(k) : m?.[k]);
const toHex = (u8) =>
  u8 && u8.length != null
    ? [...u8].map((b) => b.toString(16).padStart(2, "0")).join("")
    : undefined;
export const getPayload = (payload) => {
  const payloadClaims = cborDecode(payload);
  const app = pick(payloadClaims, -70000) || {};
  const org = pick(payloadClaims, -70010) || {};
  const type = pick(app, "t");
  const contentBytes = pick(app, "c");
  const content = contentBytes
    ? JSON.parse(td.decode(contentBytes))
    : undefined;

  return {
    iss: pick(payloadClaims, 1),
    orgId: pick(payloadClaims, 2),
    iat: pick(payloadClaims, 6),
    exp: pick(payloadClaims, 4),
    jti: toHex(pick(payloadClaims, 7)),
    type,
    content,
    org: { id: pick(org, "id"), alias: pick(org, "alias") },
  };
};

export const readCoseContent = async (content) => {
  let { text, jwkBase } = content;
  JWKS_BASE = jwkBase;
  const qr = text;
  if (!verifySignature(qr)) throw new Error("Verify of QR code failed");
  const [, , payload] = decodeSign1(qr);
  const verified = await verifySignature(qr, JWKS_BASE);
  return { verified, payload: getPayload(payload) };
};
