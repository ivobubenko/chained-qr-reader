import { inflate } from "pako";
import { decode as cborDecode, encode as cborEncode } from "cbor-x";

// Simple in-memory JWKS cache (optionally backed by localStorage).
let cache = { exp: 0, keys: [] };
const CACHE_TTL_MS = 60 * 60 * 1000;
const STORAGE_PREFIX = "secure-qr:jwks:";
const getStorage = () => {
  try {
    return typeof localStorage !== "undefined" ? localStorage : null;
  } catch {
    return null;
  }
};
const getCacheKey = (base) => `${STORAGE_PREFIX}${base || ""}`;
const readPersistentCache = (base) => {
  const storage = getStorage();
  if (!storage) return null;
  const raw = storage.getItem(getCacheKey(base));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (
      typeof parsed?.exp === "number" &&
      Array.isArray(parsed?.keys) &&
      Date.now() < parsed.exp
    ) {
      return parsed;
    }
  } catch {
    return null;
  }
  return null;
};
const writePersistentCache = (base, nextCache) => {
  const storage = getStorage();
  if (!storage) return;
  try {
    storage.setItem(getCacheKey(base), JSON.stringify(nextCache));
  } catch {
    // Ignore storage failures (quota/blocked).
  }
};
const pickKey = (keys, kid) => {
  if (kid) return keys.find((k) => k.kid === kid);
  const pref = keys.find((k) => (k.alg || "").startsWith("PS")) || keys[0];
  return pref;
};

let JWKS_BASE;
// Fetch and cache keys from the configured JWKS base URL.
const loadKeys = async () => {
  if (!JWKS_BASE) throw new Error("JWKS_BASE missing");
  if (Date.now() < cache.exp && cache.keys.length) return cache.keys;
  const persisted = readPersistentCache(JWKS_BASE);
  if (persisted?.keys?.length) {
    cache = { exp: persisted.exp, keys: persisted.keys };
    return cache.keys;
  }
  const res = await fetch(`${JWKS_BASE}.well-known/jwks.json`);
  if (!res.ok) throw new Error(`jwks_http_${res.status}`);
  const { keys } = await res.json();
  // TTL -> TO BE DONE
  cache = {
    exp: Date.now() + CACHE_TTL_MS,
    keys: Array.isArray(keys) ? keys : [],
  };
  writePersistentCache(JWKS_BASE, cache);
  return cache.keys;
};

// Decode a QR1: prefix payload into a COSE_Sign1 structure.
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
// Verify COSE signature using the Sig_structure.
const verifySignature = async (cose) => {
  const [protHdr, , payload, signature] = decodeSign1(cose);
  const sigStructure = ["Signature1", toBstr(protHdr), new Uint8Array(0), toBstr(payload)];
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
// Parse payload claims and map app/org fields into a flat object.
export const getPayload = (payload) => {
  const payloadClaims = cborDecode(payload);
  const app = pick(payloadClaims, -70000) || {};
  const org = pick(payloadClaims, -70010) || {};
  const type = pick(app, "t");
  const contentBytes = pick(app, "c");
  const content = contentBytes ? JSON.parse(td.decode(contentBytes)) : undefined;

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
