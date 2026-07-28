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
    if (typeof parsed?.exp === "number" && Array.isArray(parsed?.keys) && Date.now() < parsed.exp) {
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
// Select the candidate verification keys for a token.
// When the protected header carries a kid, exactly that key is used. When it does
// not, every key in the JWKS document is a candidate, because the verifier trusts
// the key set of the issuer origin as a whole. Returning all keys (rather than the
// first one) is what makes key rotation work: during the overlap window the set
// contains both the outgoing and the incoming key.
const selectKeys = (keys, kid) => {
  if (!Array.isArray(keys)) return [];
  if (kid) return keys.filter((k) => k.kid === kid);
  return keys;
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
const getPublicKeys = async (kid) => {
  const keys = await loadKeys();
  const candidates = selectKeys(keys, kid);
  if (!candidates.length) throw new Error("key_not_found");
  return Promise.all(candidates.map(importPublicKey));
};

const toBstr = (x) => Uint8Array.from(x);

// Read the kid from the COSE protected header (header parameter 4). It may be
// encoded as a byte string or as a text string; a header that cannot be decoded
// yields undefined, which falls back to trying the whole key set.
const tdKid = new TextDecoder();
const getKid = (protHdr) => {
  try {
    const bytes = toBstr(protHdr);
    if (!bytes.length) return undefined;
    const decoded = cborDecode(bytes);
    const raw = decoded instanceof Map ? decoded.get(4) : decoded?.[4];
    if (raw == null) return undefined;
    return typeof raw === "string" ? raw : tdKid.decode(toBstr(raw));
  } catch {
    return undefined;
  }
};

// Verify COSE signature using the Sig_structure.
const verifySignature = async (cose) => {
  const [protHdr, , payload, signature] = decodeSign1(cose);
  const sigStructure = ["Signature1", toBstr(protHdr), new Uint8Array(0), toBstr(payload)];
  const toSign = cborEncode(sigStructure);
  const sigP1363 = toBstr(signature);
  const publicKeys = await getPublicKeys(getKid(protHdr));
  for (const publicKey of publicKeys) {
    const response = await window.crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      publicKey,
      sigP1363,
      toSign
    );
    if (response) return 1;
  }
  return -1;
};

// Tolerance for a skewed device clock, in seconds.
const CLOCK_SKEW_S = 60;

// Temporal validity of the token. A valid signature says nothing about whether
// the token is still current, so exp and iat are checked separately and the
// reason is reported distinctly from a signature failure.
export const checkValidity = (payload, nowMs = Date.now()) => {
  const now = Math.floor(nowMs / 1000);
  const exp = payload?.exp;
  const iat = payload?.iat;
  if (typeof exp === "number" && now > exp + CLOCK_SKEW_S) return "token_expired";
  if (typeof iat === "number" && now + CLOCK_SKEW_S < iat) return "token_not_yet_valid";
  return null;
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
  const [, , payload] = decodeSign1(qr);
  const claims = getPayload(payload);
  const verified = await verifySignature(qr, JWKS_BASE);
  // A valid signature does not mean the token is still current.
  if (verified === 1) {
    const invalid = checkValidity(claims);
    if (invalid) return { verified: -1, reason: invalid, payload: claims };
  }
  return { verified, payload: claims };
};
