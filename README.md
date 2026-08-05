# Secure QR Scanner

Browser library for scanning QR codes and verifying signed payloads.

## Install

```
@ivobubenko:registry=https://npm.pkg.github.com
```

```
npm install @ivobubenko/chained-qr-reader
```

## Quick usage

```
import { createQrScanner } from "@ivobubenko/chained-qr-reader";

const stop = await createQrScanner(videoEl, (text) => {
  console.log("QR:", text);
});
```

```
import { readCoseContent } from "@ivobubenko/chained-qr-reader";

const { verified, payload } = await readCoseContent({
  text,
  jwkBase: "https://issuer.example.com/",
});
```

## Notes

- Camera access requires `https://` or `http://localhost`.
- Call `createQrScanner` from a user action (click/tap) to trigger permissions.

## API

- `createQrScanner(videoEl, onSuccess, options)`
- `readCoseContent({ text, jwkBase })`
- `FunctionChainer`
- `preventXss(value)`
- `createUiIframe(onSuccess, options)`
- `createUiDiv(onSuccess, options)`

## Verification result

`readCoseContent` returns `{ verified, payload, reason }`.

| `verified` | Meaning |
|---|---|
| `1` | Signature verified against the trusted key set and the token is within its validity window |
| `-1` | Signature could not be verified, or the token is outside its validity window |
| `0` | Content was scanned but is not a signed payload |

When a token is rejected on temporal grounds, `reason` is `token_expired` or
`token_not_yet_valid`. Verification tolerates 60 seconds of device clock skew.

Key selection follows the `kid` header parameter of the COSE protected header.
When a token carries no `kid`, every key in the JWKS document is tried, so a
token remains verifiable during a key rotation overlap window.

## Tests

```
npm ci
npm test
```

`tests/security.test.js` contains the adversarial test cases reported in the
Security Analysis section of the accompanying manuscript: unknown and rotated
keys, expired and not-yet-valid tokens, and an unavailable JWKS endpoint.

## Environment

Developed and tested with **Node.js v22.22.3**. Dependencies are pinned in
`package-lock.json`.
