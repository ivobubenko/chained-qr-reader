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
- `pickSecurityEntry(entries, text)`
- `Runner`
