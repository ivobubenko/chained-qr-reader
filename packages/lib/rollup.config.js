import resolve from "rollup-plugin-node-resolve";
import commonjs from "rollup-plugin-commonjs";
import webWorkerLoader from "rollup-plugin-web-worker-loader";

export default {
  input: "src/index.js",
  external: ["@zxing/browser/readers"],
  plugins: [resolve(), commonjs(), webWorkerLoader()],
  output: [
    {
      file: "dist/secure-qr-scanner.es.js",
      format: "es",
    },
    {
      file: "dist/secure-qr-scanner.umd.js",
      format: "umd",
      name: "SecureQrScanner",
      globals: {
        "@zxing/browser": "ZXingBrowserReaders",
      },
    },
    {
      file: "dist/worker.js",
      format: "iife",
    },
  ],

};
