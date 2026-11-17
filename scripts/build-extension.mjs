import { build } from "esbuild";

await build({
  entryPoints: ["extension/src/sw/worker.ts"],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  outfile: "extension/dist/worker.js",
});
await build({
  entryPoints: ["extension/src/pages/popup.js"],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "es2022",
  outfile: "extension/dist/pages/popup.js",
});
await build({
  entryPoints: ["extension/src/pages/warning.js"],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "es2022",
  outfile: "extension/dist/pages/warning.js",
});
