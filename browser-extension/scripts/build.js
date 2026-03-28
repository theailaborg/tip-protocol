#!/usr/bin/env node
/**
 * @file scripts/build.js
 * @description TIP™ Extension — Build Script
 *
 * Bundles the extension with esbuild:
 *   - background.js  → ESM service worker (inlines crypto.js + @noble packages)
 *   - content.js     → copied as-is (plain IIFE, no imports)
 *   - popup.js       → copied as-is (no imports)
 *   - options.js     → copied as-is (no imports)
 *   - popup.html     → copied as-is
 *   - options.html   → copied as-is
 *   - manifest.json  → written with target-specific tweaks
 *   - icons/         → copied as-is
 *
 * Usage:
 *   node scripts/build.js --target=chrome
 *   node scripts/build.js --target=firefox
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * Author: Dinesh Mendhe <chairman@theailab.org>
 * License: TIPCL-1.0
 */

import * as esbuild from "esbuild";
import {
  cpSync, mkdirSync, readFileSync,
  writeFileSync, rmSync, existsSync,
} from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

// ── Parse --target ────────────────────────────────────────────────────────────
const targetArg = process.argv.find(a => a.startsWith("--target="));
const target    = targetArg?.split("=")[1];

if (!["chrome", "firefox"].includes(target)) {
  console.error("Usage: node scripts/build.js --target=chrome|firefox");
  process.exit(1);
}

const OUT = resolve(ROOT, "dist", target);

console.log(`\nBuilding TIP™ v${JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")).version} for ${target}...\n`);

// ── 1. Clean and scaffold dist dir ───────────────────────────────────────────
rmSync(OUT, { recursive: true, force: true });
mkdirSync(resolve(OUT, "src"),   { recursive: true });
mkdirSync(resolve(OUT, "icons"), { recursive: true });

// ── 2. Bundle background.js ───────────────────────────────────────────────────
// Service worker: ESM format, inlines crypto.js + @noble/post-quantum + @noble/hashes.
// Dynamic import() calls inside initCrypto() are resolved at bundle time.
await esbuild.build({
  entryPoints: [resolve(ROOT, "src", "background.js")],
  outfile:     resolve(OUT, "src", "background.js"),
  bundle:      true,
  format:      "esm",
  platform:    "browser",
  target:      target === "firefox" ? ["firefox121"] : ["chrome109"],
  minify:      true,
  sourcemap:   false,
  define:      { "process.env.NODE_ENV": '"production"' },
  // Suppress "dynamic require" warnings from noble packages
  logOverride: { "commonjs-variable-in-esm": "silent" },
});
console.log("  ✓ src/background.js — bundled (crypto + noble inlined)");

// ── 3. Copy content.js ────────────────────────────────────────────────────────
// Plain IIFE with no imports — no bundling needed.
cpSync(
  resolve(ROOT, "src", "content.js"),
  resolve(OUT, "src", "content.js"),
);
console.log("  ✓ src/content.js   — copied");

// ── 4. Copy popup/options JS and HTML ─────────────────────────────────────────
// Scripts are already extracted to src/popup.js and src/options.js in the source.
// HTML files reference them via <script src="src/popup.js"> — copy everything as-is.
for (const jsFile of ["popup.js", "options.js"]) {
  cpSync(resolve(ROOT, "src", jsFile), resolve(OUT, "src", jsFile));
  console.log(`  ✓ src/${jsFile.padEnd(12)} — copied`);
}
for (const htmlFile of ["popup.html", "options.html"]) {
  cpSync(resolve(ROOT, htmlFile), resolve(OUT, htmlFile));
  console.log(`  ✓ ${htmlFile.padEnd(16)} — copied`);
}

if (existsSync(resolve(ROOT, "NOTICE.txt"))) {
  cpSync(resolve(ROOT, "NOTICE.txt"), resolve(OUT, "NOTICE.txt"));
  console.log("  ✓ NOTICE.txt       — copied");
}
cpSync(resolve(ROOT, "icons"), resolve(OUT, "icons"), { recursive: true });
console.log("  ✓ icons/           — copied");

// ── 5. Write manifest.json (target-specific) ──────────────────────────────────
const manifest = JSON.parse(readFileSync(resolve(ROOT, "manifest.json"), "utf8"));

if (target === "firefox") {
  // Firefox MV3 requires a declared extension ID and a min version.
  // Supported since Firefox 121 (Jan 2024).
  manifest.browser_specific_settings = {
    gecko: {
      id:                 "tip-protocol@theailab.org",
      strict_min_version: "121.0",
    },
  };
}

writeFileSync(resolve(OUT, "manifest.json"), JSON.stringify(manifest, null, 2), "utf8");
console.log("  ✓ manifest.json    — written");

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n✓ Done → dist/${target}/\n`);
console.log(`  Next: npm run zip:${target}  → tip-extension-${target}-v${manifest.version}.zip\n`);
