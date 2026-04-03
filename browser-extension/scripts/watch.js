#!/usr/bin/env node
/**
 * @file scripts/watch.js
 * @description TIP™ Extension - Development watch mode (Chrome)
 *
 * - background.js : esbuild context watch - rebuilds automatically on save
 *                   (crypto.js + @noble packages inlined, sourcemaps enabled)
 * - content.js, popup.js, options.js, HTML, icons, manifest.json :
 *                   fs.watch - re-copied to dist/chrome/ on every save
 *
 * Usage:
 *   npm run dev
 *
 * After each rebuild, click the reload button (↺) on chrome://extensions
 * to pick up the changes in the browser.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * Author: Dinesh Mendhe <tip@theailab.org>
 * License: TIPCL-1.0
 */

import * as esbuild from "esbuild";
import {
  cpSync, mkdirSync, readFileSync,
  writeFileSync, rmSync, watch,
} from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const OUT  = resolve(ROOT, "dist", "chrome");

// ── Helpers ───────────────────────────────────────────────────────────────────

function timestamp() {
  return new Date().toLocaleTimeString();
}

function writeManifest() {
  const manifest = JSON.parse(readFileSync(resolve(ROOT, "manifest.json"), "utf8"));
  writeFileSync(resolve(OUT, "manifest.json"), JSON.stringify(manifest, null, 2), "utf8");
}

function copyStatics() {
  for (const f of ["content.js", "popup.js", "options.js"])
    cpSync(resolve(ROOT, "src", f), resolve(OUT, "src", f));
  for (const f of ["popup.html", "options.html"])
    cpSync(resolve(ROOT, f), resolve(OUT, f));
  cpSync(resolve(ROOT, "icons"), resolve(OUT, "icons"), { recursive: true });
  writeManifest();
}

// ── Initial build ─────────────────────────────────────────────────────────────

rmSync(OUT, { recursive: true, force: true });
mkdirSync(resolve(OUT, "src"),   { recursive: true });
mkdirSync(resolve(OUT, "icons"), { recursive: true });
copyStatics();
console.log("✓ dist/chrome/ scaffolded\n");

// ── esbuild watch - background.js + crypto.js + @noble/* ─────────────────────

const ctx = await esbuild.context({
  entryPoints: [resolve(ROOT, "src", "background.js")],
  outfile:     resolve(OUT,  "src", "background.js"),
  bundle:      true,
  format:      "esm",
  platform:    "browser",
  target:      ["chrome109"],
  minify:      false,
  sourcemap:   "inline",
  define:      { "process.env.NODE_ENV": '"development"' },
  logOverride: { "commonjs-variable-in-esm": "silent" },
  plugins: [{
    name: "tip-rebuild-log",
    setup(build) {
      build.onEnd(result => {
        if (result.errors.length) {
          console.error(`[${timestamp()}] ✗ background.js - ${result.errors.length} error(s)`);
        } else {
          console.log(`[${timestamp()}] ✓ background.js rebuilt - reload extension`);
        }
      });
    },
  }],
});

await ctx.watch();
console.log(`[${timestamp()}] Watching src/background.js (+ crypto.js + @noble/*) via esbuild`);

// ── fs.watch - static files ───────────────────────────────────────────────────
// Debounce rapid successive saves (e.g. editor auto-save) to avoid redundant copies.

const debounceTimers = new Map();
function debounce(key, fn, ms = 80) {
  clearTimeout(debounceTimers.get(key));
  debounceTimers.set(key, setTimeout(() => { debounceTimers.delete(key); fn(); }, ms));
}

// src/ files other than background.js (and crypto.js which esbuild resolves)
watch(resolve(ROOT, "src"), { recursive: true }, (_, filename) => {
  if (!filename || filename === "background.js" || filename === "crypto.js") return;
  debounce(`src/${filename}`, () => {
    try {
      cpSync(resolve(ROOT, "src", filename), resolve(OUT, "src", filename));
      console.log(`[${timestamp()}] ✓ src/${filename} copied`);
    } catch { /* file may be mid-write */ }
  });
});

// icons/
watch(resolve(ROOT, "icons"), { recursive: true }, (_, filename) => {
  debounce("icons", () => {
    cpSync(resolve(ROOT, "icons"), resolve(OUT, "icons"), { recursive: true });
    console.log(`[${timestamp()}] ✓ icons/ copied`);
  });
});

// manifest.json
watch(resolve(ROOT, "manifest.json"), () => {
  debounce("manifest", () => {
    writeManifest();
    console.log(`[${timestamp()}] ✓ manifest.json written`);
  });
});

// HTML files
for (const f of ["popup.html", "options.html"]) {
  watch(resolve(ROOT, f), () => {
    debounce(f, () => {
      cpSync(resolve(ROOT, f), resolve(OUT, f));
      console.log(`[${timestamp()}] ✓ ${f} copied`);
    });
  });
}

console.log(`[${timestamp()}] Watching static files (content.js, popup.js, options.js, HTML, icons, manifest)`);
console.log("\nReady. Press Ctrl+C to stop.\n");
