"use strict";

// Regenerates the cf-doc-1 fixtures in this folder with the vendored library:
//   node tests/fixtures/documents/make-fixtures.js
// Text is synthetic and seeded, so the documents (and their fingerprints) are reproducible.

const fs = require("fs");
const path = require("path");
const { fingerprintDocument } = require("tip-content-fingerprint/src/document");

const OUT = __dirname;
const SYLLABLES = "ba be bi bo bu da de di do du fa fe fi fo ka ke ki ko ku la le li lo lu ma me mi mo mu na ne ni no nu pa pe pi po ra re ri ro ru sa se si so ta te ti to tu va ve vi vo za ze zi zo".split(" ");

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function word(r) {
  let w = "";
  const n = 2 + Math.floor(r() * 3);
  for (let i = 0; i < n; i++) w += SYLLABLES[Math.floor(r() * SYLLABLES.length)];
  return w;
}

function paragraphs(seed, count) {
  const r = rng(seed);
  const out = [];
  for (let p = 0; p < count; p++) {
    const sentences = [];
    const n = 4 + Math.floor(r() * 4);
    for (let s = 0; s < n; s++) {
      const len = 8 + Math.floor(r() * 12);
      const w = [];
      for (let i = 0; i < len; i++) w.push(word(r));
      w[0] = w[0][0].toUpperCase() + w[0].slice(1);
      sentences.push(w.join(" ") + ".");
    }
    out.push(sentences.join(" "));
  }
  return out;
}

// Every `every`-th word replaced: no long run survives, so passages break while most shingles stay.
function reword(paras, every, seed) {
  const r = rng(seed);
  return paras.map((p) => p.split(" ").map((w, i) => (i % every === every - 1 ? word(r) + (w.endsWith(".") ? "." : "") : w)).join(" "));
}

function wrap(text, width) {
  const lines = [];
  let line = "";
  for (const word of text.split(" ")) {
    if (line && line.length + 1 + word.length > width) { lines.push(line); line = word; } else line = line ? `${line} ${word}` : word;
  }
  if (line) lines.push(line);
  return lines;
}

// Pages of lines from paragraphs, a blank line between paragraphs.
function layout(paras, { width, linesPerPage }) {
  const pages = [[]];
  for (const p of paras) {
    for (const line of [...wrap(p, width), ""]) {
      if (pages[pages.length - 1].length >= linesPerPage) pages.push([]);
      pages[pages.length - 1].push(line);
    }
  }
  return pages;
}

const esc = (s) => s.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");

// Minimal text PDF; `drawings` adds a page of filled boxes and no text (a page image only).
function pdf(pages, { font = "Helvetica", producer = "fixture", drawings = 0 } = {}) {
  const objs = [];
  const add = (body) => { objs.push(body); return objs.length; };
  const catalog = add(null);
  const pagesObj = add(null);
  const fontObj = add(`<< /Type /Font /Subtype /Type1 /BaseFont /${font} /Encoding /WinAnsiEncoding >>`);
  const kids = [];
  const page = (stream) => {
    const content = add(`<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream`);
    kids.push(add(`<< /Type /Page /Parent ${pagesObj} 0 R /MediaBox [0 0 612 792] /Contents ${content} 0 R /Resources << /Font << /F1 ${fontObj} 0 R >> >> >>`));
  };
  for (const lines of pages) page(`BT /F1 10 Tf 12 TL 54 750 Td ${lines.map((l) => `(${esc(l)}) Tj T*`).join(" ")} ET`);
  for (let d = 0; d < drawings; d++) {
    const r = rng(1000 + d);
    const boxes = [];
    for (let i = 0; i < 40; i++) {
      boxes.push(`${(r() * 0.8).toFixed(2)} g ${Math.floor(r() * 500)} ${Math.floor(r() * 700)} ${40 + Math.floor(r() * 120)} ${20 + Math.floor(r() * 90)} re f`);
    }
    page(boxes.join("\n"));
  }
  objs[catalog - 1] = `<< /Type /Catalog /Pages ${pagesObj} 0 R >>`;
  objs[pagesObj - 1] = `<< /Type /Pages /Kids [${kids.map((k) => `${k} 0 R`).join(" ")}] /Count ${kids.length} >>`;
  const info = add(`<< /Producer (${esc(producer)}) >>`);
  let out = "%PDF-1.4\n";
  const offsets = [];
  objs.forEach((body, i) => { offsets.push(Buffer.byteLength(out)); out += `${i + 1} 0 obj\n${body}\nendobj\n`; });
  const xref = Buffer.byteLength(out);
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root ${catalog} 0 R /Info ${info} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
}

function rtf(paras) {
  return Buffer.from(`{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Times New Roman;}}\\f0\\fs24 ${paras.map((p) => p.replace(/[\\{}]/g, "\\$&")).join("\\par\n")}\\par}`, "latin1");
}

const BODY = paragraphs(1, 30);
const LICENCE = paragraphs(99, 4);
const OTHER = paragraphs(2, 14);
const STANDARD = { width: 95, linesPerPage: 60 };

const docs = {
  original: pdf(layout([...BODY, ...LICENCE], STANDARD)),
  resaved: pdf(layout([...BODY, ...LICENCE], { width: 84, linesPerPage: 54 }), { font: "Times-Roman", producer: "re-saved" }),
  exported: rtf([...BODY, ...LICENCE]),
  reworded: pdf(layout(reword([...BODY, ...LICENCE], 6, 8), STANDARD)),
  chapter: pdf(layout([...paragraphs(3, 6), ...BODY.slice(10, 18), ...paragraphs(4, 6)], STANDARD)),
  unrelated: pdf(layout(OTHER, STANDARD)),
  licence_a: pdf(layout([...paragraphs(5, 2), ...LICENCE], STANDARD)),
  licence_b: pdf(layout([...paragraphs(6, 2), ...LICENCE], STANDARD)),
  licence_c: pdf(layout([...paragraphs(7, 2), ...LICENCE], STANDARD)),
  scan: pdf([], { drawings: 2 }),
  scan_copy: pdf([], { drawings: 2, producer: "re-scanned" }),
};

(async () => {
  for (const [name, bytes] of Object.entries(docs)) {
    const fp = await fingerprintDocument(new Uint8Array(bytes));
    fs.writeFileSync(path.join(OUT, `${name}.json`), JSON.stringify(fp) + "\n");
    console.log(name, fp.tier || fp.format, `${JSON.stringify(fp).length} bytes`, fp.units_covered ?? "", fp.chars_covered ?? "");
  }
})().catch((err) => { console.error(err); process.exit(1); });
