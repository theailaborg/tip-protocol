/**
 * @author    Dinesh Mendhe <chairman@theailab.org>
 * @file @tip-protocol/node/src/logger.js
 */
"use strict";

const levels = { error: 0, warn: 1, info: 2, debug: 3 };

function makeLogger() {
  const level = process.env.TIP_LOG_LEVEL || "info";
  const maxLevel = levels[level] ?? 2;

  function format(lvl, ...args) {
    const ts = new Date().toISOString();
    const label = lvl.toUpperCase().padEnd(5);
    const msg = args.map(a => (typeof a === "object" ? JSON.stringify(a) : String(a))).join(" ");
    return `[${ts}] [${label}] ${msg}`;
  }

  return {
    error: (...a) => { if (maxLevel >= 0) console.error(format("error", ...a)); },
    warn:  (...a) => { if (maxLevel >= 1) console.warn(format("warn",  ...a)); },
    info:  (...a) => { if (maxLevel >= 2) console.log(format("info",  ...a)); },
    debug: (...a) => { if (maxLevel >= 3) console.log(format("debug", ...a)); },
  };
}

const log = makeLogger();
module.exports = { log };
