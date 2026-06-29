/**
 * @file @tip-protocol/node/src/safe-timer.js
 * @description setTimeout/setInterval wrappers that route a thrown error OR a
 * rejected promise from the callback through the process error-handler, tagged
 * with a label. A throw inside a bare timer callback otherwise surfaces as an
 * anonymous uncaughtException with no clue which loop fired it.
 *
 * Returns the native timer handle so clearTimeout/clearInterval and .unref()
 * keep working at the callsite.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { captureError } = require("./process-error-handler");

function _runSafe(fn, label, args) {
  try {
    const r = fn(...args);
    if (r && typeof r.then === "function") r.catch((e) => captureError(e, { origin: "timer", label }));
  } catch (e) {
    captureError(e, { origin: "timer", label });
  }
}

function safeSetTimeout(fn, ms, label, ...args) {
  return setTimeout(() => _runSafe(fn, label, args), ms);
}

function safeSetInterval(fn, ms, label, ...args) {
  return setInterval(() => _runSafe(fn, label, args), ms);
}

module.exports = { safeSetTimeout, safeSetInterval };
