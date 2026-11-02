/**
 * @file @tip-protocol/node/src/init-text-index.js
 * @description Boot the text near-duplicate index: apply the configured LSH
 * scheme (and shadow scheme), then load, resume or rebuild each index the node
 * writes to, in the background.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const textIndex = require("./perceptual/text-index");
const { log } = require("./logger");

function initTextIndex({ dag, config }) {
  textIndex.configure({ scheme: config.textLshScheme, shadow: config.textLshShadow });
  const shadow = textIndex.shadowScheme();
  log.info(`Text near-duplicate LSH: answering with ${textIndex.answerScheme()}${shadow ? `, shadow ${shadow}` : ""}`);
  return textIndex.start(dag);
}

module.exports = { initTextIndex };
