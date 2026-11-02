/**
 * @file tests/services/metrics-exposition.test.js
 * @description The /metrics body is valid exposition: one HELP and TYPE per
 * metric family, also when a shadow text LSH scheme adds a second label set.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const { MemoryStore } = require("../../src/dag");
const textIndex = require("../../src/perceptual/text-index");
const { createMetricsService } = require("../../src/services/metrics-service");

afterEach(() => textIndex.configure({}));

test("every metric family has one TYPE line, and its samples follow it, with a shadow scheme set", async () => {
  const dag = new MemoryStore();
  textIndex.configure({ shadow: "b42r3" });
  await textIndex.start(dag).done;
  const body = createMetricsService({ dag, config: { nodeId: "n1" }, consensus: null, network: null }).buildBody();
  const lines = body.split("\n");
  const types = lines.filter((l) => l.startsWith("# TYPE ")).map((l) => l.split(" ")[2]);
  expect(types.length).toBeGreaterThan(0);
  expect(types.filter((n, i) => types.indexOf(n) !== i)).toEqual([]);
  const complete = lines.filter((l) => l.startsWith("tip_text_lsh_index_complete{"));
  expect(complete).toEqual([expect.stringContaining('scheme="b32r4"'), expect.stringContaining('scheme="b42r3"')]);
  const at = (prefix) => lines.findIndex((l) => l.startsWith(prefix));
  expect(at("tip_text_lsh_index_complete{")).toBeGreaterThan(at("# TYPE tip_text_lsh_index_complete"));
  expect(at("# TYPE tip_text_lsh_index_texts")).toBeGreaterThan(lines.lastIndexOf(complete[1]));
});
