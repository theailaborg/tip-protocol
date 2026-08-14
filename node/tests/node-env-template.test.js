/**
 * @file tests/node-env-template.test.js
 * @description Generated node envs are a function of .env.example plus explicit
 * per-node values. They are handed to other node operators, so they must never
 * carry the generating machine's credentials or its local tuning.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const { renderEnvFromExample } = require(path.resolve(__dirname, "../../scripts/node-env-template"));

const CREDENTIALS = [
  "TIP_CLASSIFIER_KEY",
  "TIP_METRICS_TOKEN",
  "TIP_NODE_PRIVATE_KEY",
  "DATABASE_URL",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
];

describe("renderEnvFromExample: credential backstop", () => {
  let warn;
  beforeEach(() => { warn = jest.spyOn(console, "warn").mockImplementation(() => {}); });
  afterEach(() => { warn.mockRestore(); });

  test.each(CREDENTIALS)("%s is never written, whatever the caller passes", (key) => {
    const out = renderEnvFromExample({ [key]: "LIVE_SECRET_VALUE" });
    expect(out).not.toContain("LIVE_SECRET_VALUE");
    // The example leaves these blank or commented; either is fine, a value is not.
    expect(out).not.toMatch(new RegExp(`^${key}=.+$`, "m"));
  });

  test("reports what it dropped rather than failing silently", () => {
    renderEnvFromExample({ TIP_CLASSIFIER_KEY: "live", DATABASE_URL: "postgres://u:p@h/d" });
    expect(warn).toHaveBeenCalledTimes(1);
    const msg = warn.mock.calls[0][0];
    expect(msg).toContain("TIP_CLASSIFIER_KEY");
    expect(msg).toContain("DATABASE_URL");
    expect(msg).not.toContain("postgres://u:p@h/d");
  });

  test("a dropped credential is not smuggled into the undocumented-values block", () => {
    const out = renderEnvFromExample({ AWS_SECRET_ACCESS_KEY: "live" });
    expect(out).not.toContain("live");
    expect(out).not.toContain("Values not documented");
  });

  test("empty credential values are not treated as a leak", () => {
    renderEnvFromExample({ TIP_CLASSIFIER_KEY: "", TIP_METRICS_TOKEN: undefined });
    expect(warn).not.toHaveBeenCalled();
  });

  test("does not mutate the caller's overrides object", () => {
    const overrides = { TIP_CLASSIFIER_KEY: "live", PORT: 4100 };
    renderEnvFromExample(overrides);
    expect(overrides.TIP_CLASSIFIER_KEY).toBe("live");
  });

  test("non-credential values still render, and omissions keep the example default", () => {
    const out = renderEnvFromExample({ PORT: 4100, DB_PASSWORD: "secret" });
    expect(out).toMatch(/^PORT=4100$/m);
    expect(out).toMatch(/^DB_PASSWORD=secret$/m);
    expect(out).toMatch(/^TIP_RATE_LIMIT_MAX=200$/m);   // not a load-test value
  });
});

// The leak in #255 was the caller, not the renderer: register-node.js read 23
// values out of the operator's shell and copied them into the partner's file.
describe("register-node.js does not inherit the operator's environment", () => {
  const ALLOWED = new Set(["TIP_LOG_LEVEL"]);   // script's own debug output, never written to the env

  test("reads no process.env value that could reach a generated env", () => {
    const src = fs.readFileSync(path.resolve(__dirname, "../../scripts/register-node.js"), "utf8");
    const read = [...src.matchAll(/process\.env\.([A-Z0-9_]+)/g)].map((m) => m[1]);
    expect([...new Set(read)].filter((k) => !ALLOWED.has(k))).toEqual([]);
  });
});
