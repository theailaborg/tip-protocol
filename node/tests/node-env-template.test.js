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
const { renderEnvFromExample, productionEnvDefaults } = require(path.resolve(__dirname, "../../scripts/node-env-template"));

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
    const out = renderEnvFromExample({ AWS_SECRET_ACCESS_KEY: "LEAKED-SECRET-VALUE" });
    expect(out).not.toContain("LEAKED-SECRET-VALUE");
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

// .env.example documents dev defaults. Every one of them is wrong on a live
// node, and before this overlay existed they followed a partner into
// production: a localhost classifier, '*' CORS, heuristic verdicts when the
// classifier is down, and data/log paths under the GENERATING machine's folder.
describe("productionEnvDefaults", () => {
  const prod = productionEnvDefaults();

  test("pins the values the mainnet fleet actually runs", () => {
    expect(prod.NODE_ENV).toBe("production");
    expect(prod.TIP_CLASSIFIER_URL).toBe("https://tipclassifier.theailab.org");
    expect(prod.TIP_PRESCAN_CONCURRENCY).toBe("4");
    expect(prod.TIP_RATE_LIMIT_MAX).toBe("1000");
  });

  // 1 serves heuristic verdicts when the classifier is unreachable; the fleet
  // turned that off after the breaker handed them out under load.
  test("classifier fallback is strict, never the example's permissive 1", () => {
    expect(prod.TIP_CLASSIFIER_FALLBACK).toBe("0");
  });

  test("CORS carries the federation origins and never the dev wildcard", () => {
    expect(prod.TIP_CORS_ORIGINS.split(",")).toEqual([
      "https://theailab.org",
      "https://www.theailab.org",
      "https://vp.theailab.org",
    ]);
    expect(prod.TIP_CORS_ORIGINS).not.toContain("*");
  });

  // WORKDIR=/app with ./data and ./logs/node-1 mounted; a generator-local path
  // does not exist inside the container.
  test("paths are container-relative, not generator-local", () => {
    expect(prod.TIP_DATA_DIR).toBe("./data");
    expect(prod.TIP_DB_PATH).toBe("./data/tip.db");
    expect(prod.TIP_LOG_DIR).toBe("/app/node/logs");
    for (const v of Object.values(prod)) expect(String(v)).not.toContain("generated/");
  });

  test("the key file resolves into the mounted read-only dir", () => {
    const withKey = productionEnvDefaults({ credentialsFileName: "tip-node-abc123.tip.json" });
    expect(withKey.TIP_NODE_CREDENTIALS_FILE).toBe("genesis-data/backups/tip-node-abc123.tip.json");
  });

  test("omits the key path entirely when no file name is supplied", () => {
    expect(prod).not.toHaveProperty("TIP_NODE_CREDENTIALS_FILE");
  });

  // Per-node values belong to the caller: baking any of them in would hand
  // every partner the same bucket, database or identity.
  test("carries no per-node value", () => {
    for (const k of ["TIP_NODE_ID", "DB_NAME", "DB_PASSWORD", "TIP_PUBLIC_IP",
      "TIP_MEDIA_S3_BUCKET", "TIP_CLASSIFIER_KEY", "TIP_METRICS_TOKEN"]) {
      expect(prod).not.toHaveProperty(k);
    }
  });

  test("renders through the template without tripping the credential backstop", () => {
    const warn = jest.spyOn(console, "warn").mockImplementation(() => {});
    const out = renderEnvFromExample({ ...productionEnvDefaults({ credentialsFileName: "k.tip.json" }) });
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
    expect(out).toMatch(/^TIP_CLASSIFIER_FALLBACK=0$/m);
    expect(out).toMatch(/^TIP_RATE_LIMIT_MAX=1000$/m);
    expect(out).toMatch(/^TIP_CORS_ORIGINS=https:\/\/theailab\.org,/m);
    expect(out).not.toMatch(/^TIP_CORS_ORIGINS=\*$/m);
  });
});

// A relative TIP_LOG_DIR resolves against the container's WORKDIR (/app), not
// against the bind-mount, so `./logs/node-1` silently writes to /app/logs/node-1
// and the logs never leave the container. A partner lost a week of shipping to
// this. Pin the production value against what compose actually mounts.
describe("TIP_LOG_DIR matches the docker-compose mount", () => {
  const compose = fs.readFileSync(path.resolve(__dirname, "../../docker-compose.yml"), "utf8");

  test("production writes to the path compose bind-mounts", () => {
    const mount = compose.match(/^\s*-\s*\.\/logs\/[^:]+:(\S+)\s*$/m);
    expect(mount).not.toBeNull();
    expect(productionEnvDefaults().TIP_LOG_DIR).toBe(mount[1]);
  });

  test("production value is absolute, never relative", () => {
    expect(productionEnvDefaults().TIP_LOG_DIR.startsWith("/")).toBe(true);
  });

  // Unset is correct for both Docker and native: the logger falls back to
  // <repo>/node/logs, which is the same path compose mounts.
  test(".env.example ships TIP_LOG_DIR commented out, not set to a relative path", () => {
    const ex = fs.readFileSync(path.resolve(__dirname, "../../.env.example"), "utf8");
    expect(ex).not.toMatch(/^TIP_LOG_DIR=\.\//m);
    expect(ex).toMatch(/^#\s*TIP_LOG_DIR=/m);
  });
});
