/**
 * @file tests/routes/prescan-callback-route.test.js
 * @description POST /v1/prescan/callback: only a callback signed with this
 * node's callback secret over the exact raw body wakes the named job.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */
"use strict";

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const request = require("supertest");
const routes = require(path.resolve(__dirname, "../../src/routes/prescan-callback"));

const SECRET = "wh_test_callback_secret";

function _app({ secret = SECRET, known = ["cj_1"] } = {}) {
  const woken = [];
  const prescanJobs = {
    wakeByClassifierRef: (id) => {
      if (!known.includes(id)) return false;
      woken.push(id);
      return true;
    },
  };
  const app = express();
  app.use("/v1", routes.createRouter({ prescanJobs, config: { classifierCallbackSecret: secret } }));
  app.use(express.json());
  return { app, woken };
}

function _sign(secret, body) {
  return "hmac-sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex");
}

function _post(app, body, signature) {
  const req = request(app).post("/v1/prescan/callback").set("Content-Type", "application/json");
  if (signature !== undefined) req.set("X-TIP-Classifier-Signature", signature);
  return req.send(body);
}

const BODY = JSON.stringify({ job_id: "cj_1", client_ref: "pj_1", state: "done" });

describe("prescan callback route", () => {
  test("a correctly signed callback wakes its job", async () => {
    const { app, woken } = _app();
    const res = await _post(app, BODY, _sign(SECRET, BODY));
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ job_id: "cj_1", woken: true });
    expect(woken).toEqual(["cj_1"]);
  });

  test("a body altered by one byte is refused", async () => {
    const { app, woken } = _app();
    const tampered = BODY.replace("done", "dona");
    const res = await _post(app, tampered, _sign(SECRET, BODY));
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("signature_invalid");
    expect(woken).toEqual([]);
  });

  test("a signature made with another secret is refused", async () => {
    const { app, woken } = _app();
    const res = await _post(app, BODY, _sign("wh_someone_else", BODY));
    expect(res.status).toBe(401);
    expect(woken).toEqual([]);
  });

  test.each([undefined, "", "sha256=abc", "hmac-sha256="])("a missing or malformed signature (%p) is refused", async (sig) => {
    const { app, woken } = _app();
    const res = await _post(app, BODY, sig);
    expect(res.status).toBe(401);
    expect(woken).toEqual([]);
  });

  test("an unknown job answers 404", async () => {
    const { app } = _app({ known: [] });
    const res = await _post(app, BODY, _sign(SECRET, BODY));
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe("job_not_found");
  });

  test("a signed body without job_id answers 400", async () => {
    const { app } = _app();
    const body = JSON.stringify({ state: "done" });
    const res = await _post(app, body, _sign(SECRET, body));
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("job_id_required");
  });

  test("callbacks are off when the node has no callback secret", async () => {
    const { app, woken } = _app({ secret: "" });
    const res = await _post(app, BODY, _sign("", BODY));
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe("callback_disabled");
    expect(woken).toEqual([]);
  });
});
