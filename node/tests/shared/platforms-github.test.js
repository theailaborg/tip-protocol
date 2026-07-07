"use strict";
const { PLATFORM_CONTENT_TYPE } = require("../../../shared/platforms.js");

describe("shared/platforms.js — github.com content-type strategy", () => {
  test("github.com resolves to TEXT_DOMINANT (README registration, spec 2026-07-06)", () => {
    expect(PLATFORM_CONTENT_TYPE["github.com"]).toBe("TEXT_DOMINANT");
  });
});
