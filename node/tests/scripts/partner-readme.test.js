/**
 * @file tests/scripts/partner-readme.test.js
 * @description The partner bundle README must render and be written. It is a
 * template literal holding prose with backtick-quoted file names; an unescaped
 * backtick once ended the literal and crashed register-node.js after the
 * registration had been submitted, losing the generated key (2026-10-03).
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const { PARTNER_README, writePartnerReadme } = require(path.resolve(__dirname, "../../../scripts/partner-readme"));

describe("partner bundle README", () => {
  test("renders the reviewed text with its backtick-quoted file names intact", () => {
    expect(PARTNER_README.startsWith("# Your TIP credentials, and how to handle them")).toBe(true);
    expect(PARTNER_README).toContain("The `.tip.json` file in this folder is your organization");
    expect(PARTNER_README).toContain("The `.env` file is your node configuration");
    expect(PARTNER_README).toContain("## If something goes wrong");
    expect(PARTNER_README).toContain("tip@theailab.org");
    expect(PARTNER_README).not.toMatch(/ , /);
  });

  test("writes README.md into the partner root", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-partner-readme-"));
    try {
      writePartnerReadme(dir);
      expect(fs.readFileSync(path.join(dir, "README.md"), "utf8")).toBe(PARTNER_README);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("both register scripts use the shared module, not a private copy", () => {
    for (const f of ["register-org.js", "register-node.js"]) {
      const src = fs.readFileSync(path.resolve(__dirname, "../../../scripts", f), "utf8");
      expect(src).toMatch(/require\("\.\/partner-readme"\)/);
      expect(src).not.toMatch(/const text = `# /);
    }
  });
});
