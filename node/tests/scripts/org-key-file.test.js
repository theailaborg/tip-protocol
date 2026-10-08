/**
 * @file tests/scripts/org-key-file.test.js
 * @description The organization key file is locked with the date of
 * incorporation, so it must never carry that date. It used to: the clear
 * envelope held `incorporated` for audit, so the file came with its own unlock
 * date. The dedup inputs now go to a Lab-only record that the bundle never ships.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const path = require("path");
const fs = require("fs");
const os = require("os");
const { execFileSync } = require("child_process");
const SCRIPTS = path.resolve(__dirname, "../../../scripts");
const SHARED = path.resolve(__dirname, "../../../shared");
const { buildOrgKeyFiles, assertNoUnlockDate, recordPathFor } = require(path.join(SCRIPTS, "org-key-file"));
const { readKeyFile, datePassword } = require(path.join(SHARED, "key-file"));

const DATE = "2021-06-28";
const TIP_ID = "tip://id/IN-0123456789abcdef";

function build(overrides = {}) {
  return buildOrgKeyFiles({
    tipId: TIP_ID,
    keypair: { publicKey: "cd".repeat(1952), privateKey: "ab".repeat(4032) },
    incorporated: DATE,
    vpId: "tip://vp/US-fedcba9876543210",
    orgName: "Example Media Private Limited",
    region: "IN",
    scheme: { normalized: "U74999MH2021PTC123456", name: "IN-CIN" },
    regNumber: "u74999mh2021ptc123456",
    dedupHash: "e".repeat(64),
    registeredAt: 1759633200000,
    registeredOn: "https://node.theailab.org",
    exportedAt: "2026-10-05T03:00:00.000Z",
    ...overrides,
  });
}

describe("organization key file", () => {
  test("the delivered file never carries its unlock date, in any spelling", () => {
    const { keyFile, keyFileText } = build();
    expect(keyFile).not.toHaveProperty("incorporated");
    for (const form of [DATE, "06/28/2021", "06282021", "28/06/2021", "28-06-2021"]) {
      expect(keyFileText).not.toContain(form);
    }
  });

  test("it still opens with the date and keeps the VP app's envelope", () => {
    const { keyFileText } = build();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-org-key-"));
    const file = path.join(dir, "id-IN-0123456789abcdef.tip.json");
    try {
      fs.writeFileSync(file, keyFileText, { mode: 0o600 });
      const read = readKeyFile(file, datePassword(DATE));
      expect(read.private_key).toBe("ab".repeat(4032));
      expect(read.tip_id).toBe(TIP_ID);
      const doc = JSON.parse(keyFileText);
      expect(doc.version).toBe("tip-key-export-v2");
      expect(doc.tip_id_type).toBe("organization");
      expect(doc.vp_id).toBe("tip://vp/US-fedcba9876543210");
      expect(doc.display_name).toBe("Example Media Private Limited");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("the Lab-only record keeps every dedup input, the date included", () => {
    const { record, recordText } = build();
    expect(record.incorporated).toBe(DATE);
    expect(record.registration_number).toBe("U74999MH2021PTC123456");
    expect(record.registration_number_as_provided).toBe("u74999mh2021ptc123456");
    expect(record.registration_scheme).toBe("IN-CIN");
    expect(record.dedup_hash).toBe("e".repeat(64));
    expect(record.lab_only).toMatch(/Never deliver/);
    expect(JSON.parse(recordText)).toEqual(record);
  });

  test("the record sits beside the key file under a name the bundler skips", () => {
    const rec = recordPathFor("/g/acme/org/id-IN-0123456789abcdef.tip.json");
    expect(rec).toBe("/g/acme/org/id-IN-0123456789abcdef.registration.json");
    expect(rec.endsWith(".tip.json")).toBe(false);
    // make-secure-bundle.sh stages only org/*.tip.json from a partner folder.
    const bundler = fs.readFileSync(path.join(SCRIPTS, "make-secure-bundle.sh"), "utf8");
    expect(bundler).toContain('okey=$(ls "$PARTNER"/org/*.tip.json');
  });

  test("the bundler's org glob does not match the record", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tip-org-glob-"));
    try {
      fs.writeFileSync(path.join(dir, "id-IN-x.tip.json"), "{}");
      fs.writeFileSync(path.join(dir, "id-IN-x.registration.json"), "{}");
      const out = execFileSync("bash", ["-c", 'ls "$1"/*.tip.json', "_", dir], { encoding: "utf8" });
      expect(out).toContain("id-IN-x.tip.json");
      expect(out).not.toContain("registration.json");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("the guard rejects a date field or a field whose value is the date", () => {
    expect(() => assertNoUnlockDate({ incorporated: DATE }, DATE)).toThrow(/incorporated/);
    expect(() => assertNoUnlockDate({ dob: "x" }, DATE)).toThrow(/dob/);
    expect(() => assertNoUnlockDate({ note: "06/28/2021" }, DATE)).toThrow(/note/);
    expect(() => assertNoUnlockDate({ note: "06282021" }, DATE)).toThrow(/note/);
  });

  test("the guard does not raise a false alarm on look-alike digits", () => {
    // An export made on the incorporation day, and key material that happens
    // to contain the digits: a false alarm would fire after registration.
    expect(() => assertNoUnlockDate({
      exportedAt: `${DATE}T09:00:00.000Z`,
      publicKey: `00${datePassword(DATE)}00`,
      encrypted: `A${datePassword(DATE)}B`,
    }, DATE)).not.toThrow();
  });
});
