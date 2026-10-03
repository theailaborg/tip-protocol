/**
 * @file scripts/partner-readme.js
 * @description The README.md written at the root of every partner credentials
 * folder (generated/<partner>/) and shipped as the first file in the bundle.
 * Shared by register-org.js and register-node.js so both write the same text.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

const fs = require("fs");
const path = require("path");

const PARTNER_README = `# Your TIP credentials, and how to handle them

Everything in this bundle proves your organization and your node on the
TIP production network. Treat each file the way you treat a signing
certificate or an HSM-backed key: these are not credentials we can
reissue on request. Take an offline backup of both key files before you
deploy, store the backups with your company signing material, and tell
us immediately if any file here is ever lost or exposed, so we can act
on it with you.

## org/ : your organization identity

The \`.tip.json\` file in this folder is your organization on the
network. It signs content as you.

It is not needed to run your node. Keep it off the node host entirely,
stored wherever you keep company signing material. File mode 0600,
never committed to version control, never sent over an unencrypted
channel. The private key inside is locked with your date of
incorporation: import the file into the TIP VP app and enter that date
(MM/DD/YYYY) to sign as your organization.

## node/ : your node identity and configuration

The \`.tip.json\` file in this folder runs your node. It lives on the
node host and is read by the node process at boot. File mode 0600,
owned by the container user (uid 1001).

The \`.env\` file is your node configuration. It carries live
credentials, including the content classifier key and the metrics
token, so the same rules apply: file mode 0600, never committed, and
used only from this node. The classifier key is shared infrastructure;
a leak forces a rotation for every operator on the network.

## If something goes wrong

If either key file is lost, exposed, or even possibly exposed, contact
us at tip@theailab.org before doing anything else. Acting early is what
keeps a mistake from becoming an incident.
`;

// Overwritten on each run so it always reflects the current layout.
function writePartnerReadme(partnerRoot) {
  fs.writeFileSync(path.join(partnerRoot, "README.md"), PARTNER_README);
}

module.exports = { PARTNER_README, writePartnerReadme };
