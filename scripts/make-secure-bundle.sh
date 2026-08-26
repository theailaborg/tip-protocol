#!/usr/bin/env bash
# Build the encrypted half of a partner bundle.
#
#   ./make-secure-bundle.sh generated/<partner> [OrgFolderName]
# Accepts either a generated/<partner>/ dir (org/ + node/ auto-staged into
# delivery names, genesis added from the repo) or a pre-assembled flat dir.
#
# One encrypted zip (AES-256) holding the whole partner folder. Attach the zip,
# send the password over a separate channel. node.env carries live credentials
# (TIP_CLASSIFIER_KEY, TIP_METRICS_TOKEN), so nothing here goes out in the clear.
#
#
# ZipCrypto (`zip -e`) is deliberately not used: it is broken against a
# known-plaintext attack, and a leaked node key cannot be rotated today (#257).
set -euo pipefail

PARTNER="${1:-}"
[ -n "$PARTNER" ] || { echo "usage: $0 <path/to/partner-dir> [OrgFolderName]" >&2; exit 1; }
[ -d "$PARTNER" ] || { echo "no such partner dir: $PARTNER" >&2; exit 1; }

# Name of the folder the partner sees after extracting.
ORG="${2:-$(basename "$PARTNER")}"

command -v 7zz >/dev/null || { echo "7zz missing: brew install sevenzip" >&2; exit 1; }

# Outputs live next to the partner dir (typically under gitignored my-notes),
# NEVER next to this script , a repo checkout must not accumulate credential zips.
# All partner zips collect in one deliveries/ directory beside the partner dirs.
BASE="$(cd "$(dirname "$PARTNER")" && pwd)"
OUT="$BASE/deliveries"
mkdir -p "$OUT"
ZIP="$OUT/${ORG}-credentials.zip"
rm -f "$ZIP"

# Password: 20 chars from an unambiguous alphabet, grouped for reading aloud.
# Bounded head first, then cut: piping /dev/urandom straight into head SIGPIPEs
# the upstream filter, which pipefail turns into a failed run.
PASS=$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' \
       | cut -c1-20 | sed 's/.\{4\}/&-/g; s/-$//')

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$ORG"

# Two input layouts:
#   generated/<partner>/ with org/ + node/ subdirs (from register-org/node.js)
#     -> auto-staged into delivery names based on what is available
#   flat dir already holding node.env / NODE-KEY__ / ORG-IDENTITY__ / genesis
#     -> copied as-is (legacy layout, still supported)
missing=""
if [ -d "$PARTNER/org" ] || [ -d "$PARTNER/node" ]; then
  # node side: env + node key
  envf=$(ls "$PARTNER"/node/*.env 2>/dev/null | head -1)
  nkey=$(ls "$PARTNER"/node/tip-node-*.tip.json 2>/dev/null | head -1)
  okey=$(ls "$PARTNER"/org/*.tip.json 2>/dev/null | head -1)
  [ -n "$envf" ] && cp "$envf" "$STAGE/$ORG/node.env"           || missing="$missing node.env"
  [ -n "$nkey" ] && cp "$nkey" "$STAGE/$ORG/NODE-KEY__$(basename "$nkey")" || missing="$missing node-key"
  [ -n "$okey" ] && cp "$okey" "$STAGE/$ORG/ORG-IDENTITY__$(basename "$okey")" || missing="$missing org-identity"
  [ -f "$PARTNER/README.md" ] && cp "$PARTNER/README.md" "$STAGE/$ORG/README.md"
  # genesis comes from the repo this script lives in (the mainnet genesis on a
  # correctly prepared registration machine); override with $GENESIS_FILE.
  GEN="${GENESIS_FILE:-$(cd "$(dirname "$0")/.." && pwd)/genesis-data/genesis.json}"
  [ -f "$GEN" ] && cp "$GEN" "$STAGE/$ORG/genesis.json" || missing="$missing genesis.json"
  [ -n "$missing" ] && echo "  WARNING , not in this bundle:$missing" >&2
  # nothing sensitive at all -> refuse, an empty bundle helps nobody
  [ -z "$envf$nkey$okey" ] && { echo "no credentials found under $PARTNER/{org,node}" >&2; exit 1; }
  # secret-fill reminders: the generator leaves these empty on purpose (runbook 5.2)
  if [ -n "$envf" ]; then
    grep -qE "^TIP_CLASSIFIER_KEY=.+" "$STAGE/$ORG/node.env" || echo "  WARNING: TIP_CLASSIFIER_KEY is empty in node.env" >&2
    grep -qE "^TIP_METRICS_TOKEN=.+"  "$STAGE/$ORG/node.env" || echo "  WARNING: TIP_METRICS_TOKEN is empty in node.env" >&2
    grep -qE "^TIP_METRICS_TOKEN=certtest" "$STAGE/$ORG/node.env" && echo "  WARNING: TIP_METRICS_TOKEN is a TEST-network token" >&2
  fi
else
  cp -R "$PARTNER"/. "$STAGE/$ORG/"
  for pat in "node.env" "NODE-KEY__*.tip.json" "ORG-IDENTITY__*.tip.json" "genesis.json" "README.md"; do
    compgen -G "$STAGE/$ORG/$pat" >/dev/null \
      || { echo "missing from bundle: $pat" >&2; exit 1; }
  done
fi

( cd "$STAGE" && 7zz a -tzip -mem=AES256 -p"$PASS" -bso0 -bsp0 "$ZIP" "$ORG" >/dev/null )
chmod 600 "$ZIP"

# Append-only: a rebuild invalidates the password already sent, so keep the old
# rows rather than overwriting, and record the checksum to prove which archive
# a given password belongs to.
LOG="$BASE/ZIP-PASSWORDS.md"
if [ -f "$LOG" ]; then
  grep -q '^## Build log$' "$LOG" || printf '\n## Build log\n' >> "$LOG"
  printf '\n- `%s`  %s  password `%s`  sha256 `%s`\n' \
    "$(date '+%Y-%m-%d %H:%M %Z')" "$ORG" "$PASS" \
    "$(shasum -a 256 "$ZIP" | cut -c1-16)" >> "$LOG"
  chmod 600 "$LOG"
fi

echo
echo "  zip      : $ZIP"
echo "  password : $PASS"
echo
echo "  Extracts to $ORG/ :"
( cd "$STAGE/$ORG" && ls -1 | sed 's/^/    /' )
echo
echo "  Attach the zip. Send the password by phone or Signal, never in the same thread."
echo
