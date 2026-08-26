#!/usr/bin/env bash
# Build the encrypted half of a partner bundle.
#
#   ./make-secure-bundle.sh rooverse [OrgFolderName]
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
BASE="$(cd "$(dirname "$PARTNER")" && pwd)"
OUT="$BASE/out"
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

cp -R "$PARTNER"/. "$STAGE/$ORG/"

# Every sensitive file must actually be in there; a silent omission would mean
# mailing a bundle the partner cannot run, or worse, one file left unencrypted.
for pat in "node.env" "NODE-KEY__*.tip.json" "ORG-IDENTITY__*.tip.json" "genesis.json" "README.md"; do
  compgen -G "$STAGE/$ORG/$pat" >/dev/null \
    || { echo "missing from bundle: $pat" >&2; exit 1; }
done

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
