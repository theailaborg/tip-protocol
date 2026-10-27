#!/usr/bin/env bash
# Gated upgrade of ONE running node: check out the tag, rebuild, stop, prove the
# database rebuilds to the live root of an untouched peer, start only on MATCH.
# Run it on the node host, one node at a time, never two nodes down at once.
#
#   scripts/upgrade-node.sh <tag> <untouched-peer-url>
#   scripts/upgrade-node.sh v2.7.9 https://node.theailab.org
set -euo pipefail
TAG="${1:-}"; PEER="${2:-}"
[ -n "$TAG" ] && [ -n "$PEER" ] || { echo "usage: $0 <tag> <untouched-peer-url>" >&2; exit 1; }
cd "$(dirname "$0")/.."

if docker info >/dev/null 2>&1; then DOCKER=docker; else DOCKER="sudo docker"; fi
GENESIS=genesis-data/genesis.json
hash() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['genesis_hash'][:8])" "$1"; }

echo "== [$(hostname)] upgrading to $TAG, gate peer $PEER"
# The node must run the committed genesis; a local edit means this is not a
# plain federation node and the upgrade needs a human, not this script.
git diff --quiet -- "$GENESIS" || { echo "== $GENESIS is locally modified; refusing" >&2; exit 4; }
BEFORE=$(hash "$GENESIS")
git fetch -q --tags origin
git checkout -q "$TAG"
AFTER=$(hash "$GENESIS")
[ "$BEFORE" = "$AFTER" ] || { echo "== genesis changed $BEFORE -> $AFTER at $TAG; refusing to build" >&2; exit 4; }
echo "== genesis unchanged ($AFTER); at $(git describe --tags --always)"

$DOCKER compose build tip-node </dev/null > /tmp/build.log 2>&1 && echo "== build ok" || { tail -20 /tmp/build.log; exit 2; }
$DOCKER compose stop tip-node </dev/null
echo "== stopped; running root gate"
set +e
$DOCKER compose run --rm --no-deps -T ${NODE_OPTIONS:+-e NODE_OPTIONS="$NODE_OPTIONS"} --entrypoint node tip-node \
  scripts/check-boot-root.js --migrate --peer "$PEER" </dev/null | tee /tmp/gate.log
RC=${PIPESTATUS[0]}
set -e
if [ "$RC" != "0" ]; then
  echo "== GATE FAILED (rc=$RC): node left STOPPED on $TAG, do not start it" >&2; exit 3
fi

$DOCKER compose up -d --no-deps --force-recreate tip-node </dev/null
echo "== started; waiting for /ready"
for i in $(seq 1 60); do
  R=$(curl -s -m 3 http://localhost:4000/ready || true)
  echo "$R" | grep -q '"ready":true' && { echo "== READY after $((i*10))s: $R"; break; }
  sleep 10
done
curl -s -m 5 http://localhost:4000/health | head -c 300; echo
$DOCKER inspect --format 'RestartCount={{.RestartCount}}' "$($DOCKER compose ps -q tip-node)"
