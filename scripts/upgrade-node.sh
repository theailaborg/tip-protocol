#!/usr/bin/env bash
# Gated upgrade of ONE running node: checkout the tag, rebuild, stop, prove the
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
READY_TRIES=60

echo "== [$(hostname)] upgrading to $TAG, gate peer $PEER"
cp genesis-data/genesis.json /tmp/genesis-backup.json
# A checkout must never replace the genesis this node runs on.
git stash push -q genesis-data/genesis.json 2>/dev/null || true
git fetch -q --tags origin
git checkout -q "$TAG"
git stash pop -q 2>/dev/null || true
diff -q genesis-data/genesis.json /tmp/genesis-backup.json
echo "== genesis unchanged; at $(git describe --tags --always)"

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
for i in $(seq 1 $READY_TRIES); do
  R=$(curl -s -m 3 http://localhost:4000/ready || true)
  echo "$R" | grep -q '"ready":true' && { echo "== READY after $((i*10))s: $R"; break; }
  sleep 10
done
curl -s -m 5 http://localhost:4000/health | head -c 300; echo
$DOCKER inspect --format 'RestartCount={{.RestartCount}}' "$($DOCKER compose ps -q tip-node)"
