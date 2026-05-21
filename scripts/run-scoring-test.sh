#!/usr/bin/env bash
# scripts/run-scoring-test.sh
# DEV-ONLY: Full end-to-end scoring pipeline test.
#
# Phases:
#   1. cluster-reset  — tear down + reseed + rebuild + start all 5 nodes
#                       (with TIP_DEV_FORCE_PRESCAN_TIER + TIP_DEV_BYPASS_VOTE_WINDOWS)
#   2. seed-users     — register temp identities with jury-eligible scores
#   3. register       — register a piece of OH content (gets HIGH prescan tier)
#   4. dispute        — file a dispute against the CTID
#   5. jury           — drive commit + reveal for all seeded jurors, then watch verdict
#   6. status         — show final scores for all parties
#
# Usage:
#   bash scripts/run-scoring-test.sh                     # full flow from scratch
#   bash scripts/run-scoring-test.sh --phase register    # start from a specific phase
#   bash scripts/run-scoring-test.sh --ctid tip://c/...  # resume from dispute onward
#   bash scripts/run-scoring-test.sh --help
#
# Prerequisites:
#   - Docker + docker compose v2
#   - Node.js ≥18 (for seed.js --experimental-vm-modules)
#   - genesis-data/ output from a prior seed.js run (skipped if cluster-reset is not run)
#
# © 2026 The AI Lab Intelligence Unobscured, Inc.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_BASE="docker-compose.local.yml"
COMPOSE_SCORING="docker-compose.scoring-test.yml"
DC="docker compose -f $COMPOSE_BASE -f $COMPOSE_SCORING"
DC_BASE="docker compose -f $COMPOSE_BASE"

# ─── Colors ──────────────────────────────────────────────────────────────────
BOLD="\033[1m"; RESET="\033[0m"
GREEN="\033[32m"; RED="\033[31m"; CYAN="\033[36m"; YELLOW="\033[33m"; DIM="\033[2m"

step()  { echo -e "\n${BOLD}${CYAN}▸ $*${RESET}"; }
ok()    { echo -e "${GREEN}  ✓ $*${RESET}"; }
warn()  { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
fail()  { echo -e "${RED}  ✗ $*${RESET}"; }
info()  { echo -e "${DIM}  ℹ $*${RESET}"; }
hr()    { echo -e "${DIM}  ────────────────────────────────────────${RESET}"; }

# ─── CLI ─────────────────────────────────────────────────────────────────────
START_PHASE="cluster-reset"
CTID=""
NODE_URL="http://localhost:4000"
SKIP_BUILD=false
USERS=50
CONTENT_TEXT="This article discusses the rapid advancement of artificial intelligence and how large language models are fundamentally transforming software engineering workflows, developer productivity, and automated reasoning systems in the enterprise."
VOTE_BIAS="UPHELD"

usage() {
  cat <<EOF
usage: bash scripts/run-scoring-test.sh [opts]

  --phase PHASE       start from: cluster-reset | seed-users | register | dispute | jury | status
  --ctid CTID         CTID to use (required when --phase=dispute or later)
  --node-url URL      target node for API calls (default: http://localhost:4000)
  --users N           number of temp users to seed (default: 50)
  --content TEXT      content to register (default: built-in sample text)
  --vote-bias BIAS    UPHELD | DISMISSED | RANDOM for jury votes (default: UPHELD)
  --skip-build        skip docker build step (use existing image)
  --help              show this help
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase)        START_PHASE="$2"; shift 2 ;;
    --ctid)         CTID="$2"; shift 2 ;;
    --node-url)     NODE_URL="$2"; shift 2 ;;
    --users)        USERS="$2"; shift 2 ;;
    --content)      CONTENT_TEXT="$2"; shift 2 ;;
    --vote-bias)    VOTE_BIAS="$2"; shift 2 ;;
    --skip-build)   SKIP_BUILD=true; shift ;;
    --help|-h)      usage ;;
    *)              echo "unknown arg: $1"; exit 1 ;;
  esac
done

PHASES=(cluster-reset seed-users register dispute jury status)
START_IDX=0
for i in "${!PHASES[@]}"; do
  [[ "${PHASES[$i]}" == "$START_PHASE" ]] && START_IDX=$i
done

should_run() { local phase="$1"; local idx; for idx in "${!PHASES[@]}"; do [[ "${PHASES[$idx]}" == "$phase" ]] && [[ $idx -ge $START_IDX ]] && return 0; done; return 1; }

# State file — persists CTID and SIGNER across phase runs in the same session.
STATE_FILE="$REPO_ROOT/.scoring-test-state"
load_state() { [[ -f "$STATE_FILE" ]] && source "$STATE_FILE" || true; }
save_state() {
  cat >"$STATE_FILE" <<EOF
CTID="$CTID"
SIGNER_TIP_ID="${SIGNER_TIP_ID:-}"
EOF
}
load_state

# ─── Health check ─────────────────────────────────────────────────────────────
wait_healthy() {
  local url="$1/health"; local label="$2"; local max="${3:-60}"; local i=0
  info "Waiting for $label to be healthy at $url (max ${max}s)…"
  while [[ $i -lt $max ]]; do
    local resp; resp=$(curl -sf --max-time 3 "$url" 2>/dev/null || true)
    if [[ -n "$resp" ]]; then
      local status; status=$(echo "$resp" | node -e "let d=''; process.stdin.on('data',c=>d+=c); process.stdin.on('end',()=>{ try{ console.log(JSON.parse(d).data?.status||''); }catch{} });")
      if [[ "$status" == "healthy" ]]; then ok "$label healthy"; return 0; fi
    fi
    sleep 2; ((i+=2))
  done
  fail "$label not healthy after ${max}s"; return 1
}

check_all_nodes() {
  step "Cluster health check"
  local ports=(4000 4100 4200 4300 4400)
  local names=(node1 node2 node3 node4 node5)
  local healthy=0
  for i in "${!ports[@]}"; do
    local port="${ports[$i]}"; local name="${names[$i]}"
    local resp; resp=$(curl -sf --max-time 3 "http://localhost:$port/health" 2>/dev/null || true)
    if [[ -n "$resp" ]]; then
      local st rnd js
      st=$(echo "$resp" | node -e "let d=''; process.stdin.on('data',c=>d+=c); process.stdin.on('end',()=>{ const h=JSON.parse(d); const c=h.data?.consensus?.narwhal||{}; console.log(h.data?.status+' round='+c.round+' join='+c.joinState); });")
      echo -e "  ${GREEN}✓${RESET} $name :$port — $st"
      ((healthy++))
    else
      echo -e "  ${RED}✗${RESET} $name :$port — unreachable"
    fi
  done
  [[ $healthy -ge 3 ]] || { fail "Need ≥3 healthy nodes for quorum"; exit 1; }
  ok "$healthy/5 nodes healthy"
}

# ─── Phase 1: Cluster Reset ───────────────────────────────────────────────────
if should_run "cluster-reset"; then
  step "Phase 1/6 — Cluster Reset"
  hr

  info "Tearing down existing cluster (volumes included)…"
  $DC_BASE --profile observability down -v 2>/dev/null || true
  $DC_BASE down -v 2>/dev/null || true

  info "Removing node data directories…"
  rm -rf "$REPO_ROOT/data/" "$REPO_ROOT"/node{2,3,4,5}-env/
  ok "Data directories removed"

  info "Regenerating genesis + keys (seed.js)…"
  cd "$REPO_ROOT"
  node --experimental-vm-modules scripts/seed.js
  ok "Genesis reseeded"

  if [[ "$SKIP_BUILD" != "true" ]]; then
    info "Building Docker image tip-protocol/node:2.0.0…"
    docker build -t tip-protocol/node:2.0.0 . 2>&1 | tail -8
    ok "Image built"
  else
    warn "--skip-build: using existing image"
  fi

  step "Starting node1 (primary)…"
  $DC up node1 -d
  wait_healthy "http://localhost:4000" "node1" 90
  docker logs tip-node1 --tail 30

  step "Registering nodes 2–5…"
  for n in 2 3 4 5; do
    local_port=$((4000 + (n-1)*100)); p2p_port=$((local_port + 1))
    last_octet=$((9 + n)); ip="172.30.0.$last_octet"
    info "Registering node$n (port $local_port, ip $ip)…"
    node scripts/register-node.js \
      --name "Node $n" \
      --port "$local_port" \
      --p2p-port "$p2p_port" \
      --public-ip "$ip" \
      --out-dir "./node${n}-env" \
      --db-name "tip_node${n}" \
      --force
    ok "node$n registered"
  done

  step "Starting nodes 2–5…"
  for n in 2 3 4 5; do
    $DC up "node$n" -d
    sleep 8
    docker logs "tip-node$n" --tail 20
    ok "node$n started"
  done

  step "Starting observability stack…"
  $DC_BASE --profile observability up -d 2>&1 | tail -5

  sleep 5
  check_all_nodes
  ok "Cluster reset complete — all nodes running with TIP_DEV_FORCE_PRESCAN_TIER=high + TIP_DEV_BYPASS_VOTE_WINDOWS=1"
fi

# ─── Phase 2: Seed Temp Users ─────────────────────────────────────────────────
if should_run "seed-users"; then
  step "Phase 2/6 — Seed Temp Users (${USERS} users)"
  hr

  # Require cluster healthy before seeding.
  wait_healthy "$NODE_URL" "node1" 30

  node scripts/seed-temp-users.js \
    --count "$USERS" \
    --node-url "$NODE_URL" \
    --high-pct 70 \
    --regions "US,BR,DE,JP,IN,GB,FR,AU,CA,MX"

  ok "Temp users seeded — restarting all nodes to re-hydrate scores from DB…"
  for name in tip-node1 tip-node2 tip-node3 tip-node4 tip-node5; do
    docker restart "$name" 2>/dev/null && info "Restarted $name" || warn "$name not running (skip)"
  done

  sleep 12
  check_all_nodes
  ok "Nodes restarted — scores re-hydrated"
fi

# ─── Phase 3: Register Content ───────────────────────────────────────────────
if should_run "register"; then
  step "Phase 3/6 — Register Content"
  hr
  wait_healthy "$NODE_URL" "node1" 30

  info "Registering OH content (TIP_DEV_FORCE_PRESCAN_TIER=high on node → HIGH tier)…"
  info "Content: \"${CONTENT_TEXT:0:80}…\""

  REGISTER_OUT=$(node scripts/register-content.js \
    --pick-first \
    --content "$CONTENT_TEXT" \
    --origin OH \
    --node-url "$NODE_URL" 2>&1)
  echo "$REGISTER_OUT"

  # Extract CTID from output.
  CTID=$(echo "$REGISTER_OUT" | grep -oE 'tip://c/[A-Z]+-[0-9a-f]+-[0-9a-f]+' | head -1)
  if [[ -z "$CTID" ]]; then
    fail "Could not parse CTID from register-content output. Check logs above."
    exit 1
  fi

  # Extract signer tip_id for later use.
  SIGNER_TIP_ID=$(node -e "
    const f=require('./genesis-data/temp-users/temp-users-latest.json');
    console.log(f.users[0].tip_id);
  " 2>/dev/null || echo "")

  save_state
  ok "Content registered — CTID: $CTID"
fi

# ─── Phase 4: File Dispute ────────────────────────────────────────────────────
if should_run "dispute"; then
  step "Phase 4/6 — File Dispute"
  hr

  [[ -n "$CTID" ]] || { fail "--ctid required for --phase=dispute"; exit 1; }
  wait_healthy "$NODE_URL" "node1" 30

  info "Filing origin_mismatch dispute against $CTID (claimed_origin=AG)…"
  node scripts/file-dispute.js \
    --ctid "$CTID" \
    --pick-first \
    --claimed-origin AG \
    --node-url "$NODE_URL"

  ok "Dispute filed"
fi

# ─── Phase 5: Drive Jury ─────────────────────────────────────────────────────
if should_run "jury"; then
  step "Phase 5/6 — Drive Jury (TIP_DEV_BYPASS_VOTE_WINDOWS=1 active)"
  hr

  [[ -n "$CTID" ]] || { fail "--ctid required for --phase=jury"; exit 1; }
  wait_healthy "$NODE_URL" "node1" 30

  info "Submitting jury commits (vote-bias=$VOTE_BIAS)…"
  node scripts/drive-jury.js \
    --ctid "$CTID" \
    --phase COMMIT \
    --vote-bias "$VOTE_BIAS" \
    --node-url "$NODE_URL"

  ok "Commits submitted"

  info "Submitting jury reveals + watching for verdict…"
  node scripts/drive-jury.js \
    --ctid "$CTID" \
    --phase REVEAL \
    --vote-bias "$VOTE_BIAS" \
    --watch \
    --watch-timeout 60 \
    --node-url "$NODE_URL"

  ok "Jury phase complete"
fi

# ─── Phase 6: Scoring Status ─────────────────────────────────────────────────
if should_run "status"; then
  step "Phase 6/6 — Scoring Status"
  hr

  [[ -n "$CTID" ]] || { fail "--ctid required for --phase=status"; exit 1; }
  wait_healthy "$NODE_URL" "node1" 30

  SIGNER_ARG=""
  if [[ -n "${SIGNER_TIP_ID:-}" ]]; then
    SIGNER_ARG="--tip-id $SIGNER_TIP_ID"
  fi

  node scripts/scoring-status.js \
    $SIGNER_ARG \
    --ctid "$CTID" \
    --all-parties \
    --node-url "$NODE_URL"
fi

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}✓ Scoring test complete${RESET}"
if [[ -n "$CTID" ]]; then
  echo -e "  CTID: ${BOLD}$CTID${RESET}"
  echo ""
  echo "  Replay any phase independently:"
  echo "    bash scripts/run-scoring-test.sh --phase dispute --ctid $CTID"
  echo "    bash scripts/run-scoring-test.sh --phase jury    --ctid $CTID --vote-bias DISMISSED"
  echo "    bash scripts/run-scoring-test.sh --phase status  --ctid $CTID"
fi
echo ""
