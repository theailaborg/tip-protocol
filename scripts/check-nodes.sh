#!/usr/bin/env bash
# check-nodes.sh — Quick health + divergence check across all 5 local nodes.
# Run after every test session before marking work as done.
# Green state: all state_merkle_root values identical, byzantineForkHalt null on all.

PORTS=(4000 4100 4200 4300 4400)

echo ""
echo "══════════════════════════════════════════"
echo "  TIP Node Health Check"
echo "══════════════════════════════════════════"

# ── 1. State-root agreement ───────────────────────────────────────────────────
echo ""
echo "── State Merkle Root (must all match) ──"
ROOTS=()
for port in "${PORTS[@]}"; do
  result=$(curl -s --max-time 3 "http://localhost:$port/v1/state-root" 2>/dev/null)
  if echo "$result" | python3 -c "import sys,json; json.load(sys.stdin)['data']" &>/dev/null 2>&1; then
    line=$(echo "$result" | python3 -c "
import sys,json
d=json.load(sys.stdin)['data']
root=d.get('state_merkle_root','?')
print(f\":$port  r={d.get('round','?'):>6}  root={root[:32]}…\")
" 2>/dev/null)
    root=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'].get('state_merkle_root',''))" 2>/dev/null)
    ROOTS+=("$root")
  else
    line=":$port  ✗ no response"
    ROOTS+=("MISSING")
  fi
  echo "  $line"
done

# Check uniqueness
UNIQUE=$(printf '%s\n' "${ROOTS[@]}" | sort -u | wc -l | tr -d ' ')
echo ""
if [ "$UNIQUE" -eq 1 ] && [ "${ROOTS[0]}" != "MISSING" ]; then
  echo "  ✅  All roots AGREE"
else
  echo "  ❌  DIVERGENCE DETECTED — roots differ across nodes!"
fi

# ── 2. Anti-entropy divergence counters ──────────────────────────────────────
echo ""
echo "── Anti-Entropy Counters (cumulative since node start) ──"
for port in "${PORTS[@]}"; do
  result=$(curl -s --max-time 3 "http://localhost:$port/v1/stats" 2>/dev/null)
  echo "$result" | python3 -c "
import sys,json
try:
  ae=json.load(sys.stdin)['data']['consensus']['antiEntropy']['metrics']
  div=ae['consensus_divergence_total']
  halts=ae['byzantine_fork_halts_triggered']
  gaps=ae['gaps_pulled']
  flag = '❌' if div > 0 or halts > 0 else '✅'
  print(f'  {flag} :$port  divergences={div}  halts={halts}  gaps_pulled={gaps}')
except Exception as e:
  print(f'  ✗ :$port  error reading stats')
" 2>/dev/null
done

# ── 3. Halt status ────────────────────────────────────────────────────────────
echo ""
echo "── Byzantine Fork Halt Status ──"
ALL_OK=true
for port in "${PORTS[@]}"; do
  result=$(curl -s --max-time 3 "http://localhost:$port/v1/stats" 2>/dev/null)
  echo "$result" | python3 -c "
import sys,json
try:
  n=json.load(sys.stdin)['data']['consensus']['narwhal']
  halt=n.get('byzantineForkHalt')
  round=n.get('round','?')
  flag = '❌ HALTED' if halt else '✅'
  print(f'  {flag} :$port  round={round}  halt={halt}')
except:
  print(f'  ✗ :$port  error')
" 2>/dev/null
done

# ── 4. Peer connectivity ──────────────────────────────────────────────────────
echo ""
echo "── Peer Connectivity ──"
for port in "${PORTS[@]}"; do
  result=$(curl -s --max-time 3 "http://localhost:$port/health" 2>/dev/null)
  echo "$result" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)['data']
  peers=d['peers']['connected']
  flag = '✅' if peers >= 4 else ('⚠️ ' if peers >= 2 else '❌')
  print(f'  {flag} :$port  peers_connected={peers}')
except:
  print(f'  ✗ :$port  no response')
" 2>/dev/null
done

echo ""
echo "══════════════════════════════════════════"
echo ""
