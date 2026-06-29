#!/usr/bin/env bash
# Star every provisioned TIP dashboard so each appears as a direct link in
# Grafana's left sidebar ("Starred"). Stars are per-user runtime state (stored
# in Grafana's DB, not provisioned), so re-run this after `docker compose down -v`.
#
# Usage: ./grafana/star-dashboards.sh
# Env:   GF_URL  (default http://localhost:3030)
#        GF_AUTH (default admin:admin — match your .env)
set -euo pipefail

GF_URL="${GF_URL:-http://localhost:3030}"
GF_AUTH="${GF_AUTH:-admin:admin}"

uids=$(curl -sf -u "$GF_AUTH" "$GF_URL/api/search?type=dash-db" \
  | grep -o '"uid":"[^"]*"' | cut -d'"' -f4 || true)

if [ -z "$uids" ]; then
  echo "No dashboards found at $GF_URL (is Grafana up, and GF_AUTH correct?)" >&2
  exit 1
fi

for uid in $uids; do
  if curl -sf -o /dev/null -u "$GF_AUTH" -X POST \
       "$GF_URL/api/user/stars/dashboard/uid/$uid"; then
    echo "starred $uid"
  else
    echo "failed to star $uid" >&2
  fi
done
