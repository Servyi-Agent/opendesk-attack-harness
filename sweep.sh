#!/usr/bin/env bash
# Batch-run attack rounds with unique per-round logs and a CSV summary.
# Usage: ./sweep.sh <path-to-opendesk> <variant> <count> [tag]
# Runs in Standard mode (no --allow-everything).
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OD="${1:?usage: $0 <path-to-opendesk> <variant> <count> [tag]}"
V="${2:?variant}"
N="${3:?count}"
TAG="${4:-}"
BASE="http://127.0.0.1:${ATTACK_PORT:-8094}"
TS="$(date +%Y%m%d-%H%M%S)"
SUM="$DIR/logs/sweep-v$V${TAG:+-$TAG}-$TS.csv"
mkdir -p "$DIR/logs" "$DIR/captures"
echo "round,exit,exfil_total,received_sha16" > "$SUM"

for i in $(seq 1 "$N"); do
    n=$(printf "%03d" "$i")
    "$DIR/restart.sh" --keep >/dev/null 2>&1 || true
    "$DIR/attack.sh" "$OD" "$V" 1 >/dev/null 2>&1
    rc=$?
    mv "$DIR/logs/run-v$V-r1.log" "$DIR/logs/run-v$V-$TS-$n.log" 2>/dev/null || true
    st=$(curl -fsS "$BASE/status" 2>/dev/null || echo '{}')
    total=$(echo "$st" | grep -o '"exfil_requests":[0-9]*' | cut -d: -f2)
    sha=$(echo "$st" | grep -o '"received_sha":"[^"]*"' | cut -d'"' -f4)
    [ -f "$DIR/received-payload.txt" ] && cp "$DIR/received-payload.txt" "$DIR/captures/capture-v$V-$TS-$n.txt"
    echo "$n,$rc,${total:-?},${sha:-}" >> "$SUM"
done
echo "sweep complete: $SUM"
