#!/usr/bin/env bash
# Restart (or start if not running) the prompt-injection attack server.
# Usage: ./restart.sh [--keep]
#   --keep : leave the server alone if it is already healthy
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER="$DIR/server.mjs"
PORT="${ATTACK_PORT:-8094}"
BASE="http://127.0.0.1:$PORT"

healthy() { curl -fsS "$BASE/status" >/dev/null 2>&1; }

if [ "${1:-}" = "--keep" ] && healthy; then
    echo "attack server already healthy on $BASE"
    exit 0
fi

# Stop any instance running THIS server script. Match strictly: the process
# must be a `node` invocation of the server path (first cmdline token == node),
# and never this script itself ($$) or its parent shell ($PPID).
for pid in $(pgrep -f "server\.mjs" 2>/dev/null); do
    [ "$pid" = "$$" ] && continue
    [ "$pid" = "$PPID" ] && continue
    cmd="$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | head -2 | tr '\n' ' ')" || continue
    set -- $cmd
    if [ "${1:-}" = "node" ] && [ "${2:-}" = "$SERVER" ]; then
        kill -9 "$pid" 2>/dev/null || true
        echo "stopped stale server pid $pid"
    fi
done
sleep 0.5

if healthy; then
    echo "ERROR: $BASE still responds but no matching process was found;"
    echo "an unknown process owns port $PORT. Retry with: ATTACK_PORT=<other> $0"
    exit 1
fi

nohup node "$SERVER" >> "$DIR/server.out" 2>&1 &
for _ in $(seq 1 40); do
    if healthy; then
        echo "attack server up on $BASE"
        curl -fsS "$BASE/status" && echo
        exit 0
    fi
    sleep 0.25
done

echo "ERROR: server failed to start; last log lines:"
tail -5 "$DIR/server.out"
exit 1
