#!/usr/bin/env bash
# Supervisor: keeps the OpenDesk engine (inside) alive.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while true; do
    echo "[supervisor] starting engine $(date +%T)"
    /opt/node22/bin/node /workspace/OpenDesk/dist/cli/opendesk-debug serve \
        --port "${OPENDESK_PORT:-4096}" --hostname 127.0.0.1 \
        --config-directory /tmp/opencode/odconfig --use-config-permissions \
        >> "$DIR/inside.log" 2>&1
    echo "[supervisor] engine exited rc=$? $(date +%T); restarting in 3s"
    sleep 3
done
