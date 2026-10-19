#!/usr/bin/env bash
# Start the OpenDesk EXECUTION ENGINE — this runs INSIDE the agentbox
# (in deployment: launched by run-agent inside the gated container; in this
# sandbox: a separate process, with the agentbox FUSE gate providing the
# secret boundary where the kernel allows mounts).
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${OPENDESK_PORT:-4096}"
cd /workspace/OpenDesk
exec /opt/node22/bin/node dist/cli/opendesk-debug serve \
    --port "$PORT" --hostname 127.0.0.1 \
    --config-directory /tmp/opencode/odconfig --use-config-permissions
