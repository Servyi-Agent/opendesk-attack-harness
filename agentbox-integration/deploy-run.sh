#!/usr/bin/env bash
# DEPLOYMENT MODE (requires docker/podman + kernel FUSE; NOT runnable inside
# this sandbox — here the engine runs host-side under supervise-inside.sh).
#
# Launches the OpenDesk execution engine INSIDE an agentbox container with the
# LLM credential gated by the FUSE one-read policy; the broker + UI stay on the
# host (outside). Port 4096 of the container is published for the broker/UI.
#
# Usage: ./deploy-run.sh <path-to-agent-scripts> <sha256-of-node-binary>
set -eu

AGENT_SCRIPTS="${1:?usage: $0 <agent-scripts-dir> <node-sha256>}"
NODE_HASH="${2:?usage: $0 <agent-scripts-dir> <node-sha256>}"
LLM_KEY_FILE="${LLM_KEY_FILE:?set LLM_KEY_FILE to the host file holding the z.ai API key}"

"$AGENT_SCRIPTS/target/release/run-agent" \
    "$NODE_HASH" \
    bash -c '
      mkdir -p /root/.opendesk-config
      ln -sf /fuse/llm-key /root/.opendesk-config/llm-key
      # node (the gate-approved binary) reads the gated key itself via preload;
      # provider config references env://ZAI_API_KEY — no plaintext anywhere
      exec /opt/node22/bin/node -r /root/.opendesk-config/preload-key.js \
        /workspace/OpenDesk/dist/cli/opendesk-debug serve \
        --port 4096 --hostname 0.0.0.0 \
        --config-directory /root/.opendesk-config \
        --use-config-permissions
    ' \
    --secret llm-key "$LLM_KEY_FILE"

# After the box is up (outside):
#   node broker.mjs --url http://127.0.0.1:4096        # white/blacklist + ask UI
# The one-read counter is reset by run-agent on exit; mid-session resets:
#   fuse-client reset --name llm-key
