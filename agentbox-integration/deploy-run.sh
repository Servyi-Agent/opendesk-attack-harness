#!/usr/bin/env bash
# DEPLOYMENT MODE — run the OpenDesk engine INSIDE an agentbox container.
# Run this from your agent_path (the dir containing workspace/ and config/):
#   /var/home/jonas/opendesk/
#     ├── workspace/   <- mounted at /workspace inside the box (workdir)
#     │   └── OpenDesk/  (clone/copy the repo here; symlinks outside won't resolve)
#     └── config/      <- mounted at /root/.config/<agent> inside
#
# Usage:
#   LLM_KEY_FILE=~/.secrets/zai.key ./deploy-run.sh ~/…/agent-scripts
# Env:
#   IMAGE=agentbox            container image tag (podman build -t agentbox …/agent-scripts)
#   NODE_BIN=/usr/bin/node    node binary INSIDE the image
#   FORCE_HASH=…              skip hash derivation (e.g. '*' for smoke tests)
set -eu

AGENT_SCRIPTS="${1:?usage: $0 <agent-scripts-dir>}"
IMAGE="${IMAGE:-agentbox}"
NODE_BIN="${NODE_BIN:-/usr/bin/node}"
LLM_KEY_FILE="${LLM_KEY_FILE:?set LLM_KEY_FILE to the host file holding the z.ai API key}"

# 1. image must exist
if ! podman image exists "$IMAGE"; then
    echo "building image $IMAGE from $AGENT_SCRIPTS …"
    podman build -t "$IMAGE" "$AGENT_SCRIPTS"
fi

# 2. hash the node binary that will actually run INSIDE the box
HASH="${FORCE_HASH:-$(podman run --rm --entrypoint /usr/bin/sha256sum "$IMAGE" "$NODE_BIN" | cut -d' ' -f1)}"
echo "gating secret to binary: $NODE_BIN (sha256 ${HASH:0:16}…) inside $IMAGE"

# 3. stage engine files into the mounted workspace (copied: symlinks out of the mount don't resolve in-box)
WS="$(pwd)/workspace"
[ -f "$WS/OpenDesk/dist/cli/opendesk-debug" ] || { echo "missing $WS/OpenDesk/dist/cli/opendesk-debug — clone/copy OpenDesk there first"; exit 1; }
mkdir -p config
[ -f config/preload-key.js ] || cp "$(dirname "$BASH_SOURCE")/preload-key.js" config/
[ -f config/setting.json ]   || echo '{"note":"copy your odconfig setting.json here (without inline api_key)"}' > config/setting.json

# 4. launch: run-agent creates/reuses the box, gates llm-key to the hashed node, execs the engine
"$AGENT_SCRIPTS/target/release/run-agent" \
    "$HASH" \
    bash -c '
      set -e
      mkdir -p /root/.opendesk-config
      ln -sf /fuse/llm-key /root/.opendesk-config/llm-key
      cd /workspace
      exec '"$NODE_BIN"' -r /root/.config/config/preload-key.js \
        /workspace/OpenDesk/dist/cli/opendesk-debug serve \
        --port 4096 --hostname 0.0.0.0 \
        --config-directory /root/.opendesk-config \
        --use-config-permissions
    ' \
    --secret llm-key "$LLM_KEY_FILE"

# 5. from OUTSIDE, once the box is up:
#   IP=$(podman inspect agentbox-<shorthash> | grep -oP '"IPAddress": "\K[0-9.]+')
#   node broker.mjs --url http://$IP:4096 --auto deny
#   node ui.mjs     --engine http://$IP:4096     # open http://127.0.0.1:4196
