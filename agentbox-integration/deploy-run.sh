#!/usr/bin/env bash
# DEPLOYMENT MODE — run the OpenDesk engine INSIDE an agentbox container.
# Run from your agent_path (dir containing workspace/); the workspace is
# mounted at /workspace inside the box and is the ONLY guaranteed path, so
# everything engine-related is staged under workspace/.agentbox-engine/.
#
# Usage:
#   LLM_KEY_FILE=~/.secrets/zai.key ./deploy-run.sh ~/…/agent-scripts
# Env:
#   IMAGE=agentbox            container image tag
#   NODE_BIN=/usr/bin/node    node binary INSIDE the image
#   FORCE_HASH=…              skip hash derivation ('*' for smoke tests)
set -eu

AGENT_SCRIPTS="${1:?usage: $0 <agent-scripts-dir>}"
IMAGE="${IMAGE:-agentbox}"
NODE_BIN="${NODE_BIN:-/usr/bin/node}"
LLM_KEY_FILE="${LLM_KEY_FILE:?set LLM_KEY_FILE to the host file holding the z.ai API key}"

if ! podman image exists "$IMAGE"; then
    echo "building image $IMAGE from $AGENT_SCRIPTS …"
    podman build -t "$IMAGE" "$AGENT_SCRIPTS"
fi

HASH="${FORCE_HASH:-$(podman run --rm --entrypoint /usr/bin/sha256sum "$IMAGE" "$NODE_BIN" | cut -d' ' -f1)}"
echo "gating secret to binary: $NODE_BIN (sha256 ${HASH:0:16}…) inside $IMAGE"

WS="$(pwd)/workspace"
[ -f "$WS/OpenDesk/dist/cli/opendesk-debug" ] || { echo "MISSING: $WS/OpenDesk/dist/cli/opendesk-debug — clone/copy OpenDesk there and build dist first"; exit 1; }
STAGE="$WS/.agentbox-engine"
mkdir -p "$STAGE"
cp "$(dirname "$BASH_SOURCE")/preload-key.js" "$STAGE/preload-key.js"
[ -f "$STAGE/setting.json" ] || cp "$(dirname "$BASH_SOURCE")/setting.example.json" "$STAGE/setting.json" 2>/dev/null \
    || echo '{"note":"place your odconfig setting.json here (without inline api_key)"}' > "$STAGE/setting.json"
echo "staged engine config in $STAGE"

"$AGENT_SCRIPTS/target/release/run-agent" \
    "$HASH" \
    bash -c '
      set -e
      ln -sf /fuse/llm-key /workspace/.agentbox-engine/llm-key
      cd /workspace
      exec '"$NODE_BIN"' -r /workspace/.agentbox-engine/preload-key.js \
        /workspace/OpenDesk/dist/cli/opendesk-debug serve \
        --port 4096 --hostname 0.0.0.0 \
        --config-directory /workspace/.agentbox-engine \
        --use-config-permissions
    ' \
    --secret llm-key "$LLM_KEY_FILE"
