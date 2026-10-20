#!/usr/bin/env bash
# Keep the OpenDesk engine alive (HOST MODE — no agentbox container).
# All paths discoverable/overridable via env:
#   ENGINE_NODE     node binary          (default: discovery)
#   ENGINE_DIR      OpenDesk checkout    (default: discovery)
#   ENGINE_CONFIG   config dir with setting.json (default: discovery)
#   OPENDESK_PORT   serve port           (default: 4096)
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${OPENDESK_PORT:-4096}"
LOG() { printf '[engine] %s\n' "$*"; }

find_node() {
    [ -n "${ENGINE_NODE:-}" ] && { echo "$ENGINE_NODE"; return 0; }
    local c
    for c in "$(command -v node 2>/dev/null || true)" \
             "$HOME/.nvm/versions/node/"*/bin/node \
             /usr/bin/node /usr/local/bin/node /opt/node*/bin/node; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    # toolbox fallback (atomic Fedora hosts often have node only there)
    c="$(toolbox run --container agentbox-dev which node 2>/dev/null || toolbox run which node 2>/dev/null || true)"
    [ -n "$c" ] && [ -x "$c" ] && { echo "$c"; return 0; }
    return 1
}
find_engine_dir() {
    [ -n "${ENGINE_DIR:-}" ] && { echo "$ENGINE_DIR"; return 0; }
    local c
    for c in "${AGENTBOX_AGENT_PATH:-$HOME/opendesk}/workspace/OpenDesk" \
             "$HOME/opendesk/workspace/OpenDesk" "$HOME/OpenDesk" "$HOME/src/OpenDesk"; do
        [ -f "$c/dist/cli/opendesk-debug" ] && { echo "$c"; return 0; }
    done
    return 1
}
find_config() {
    [ -n "${ENGINE_CONFIG:-}" ] && { echo "$ENGINE_CONFIG"; return 0; }
    local c
    for c in "${AGENTBOX_AGENT_PATH:-$HOME/opendesk}/config" "$HOME/.config/opendesk"; do
        [ -f "$c/setting.json" ] && { echo "$c"; return 0; }
    done
    return 1
}

NODE_BIN="$(find_node)"     || { LOG "ERROR: no node binary found (set ENGINE_NODE)"; exit 1; }
ENGINE_DIR="$(find_engine_dir)" || { LOG "ERROR: no OpenDesk checkout with dist/ found (set ENGINE_DIR)"; exit 1; }
CONFIG_DIR="$(find_config)" || { LOG "ERROR: no config dir with setting.json found (set ENGINE_CONFIG)"; exit 1; }
LOG "node=$NODE_BIN"
LOG "engine=$ENGINE_DIR"
LOG "config=$CONFIG_DIR"

while true; do
    LOG "starting engine $(date +%T)"
    "$NODE_BIN" "$ENGINE_DIR/dist/cli/opendesk-debug" serve \
        --port "$PORT" --hostname 127.0.0.1 \
        --config-directory "$CONFIG_DIR" \
        --use-config-permissions \
        >> "$DIR/inside.log" 2>&1
    LOG "engine exited rc=$? $(date +%T); restarting in 3s"
    sleep 3
done
