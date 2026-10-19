#!/usr/bin/env bash
# Makes `opendesk` transparent: installs the launcher shim into ~/.local/bin
# (ahead of the real opendesk on PATH) and stamps the agentbox paths.
set -eu
AB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin"
mkdir -p "$BIN"
cat > "$BIN/opendesk" <<EOF
#!/usr/bin/env bash
# agentbox-wrapped opendesk (installed by opendesk-agentbox/install.sh)
export AGENT_SCRIPTS="\${AGENT_SCRIPTS:-$HOME/agent-scripts}"
export AGENTBOX_AGENT_PATH="\${AGENTBOX_AGENT_PATH:-$HOME/opendesk}"
export LLM_KEY_FILE="\${LLM_KEY_FILE:-$HOME/secrets/zai.key}"
exec "$AB/bin/opendesk" "\$@"
EOF
chmod +x "$BIN/opendesk" "$AB/bin/opendesk"
echo "installed: $BIN/opendesk"
echo "assumes:   \$AGENT_SCRIPTS ($HOME/agent-scripts — your agent-scripts checkout)"
echo "           \$AGENTBOX_AGENT_PATH ($HOME/opendesk — dir with workspace/ and config/)"
echo "           \$LLM_KEY_FILE ($HOME/secrets/zai.key)"
echo "override any of them via environment; hash-user? logout+login for ~/.local/bin on some systems"
