// Preloaded with the engine (node = the gate-approved binary): reads the
// gated LLM key at startup and exports it for the engine's provider config.
// Deployed INSIDE the agentbox; expects the key at /root/.opendesk-config/llm-key.
const fs = require('fs');
try {
    process.env.ZAI_API_KEY = fs.readFileSync('/root/.opendesk-config/llm-key', 'utf8').trim();
} catch (e) {
    console.error('[preload-key] gated key unreadable:', e.code || e.message);
    // fail closed: engine starts without the key; provider auth will fail
}
