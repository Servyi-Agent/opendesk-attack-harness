#!/usr/bin/env node
// Minimal OUTSIDE web UI for the agentbox integration.
// Serves a single page that streams permission asks from the engine and lets
// you answer them (once / always / reject). Run on the trusted host:
//   node ui.mjs [--engine http://127.0.0.1:4096] [--port 4196]
import http from 'node:http';

const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 ? process.argv[i + 1] : d; };
const ENGINE = arg('engine', 'http://127.0.0.1:4096');
const PORT = Number(arg('port', 4196));

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>agentbox UI</title>
<style>
body{font-family:system-ui,sans-serif;background:#111;color:#eee;max-width:720px;margin:24px auto;padding:0 12px}
.ask{border:1px solid #444;border-radius:8px;padding:12px;margin:10px 0}
.cmd{font-family:monospace;background:#1c1c1c;padding:8px;border-radius:6px;margin:8px 0;word-break:break-all}
button{margin-right:8px;padding:6px 14px;border:0;border-radius:6px;font-weight:600;cursor:pointer}
.once{background:#2e7d32}.always{background:#1565c0}.reject{background:#c62828}
.log{color:#888;font-size:12px;margin-top:16px}
</style></head><body>
<h3>agentbox — pending permission asks</h3>
<div id="asks"></div><div class="log" id="log"></div>
<script>
const log = (m) => document.getElementById('log').innerHTML += m + '<br>';
async function reply(id, r) {
    const res = await fetch('/reply/' + id + '/' + r, { method: 'POST' });
    log('replied ' + r + ' to ' + id + ' -> ' + res.status);
    document.getElementById('a-' + id)?.remove();
}
function render(p) {
    if (document.getElementById('a-' + p.id)) return;
    const d = document.createElement('div'); d.className = 'ask'; d.id = 'a-' + p.id;
    const subj = p.metadata?.command || p.metadata?.url || p.metadata?.filePath || JSON.stringify(p.metadata?.requests || '');
    d.innerHTML = '<b>' + p.permission + '</b> <span style="color:#888">' + p.id + '</span>'
        + '<div class="cmd">' + String(subj).replace(/</g,'&lt;').slice(0, 400) + '</div>'
        + '<button class="once" onclick="reply(\\'' + p.id + '\\',\\'once\\')">Allow once</button>'
        + '<button class="always" onclick="reply(\\'' + p.id + '\\',\\'always\\')">Always</button>'
        + '<button class="reject" onclick="reply(\\'' + p.id + '\\',\\'reject\\')">Reject</button>';
    document.getElementById('asks').prepend(d);
}
const es = new EventSource('/event');
es.onmessage = (e) => { try { const d = JSON.parse(e.data); if (d.type === 'permission.asked') render(d.properties); } catch {} };
log('listening for permission.asked …');
</script></body></html>`;

http.createServer(async (req, res) => {
    if (req.url === '/' ) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(PAGE); }
    if (req.url === '/event') {
        const target = new URL(ENGINE + '/event');
        const up = http.get({ hostname: target.hostname, port: target.port, path: target.pathname }, (ur) => {
            res.writeHead(ur.statusCode, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
            ur.pipe(res);
        });
        up.on('error', () => { res.writeHead(502); res.end('engine unreachable'); });
        return;
    }
    const m = req.url.match(/^\/reply\/([^/]+)\/(once|always|reject)$/);
    if (m) {
        const up = await fetch(ENGINE + `/permission/${m[1]}/reply`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reply: m[2] })
        });
        res.writeHead(up.status, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ ok: up.ok }));
    }
    res.writeHead(404); res.end('not found');
}).listen(PORT, '127.0.0.1', () => console.log(`agentbox UI outside: http://127.0.0.1:${PORT} (engine ${ENGINE})`));
