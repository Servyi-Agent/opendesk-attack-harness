#!/usr/bin/env node
// Full outside client: chat + permission asks in one page.
//   node desk.mjs [--engine http://127.0.0.1:4096] [--port 4196]
import http from 'node:http';

const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 ? process.argv[i + 1] : d; };
const ENGINE = arg('engine', 'http://127.0.0.1:4096');
const PORT = Number(arg('port', 4196));
const E = new URL(ENGINE);

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>opendesk</title>
<style>
body{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;display:flex;flex-direction:column;height:100vh}
header{padding:8px 14px;background:#1a1a2e;font-weight:600}
main{flex:1;display:flex;overflow:hidden}
#chat{flex:1;display:flex;flex-direction:column;border-right:1px solid #333}
#msgs{flex:1;overflow-y:auto;padding:12px}
.m{margin:6px 0;padding:8px 12px;border-radius:10px;max-width:80%;white-space:pre-wrap;font-size:14px}
.u{background:#23527c;align-self:flex-end;margin-left:auto}
.a{background:#222}
.t{color:#7aa2f7;font-size:12px;margin:10px 0 2px}
#asks{width:360px;overflow-y:auto;padding:10px;background:#161616}
.ask{border:1px solid #555;border-radius:8px;padding:10px;margin:8px 0;background:#1e1e1e}
.cmd{font-family:monospace;background:#111;padding:6px;border-radius:6px;margin:6px 0;word-break:break-all;font-size:12px}
button{margin-right:6px;padding:5px 12px;border:0;border-radius:6px;font-weight:600;cursor:pointer}
.once{background:#2e7d32}.always{background:#1565c0}.reject{background:#c62828}
#input{display:flex;padding:10px;gap:8px;background:#181818}
#input input{flex:1;background:#222;border:1px solid #444;color:#eee;border-radius:8px;padding:10px;font-size:14px}
#input button{background:#333;color:#eee}
h4{margin:6px 0;color:#888;text-transform:uppercase;font-size:11px;letter-spacing:.08em}
</style></head><body>
<header>opendesk — engine inside the agentbox <span id="status" style="float:right;color:#888"></span></header>
<main><div id="chat">
  <div id="msgs"><div class="t">connecting…</div></div>
  <div id="input"><input id="q" placeholder="Message the agent… (Enter to send)" autofocus><button onclick="send()">Send</button></div>
</div>
<div id="asks"><h4>Permission asks</h4><div id="asklist"></div><h4>Activity</h4><div id="log" style="color:#777;font-size:11px"></div></div></main>
<script>
let SID = null, sending = false;
const msgs = document.getElementById('msgs'), logel = document.getElementById('log');
const esc = s => String(s).replace(/</g,'&lt;');
const log = m => { logel.innerHTML = esc(m) + '<br>' + logel.innerHTML; };
function add(cls, text){ const d=document.createElement('div'); d.className='m '+cls; d.textContent=text; msgs.appendChild(d); msgs.scrollTop=msgs.scrollHeight; }
async function newSession(){
  const r = await fetch('/api/session', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:'agentbox session'})});
  const j = await r.json(); SID = j.id; msgs.innerHTML=''; add('a','Engine ready inside the agentbox. Ask me anything.'); log('session ' + SID);
}
async function send(){
  const q = document.getElementById('q'); const text = q.value.trim(); if(!text || !SID || sending) return;
  q.value=''; sending=true; add('u', text); add('t','agent working…');
  try {
    const r = await fetch('/api/session/'+SID+'/message', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({prompt:text})});
    const j = await r.json();
    let out = '';
    const walk = x => { if(!x) return; if(Array.isArray(x)) return x.forEach(walk);
      if(typeof x==='object'){ if(typeof x.text==='string') out += x.text + '\\n'; Object.values(x).forEach(walk); } };
    walk(j);
    msgs.lastChild?.remove(); add('a', out.trim() || JSON.stringify(j).slice(0,400));
  } catch(e){ add('a','ERROR: '+e.message); }
  sending=false;
}
document.getElementById('q').addEventListener('keydown', e => { if(e.key==='Enter') send(); });
async function reply(id, r){
  await fetch('/reply/'+id+'/'+r, {method:'POST'});
  document.getElementById('a-'+id)?.remove(); log('permission '+id+' → '+r);
}
function renderAsk(p){
  if(document.getElementById('a-'+p.id)) return;
  const d=document.createElement('div'); d.className='ask'; d.id='a-'+p.id;
  const subj = p.metadata?.command || p.metadata?.url || p.metadata?.filePath || '';
  d.innerHTML = '<b>'+esc(p.permission)+'</b><div class="cmd">'+esc(subj).slice(0,400)+'</div>'
    +'<button class="once" onclick="reply(\\''+p.id+'\\',\\'once\\')">Allow once</button>'
    +'<button class="always" onclick="reply(\\''+p.id+'\\',\\'always\\')">Always</button>'
    +'<button class="reject" onclick="reply(\\''+p.id+'\\',\\'reject\\')">Reject</button>';
  document.getElementById('asklist').prepend(d); log('asked '+p.permission+': '+String(subj).slice(0,60));
}
new EventSource('/event').onmessage = e => { try { const d=JSON.parse(e.data);
  if(d.type==='permission.asked') renderAsk(d.properties);
  if(d.type==='session.status') document.getElementById('status').textContent=(d.properties?.status)||'';
} catch{} };
newSession();
</script></body></html>`;

const proxy = (path, method, body, res) => {
    const opts = { hostname: E.hostname, port: E.port, path, method, headers: {} };
    if (body) { opts.headers['Content-Type'] = 'application/json'; }
    const up = http.request(opts, ur => {
        res.writeHead(ur.statusCode, { 'Content-Type': ur.headers['content-type'] || 'application/json' });
        ur.pipe(res);
    });
    up.on('error', () => { res.writeHead(502); res.end(JSON.stringify({ error: 'engine unreachable' })); });
    if (body) up.write(body);
    up.end();
};

http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(PAGE); }
    if (req.url === '/event') {
        const up = http.get({ hostname: E.hostname, port: E.port, path: '/event' }, ur => {
            res.writeHead(ur.statusCode, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
            ur.pipe(res);
        });
        up.on('error', () => { res.writeHead(502); res.end(); });
        return;
    }
    if (req.url === '/api/session' && req.method === 'POST') { let b=''; req.on('data',c=>b+=c); req.on('end',()=>proxy('/session','POST',b,res)); return; }
    let m;
    if ((m = req.url.match(/^\/api\/session\/([^/]+)\/message$/)) && req.method === 'POST') {
        let b=''; req.on('data',c=>b+=c); req.on('end',()=>proxy(`/session/${m[1]}/message`,'POST',b,res)); return;
    }
    if ((m = req.url.match(/^\/reply\/([^/]+)\/(once|always|reject)$/))) { proxy(`/permission/${m[1]}/reply`,'POST',JSON.stringify({reply:m[2]}),res); return; }
    res.writeHead(404); res.end('not found');
}).listen(PORT, '127.0.0.1', () => console.log(`opendesk UI: http://127.0.0.1:${PORT} → engine ${ENGINE}`));
