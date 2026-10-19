#!/usr/bin/env node
// OpenDesk agentbox permission broker (OUTSIDE the agentbox).
//
// Subscribes to the served engine's /event SSE stream. For every
// `permission.asked` event it applies the white/black lists from rules.json:
//   - blacklist match  -> auto reject
//   - whitelist match  -> auto allow ('once')
//   - otherwise        -> ask the user (UI seam: --auto deny|allow|always for
//                         headless operation; interactive readline otherwise)
// 'always' replies are persisted back into rules.json (the list learns).
// Every decision is appended to decisions.jsonl (audit).
//
// Usage: node broker.mjs [--url http://127.0.0.1:4096] [--auto deny|always|passthrough]
//   --auto passthrough : lists decide known patterns; unknown asks are left
//                        for the UI (or any other client) to answer.

import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import http from 'node:http';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const BASE = process.env.OPENDESK_URL || 'http://127.0.0.1:4096';
const RULES = path.join(HERE, 'rules.json');
const AUDIT = path.join(HERE, 'decisions.jsonl');

const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 ? process.argv[i + 1] : d; };
const AUTO = arg('auto', null); // null = interactive

let rules = JSON.parse(fs.readFileSync(RULES, 'utf8'));
const saveRules = () => fs.writeFileSync(RULES, JSON.stringify(rules, null, 2) + '\n');

// minimal glob: prefix**, **suffix, **, exact
function globMatch(pattern, value) {
    if (pattern === value) return true;
    if (pattern.endsWith('/**')) return value.startsWith(pattern.slice(0, -2));
    if (pattern.startsWith('**/')) return value.endsWith(pattern.slice(3)) || value.includes('/' + pattern.slice(3));
    if (pattern.includes('**')) {
        const [pre, post] = pattern.split('**');
        return value.startsWith(pre) && value.endsWith(post);
    }
    return false;
}
const reMatch = (p, v) => { try { return new RegExp(p).test(v); } catch { return false; } };

function subjectOf(permission, meta) {
    if (permission === 'bash') return meta.command || '';
    if (permission === 'webfetch') return meta.url || '';
    if (permission === 'read' || permission === 'edit') return meta.filePath || meta.filepath || '';
    if (permission === 'websearch') return meta.query || '';
    return '';
}

function decide(permission, subject) {
    for (const p of rules.blacklist[permission] || [])
        if ((permission === 'read' || permission === 'edit') ? globMatch(p, subject) : reMatch(p, subject))
            return { action: 'reject', why: `blacklist: ${p}` };
    for (const p of rules.whitelist[permission] || [])
        if ((permission === 'read' || permission === 'edit') ? globMatch(p, subject) : reMatch(p, subject))
            return { action: 'once', why: `whitelist: ${p}` };
    return { action: 'ask', subject };
}

async function reply(id, r) {
    const res = await fetch(`${BASE}/permission/${id}/reply`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reply: r })
    });
    return res.ok;
}

function askUser(permission, subject) {
    if (AUTO === 'deny') return Promise.resolve({ reply: 'reject' });
    if (AUTO === 'always') return Promise.resolve({ reply: 'always' });
    if (AUTO === 'once') return Promise.resolve({ reply: 'once' });
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question(`\n[agentbox] ${permission.toUpperCase()} request: ${String(subject).slice(0, 160)}\n[a]llow once / [A]lways / [r]eject? `, (a) => {
            rl.close();
            const ans = a.trim().toLowerCase();
            resolve({ reply: ans === 'a' ? 'once' : ans === 'always' || ans === 'A'.toLowerCase() ? 'always' : ans === '' ? 'once' : 'reject' });
        });
    });
}

function learn(permission, subject, pattern) {
    rules.whitelist[permission] = rules.whitelist[permission] || [];
    if (!rules.whitelist[permission].includes(pattern)) {
        rules.whitelist[permission].push(pattern);
        saveRules();
        console.log(`[agentbox] learned whitelist rule: ${permission} ${pattern}`);
    }
}

function audit(entry) { fs.appendFileSync(AUDIT, JSON.stringify({ t: new Date().toISOString(), ...entry }) + '\n'); }

async function handle(info) {
    const permission = info.permission;
    const subject = subjectOf(permission, info.metadata || {});
    const d = decide(permission, subject);
    let replyKind, learned = null;
    if (d.action === 'reject' || d.action === 'once') {
        replyKind = d.action === 'reject' ? 'reject' : 'once';
        console.log(`[agentbox] ${permission} ${d.action.toUpperCase()} (${d.why}): ${String(subject).slice(0, 100)}`);
    } else if (AUTO === 'passthrough') {
        console.log(`[agentbox] ${permission} PASSTHROUGH to UI: ${String(subject).slice(0, 100)}`);
        audit({ id: info.id, permission, subject: String(subject).slice(0, 300), decision: 'passthrough', why: 'unlisted', learned: null });
        return;
    } else {
        const u = await askUser(permission, subject);
        replyKind = u.reply;
        if (u.reply === 'always') {
            // learn a prefix pattern for paths/urls, exact command otherwise
            learned = (permission === 'read' || permission === 'edit') && subject.includes('/')
                ? subject.slice(0, subject.lastIndexOf('/')) + '/**'
                : (permission === 'webfetch') ? subject : subject;
            learn(permission, subject, learned);
        }
        console.log(`[agentbox] ${permission} user said ${u.reply.toUpperCase()}: ${String(subject).slice(0, 100)}`);
    }
    await reply(info.id, replyKind);
    audit({ id: info.id, permission, subject: String(subject).slice(0, 300), decision: replyKind, why: d.why || 'user', learned });
}

async function main() {
    console.log(`[agentbox] broker outside, engine at ${BASE}, mode: ${AUTO ? `auto=${AUTO}` : 'interactive'}`);
    for (;;) {
        try {
            await new Promise((resolveP, rejectP) => {
                const req = http.get(`${BASE}/event`, (res) => {
                    if (res.statusCode !== 200) { res.resume(); return rejectP(new Error(`status ${res.statusCode}`)); }
                    let buf = '';
                    res.setEncoding('utf8');
                    res.on('data', (chunk) => {
                        buf += chunk;
                        let nl;
                        while ((nl = buf.indexOf('\n')) >= 0) {
                            const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
                            if (!line.startsWith('data:')) continue;
                            let evt; try { evt = JSON.parse(line.slice(5).trim()); } catch { continue; }
                            if (evt.type === 'permission.asked') handle(evt.properties || {}).catch(() => {});
                        }
                    });
                    res.on('end', () => rejectP(new Error('stream ended')));
                    res.on('error', rejectP);
                });
                req.on('error', rejectP);
            });
        } catch (e) {
            console.log(`[agentbox] event stream down (${e.message}); retrying in 2s`);
            await new Promise(r => setTimeout(r, 2000));
        }
    }
}
main();
