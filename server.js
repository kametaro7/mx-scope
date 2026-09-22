#!/usr/bin/env node
/* MXスコープ — ローカルサーバー（静的配信 + /api/resolve）
 * 使い方: node server.js [port]   → http://localhost:8791
 * /api/resolve?name=example.com&type=15 は DNS over HTTPS(JSON) と同じ形で返す。
 */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { Resolver } = require('dns').promises;

const PORT = parseInt(process.argv[2] || process.env.PORT || '8791', 10);
const ROOT = __dirname;
const resolver = new Resolver({ timeout: 5000, tries: 2 });
const servers = (process.env.MXSCOPE_DNS || '8.8.8.8,1.1.1.1').split(',').map(s => s.trim()).filter(Boolean);
if (servers.length) resolver.setServers(servers);

const TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV' };
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.md': 'text/plain; charset=utf-8', '.csv': 'text/csv; charset=utf-8' };

async function resolveJson(name, type) {
  const t = parseInt(type, 10);
  const q = { name: name + '.', type: t };
  const out = { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [q], Answer: [] };
  const push = (data) => out.Answer.push({ name: name + '.', type: t, TTL: 300, data });
  try {
    switch (TYPES[t]) {
      case 'MX': (await resolver.resolveMx(name)).forEach(r => push(`${r.priority} ${r.exchange}.`)); break;
      case 'TXT': (await resolver.resolveTxt(name)).forEach(chunks => push(chunks.map(c => `"${c.replace(/"/g, '\\"')}"`).join(' '))); break;
      case 'A': (await resolver.resolve4(name)).forEach(push); break;
      case 'AAAA': (await resolver.resolve6(name)).forEach(push); break;
      case 'CNAME': (await resolver.resolveCname(name)).forEach(v => push(v + '.')); break;
      case 'NS': (await resolver.resolveNs(name)).forEach(v => push(v + '.')); break;
      case 'PTR': {
        const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa$/i.exec(name);
        const list = m ? await resolver.reverse(`${m[4]}.${m[3]}.${m[2]}.${m[1]}`) : await resolver.resolvePtr(name);
        list.forEach(v => push(v + '.')); break;
      }
      case 'SRV': (await resolver.resolveSrv(name)).forEach(r => push(`${r.priority} ${r.weight} ${r.port} ${r.name}.`)); break;
      default: out.Status = 4; // NOTIMP
    }
  } catch (e) {
    const code = e && e.code;
    if (code === 'ENOTFOUND') out.Status = 3;           // NXDOMAIN
    else if (code === 'ENODATA' || code === 'ESERVFAIL' && false) out.Status = 0; // NODATA → 空の Answer
    else if (code === 'ETIMEOUT' || code === 'ESERVFAIL' || code === 'ECONNREFUSED') out.Status = 2;
    else if (code === 'EREFUSED') out.Status = 5;
    else if (code === 'ECANCELLED' || code === 'EBADRESP') out.Status = 2;
    else out.Status = 2;
    out.Comment = String(code || e);
    // NXDOMAIN と NODATA の区別: Node は ENOTFOUND を両方に使うことがあるため SOA/NS で存在確認
    if (out.Status === 3) {
      try { await resolver.resolveNs(name); out.Status = 0; } catch (e2) {
        try { await resolver.resolveAny ? await resolver.resolve(name, 'SOA') : null; out.Status = 0; } catch (e3) { /* 本当に存在しない可能性 */
          // 親ドメインが存在するサブドメイン（例: _dmarc.example.com）は NODATA 扱いにする
          const parent = name.split('.').slice(1).join('.');
          if (parent && parent.includes('.')) { try { await resolver.resolveNs(parent); out.Status = 0; } catch (e4) { /* NXDOMAIN のまま */ } }
        }
      }
    }
  }
  return out;
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (u.pathname === '/api/ping') { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ ok: true, servers })); return; }
  if (u.pathname === '/api/resolve') {
    const name = String(u.searchParams.get('name') || '').replace(/\.$/, '').toLowerCase();
    const type = u.searchParams.get('type') || '15';
    if (!/^[a-z0-9_.-]{1,253}$/.test(name)) { res.statusCode = 400; res.end('bad name'); return; }
    try { const j = await resolveJson(name, type); res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(j)); }
    catch (e) { res.statusCode = 500; res.end(String(e)); }
    return;
  }
  let p = decodeURIComponent(u.pathname); if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(ROOT, p));
  if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.statusCode = 404; res.end('not found'); return; }
  res.setHeader('Content-Type', MIME[path.extname(file)] || 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-store');
  fs.createReadStream(file).pipe(res);
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`MXスコープ: http://localhost:${PORT}  (DNS: ${servers.join(', ')})  Ctrl+C で終了`);
});
