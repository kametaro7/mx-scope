#!/usr/bin/env node
/* 回帰テスト: ラベル付きコーパス（test/corpus.json）を実際に引いて判定し、期待値と比較する
 * 使い方: node test/run.mjs [corpus.json] [--only=google_workspace] [--verbose]
 * コーパス形式: [{ "domain": "example.co.jp", "expected_platform": "google_workspace", "company": "...", "note": "..." }]
 * expected_platform はベンダー id、または "<id>_behind_gateway" / "exchange_onprem" / "onprem"
 */
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
require(path.join(root, 'rules.js'));
require(path.join(root, 'dns.js'));
const { dns, classify, rules } = globalThis.MXC;

const args = process.argv.slice(2);
const file = args.find(a => !a.startsWith('--')) || path.join(root, 'test', 'corpus.json');
const only = (args.find(a => a.startsWith('--only=')) || '').slice(7);
const verbose = args.includes('--verbose');
const corpus = JSON.parse(fs.readFileSync(file, 'utf8')).filter(e => !only || e.expected_platform.startsWith(only));

// 期待値 → 判定結果の照合ルール
function matches(exp, c) {
  const pid = c.platformId, bid = c.backend ? c.backend.id : '';
  if (exp.endsWith('_behind_gateway')) { const b = exp.replace('_behind_gateway', ''); return (c.platform.cat === 'gateway' || c.platform.cat === 'relay' || c.platform.cat === 'hosting') && bid === b; }
  if (exp === 'exchange_onprem' || exp === 'onprem') return c.hosting === 'onprem' || c.hosting === 'onprem_maybe';
  return pid === exp || bid === exp;
}

const t0 = Date.now();
let ok = 0, ng = 0; const fails = [];
const conc = 8; let next = 0; const results = [];
await Promise.all(Array.from({ length: conc }, async () => {
  while (next < corpus.length) {
    const i = next++; const e = corpus[i];
    try {
      const d = await dns.lookupDomain(e.domain, { deep: 'auto' });
      const c = classify(d);
      const hit = matches(e.expected_platform, c);
      results[i] = { e, c, d, hit };
    } catch (err) { results[i] = { e, c: null, d: null, hit: false, err: String(err) }; }
  }
}));
for (const r of results) {
  if (r.hit) ok++; else { ng++; fails.push(r); }
  if (verbose || !r.hit) console.log(`${r.hit ? 'OK ' : 'NG '} ${r.e.domain.padEnd(28)} 期待=${r.e.expected_platform.padEnd(28)} 判定=${r.c ? r.c.label : r.err} [${r.c ? r.c.hostingLabel : ''}] MX=${r.d ? r.d.mx.map(m => m.host).join(',') : ''}`);
}
console.log(`\n${ok}/${corpus.length} 一致 (${((ok / Math.max(1, corpus.length)) * 100).toFixed(1)}%)  ${((Date.now() - t0) / 1000).toFixed(1)} 秒  DNS ${dns.state.stats.queries} 回`);
process.exit(ng ? 1 : 0);
