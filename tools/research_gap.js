#!/usr/bin/env node
/* 調査結果 JSON（ワークフロー出力）と rules.js の差分レポート
 * 使い方: node tools/research_gap.js <workflow-result.json>
 * 各ベンダーの観測 MX ホスト / SPF include / ASN / PTR が現在のルールで拾えるかを表示する
 */
'use strict';
const fs = require('fs'); const path = require('path');
require(path.join(__dirname, '..', 'i18n.js'));
require(path.join(__dirname, '..', 'i18n', 'ja.js'));
require(path.join(__dirname, '..', 'rules.js'));
const { matchMx, matchSpf, asnInfo, matchPtr } = globalThis.MXC.rules;
const j = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const groups = j.groups || Object.values(j).filter(x => x && x.vendors).map(x => ({ key: '?', verified: x }));
for (const g of groups) {
  const src = g.verified || g.research; if (!src) { console.log(`== ${g.key}: (no data)`); continue; }
  if (g.key === 'onprem_asn') {
    console.log(`== ${g.key}: ${src.asns.length} ASNs`);
    for (const a of src.asns) { const t = asnInfo(a.asn); const mine = t ? t.kind : '-'; const mark = !t ? 'NEW ' : (t.kind !== ({ isp: 'isp', carrier: 'isp', hosting: 'hosting', cloud_iaas: 'cloud', cdn: 'cdn', colocation: 'hosting', saas: 'cloud', other: 'other' }[a.kind] || a.kind) ? 'DIFF' : 'ok  '); if (mark !== 'ok  ') console.log(`  ${mark} AS${a.asn} ${a.as_name} | ${a.org_ja || ''} | research=${a.kind} mine=${mine} ${a.verified ? '' : '(unverified)'} ${a.note || ''}`); }
    console.log('  keywords:', JSON.stringify(src.as_name_keywords));
    console.log('  ptr_isp:', (src.ptr_patterns_isp || []).map(p => p.regex + ' (' + p.org + ')').join(' ; '));
    console.log('  ptr_hosting:', (src.ptr_patterns_hosting || []).map(p => p.regex + ' (' + p.org + ')').join(' ; '));
    console.log('  heuristics:', (src.onprem_heuristics || []).join(' / '));
    console.log('  exchange:', JSON.stringify(src.exchange_onprem_signals));
    continue;
  }
  console.log(`== ${g.key}: ${src.vendors.length} vendors`);
  for (const v of src.vendors) {
    const lines = [];
    for (const p of v.mx_patterns || []) {
      // パターン自体が既存ルールで拾えるか: 例ホストで確認
      lines.push(`    mx ${p.verified ? 'V' : '-'} ${p.regex}${p.note ? '  // ' + p.note : ''}`);
    }
    for (const e of v.example_domains || []) for (const h of e.observed_mx || []) {
      const host = String(h).replace(/^\d+\s+/, '').replace(/\.$/, '').toLowerCase(); if (!host) continue;
      const m = matchMx(host); lines.push(`    ex ${m ? m.id.padEnd(22) : 'UNMATCHED'.padEnd(22)} ${host}  (${e.domain})`);
    }
    for (const inc of v.spf_includes || []) { const m = matchSpf(inc); if (!m) lines.push(`    spf UNMATCHED ${inc}`); }
    for (const a of v.asn || []) { if (!asnInfo(a.asn)) lines.push(`    asn NEW AS${a.asn} ${a.as_name || ''}`); }
    for (const p of v.ptr_patterns || []) lines.push(`    ptr ${p}`);
    for (const sgn of v.other_dns_signals || []) lines.push(`    signal ${sgn.record_type} ${sgn.name_template} ~ ${sgn.expected_regex} : ${sgn.meaning || ''}`);
    console.log(`  - ${v.id} | ${v.name_ja} | ${v.category}/${v.hosting_type} | conf=${v.confidence}${v.notes ? '\n    note: ' + v.notes.replace(/\n/g, ' ') : ''}`);
    console.log(lines.join('\n'));
  }
  if (src.caveats) console.log('  caveats:', src.caveats.replace(/\n/g, ' '));
}
if (j.critic) {
  console.log('== CRITIC');
  for (const m of j.critic.missing_vendors || []) console.log(`  missing: ${m.name_ja} (${m.name_en}) ${m.verified_by_dig ? '[dig]' : ''} mx=${(m.suggested_mx_patterns || []).join(' ')} spf=${(m.suggested_spf_includes || []).join(' ')} ex=${(m.example_domains || []).join(',')} — ${m.why_common}`);
  for (const p of j.critic.pattern_problems || []) console.log('  problem:', p);
  for (const o of j.critic.other_gaps || []) console.log('  gap:', o);
}
