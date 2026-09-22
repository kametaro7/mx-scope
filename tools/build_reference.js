#!/usr/bin/env node
/* 判定ルール一覧の参照ページ（Artifact 公開用・静的）を rules.js から生成する
 * 使い方: node tools/build_reference.js > /path/to/reference.html
 */
'use strict';
const path = require('path');
require(path.join(__dirname, '..', 'rules.js'));
const { VENDORS, ASN_TABLE, HOSTING_JA, PROSPECT_JA } = globalThis.MXC.rules;
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const CAT_JA = { saas: 'クラウド SaaS', hosting: 'レンタルサーバー', gateway: 'セキュリティゲートウェイ', isp: 'ISP メール', iaas: 'IaaS（自社運用）', relay: '転送・配信', consumer: '個人向け' };
const order = ['saas', 'gateway', 'hosting', 'isp', 'iaas', 'relay', 'consumer'];
const groups = new Map();
for (const v of VENDORS) { if (!groups.has(v.cat)) groups.set(v.cat, []); groups.get(v.cat).push(v); }
// 正規表現を「読める形」に（エスケープ除去・ラベル境界表現の簡略化）
const human = (re) => re.replace(/^\(\^\|\\\.\)/, '*.').replace(/^\^/, '').replace(/\$$/, '').replace(/\\\./g, '.').replace(/\\d\+/g, '###').replace(/\\d\*/g, '#').replace(/\\d/g, '#').replace(/\[a-z0-9-\]\+/g, '＊').replace(/\[a-z0-9\]\+/g, '＊').replace(/\(\?:/g, '(');
let rows = '';
for (const cat of order) {
  const list = groups.get(cat) || []; if (!list.length) continue;
  rows += `<h2 id="${cat}">${esc(CAT_JA[cat] || cat)} <span class="n">${list.length} 種</span></h2><div class="tbl"><table><thead><tr><th>ブランド</th><th>MX ホスト名のパターン</th><th>SPF include / 逆引き / AS</th><th>見込み</th></tr></thead><tbody>`;
  for (const v of list) {
    const p = PROSPECT_JA[v.prospect] || PROSPECT_JA['?'];
    const extra = [];
    if (v.spf && v.spf.length) extra.push('<b>SPF</b> ' + v.spf.map(x => `<code>${esc(human(x))}</code>`).join(' '));
    if (v.ptr && v.ptr.length) extra.push('<b>PTR</b> ' + v.ptr.map(x => `<code>${esc(human(x))}</code>`).join(' '));
    if (v.asn && v.asn.length) extra.push('<b>AS</b> ' + v.asn.map(a => `AS${a}`).join(' '));
    if (v.dkim && v.dkim.length) extra.push('<b>DKIM</b> ' + v.dkim.map(d => `<code>${esc(d.sel)}._domainkey</code>`).join(' '));
    rows += `<tr><td class="name">${esc(v.name)}</td><td>${(v.mx || []).map(x => `<code>${esc(human(x))}</code>`).join('<br>')}</td><td class="extra">${extra.join('<br>') || '<span class="muted">—</span>'}</td><td><span class="chip p-${v.prospect === '?' ? 'Q' : v.prospect}">${esc(p.mark + ' ' + p.label)}</span></td></tr>`;
  }
  rows += '</tbody></table></div>';
}
const asnRows = Object.entries(ASN_TABLE).sort((a, b) => a[1].kind.localeCompare(b[1].kind) || Number(a[0]) - Number(b[0]))
  .map(([asn, t]) => `<tr><td>AS${asn}</td><td>${esc(t.name)}</td><td>${esc({ isp: 'ISP/通信事業者 → オンプレ濃厚', hosting: 'ホスティング', cloud: 'クラウド IaaS', cdn: 'CDN', own: '組織自身' }[t.kind] || t.kind)}</td></tr>`).join('');
process.stdout.write(`<title>MXスコープ 判定ルール</title>
<style>
:root{--bg:#f3f4f6;--surface:#fff;--ink:#1b2130;--ink-2:#414a5c;--muted:#6b7385;--line:#dde1e8;--accent:#0d5c63;--accent-soft:#dfeff0;--good:#1e7b45;--good-soft:#e0f3e7;--warn:#9a5b00;--warn-soft:#fbefd9;--info:#2a5db0;--info-soft:#e5edfa;--neutral:#5b6474;--neutral-soft:#e9ecf1;--code:#eef1f5}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#101318;--surface:#181c23;--ink:#e6e9ef;--ink-2:#b5bcc9;--muted:#8b93a5;--line:#2a303b;--accent:#5cc8cf;--accent-soft:#143236;--good:#66cf8d;--good-soft:#15301f;--warn:#f2b653;--warn-soft:#3a2b10;--info:#8fb6f7;--info-soft:#172641;--neutral:#a7aebc;--neutral-soft:#262b35;--code:#232833}}
:root[data-theme="dark"]{--bg:#101318;--surface:#181c23;--ink:#e6e9ef;--ink-2:#b5bcc9;--muted:#8b93a5;--line:#2a303b;--accent:#5cc8cf;--accent-soft:#143236;--good:#66cf8d;--good-soft:#15301f;--warn:#f2b653;--warn-soft:#3a2b10;--info:#8fb6f7;--info-soft:#172641;--neutral:#a7aebc;--neutral-soft:#262b35;--code:#232833}
body{background:var(--bg);color:var(--ink);font-family:"BIZ UDPGothic","Hiragino Sans","Yu Gothic UI",system-ui,sans-serif;font-size:14px;line-height:1.6;padding-block:24px 48px;padding-inline:16px;margin:0}
.wrap{max-width:1100px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}h1 small{font-size:13px;color:var(--muted);font-weight:400;margin-left:10px}
.lead{color:var(--ink-2);margin:0 0 16px;max-width:70ch}
h2{font-size:16px;margin:26px 0 8px;color:var(--accent)}h2 .n{font-size:12px;color:var(--muted);font-weight:400;margin-left:8px}
.tbl{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:720px;font-size:13px}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;color:var(--ink-2);background:var(--accent-soft)}
td.name{font-weight:700;white-space:nowrap}
td.extra{color:var(--ink-2);font-size:12px}
code{font-family:"IBM Plex Mono",Menlo,Consolas,monospace;font-size:12px;background:var(--code);padding:0 5px;border-radius:4px;white-space:nowrap}
.chip{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;white-space:nowrap}
.p-A{background:var(--good-soft);color:var(--good)}.p-B{background:var(--warn-soft);color:var(--warn)}.p-C{background:var(--info-soft);color:var(--info)}.p-X,.p-Q{background:var(--neutral-soft);color:var(--neutral)}
.muted{color:var(--muted)}
nav{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:13px;margin-bottom:8px}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;margin:10px 0 0;font-size:13px}
.note{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:16px 0;color:var(--ink-2);font-size:13px}
</style>
<div class="wrap">
<h1>MXスコープ 判定ルール <small>${VENDORS.length} ブランド・${Object.keys(ASN_TABLE).length} AS</small></h1>
<p class="lead">ドメインの MX レコードのホスト名がどのパターンに当たると、どのメール基盤と判定されるかの一覧です。<code>*.</code> はサブドメイン、<code>#</code> は数字、<code>＊</code> は任意の英数字を表します。MX がどれにも当たらない場合は、MX の IP の逆引き（PTR）と AS 番号から推定します。</p>
<nav>${order.filter(c => groups.has(c)).map(c => `<a href="#${c}">${esc(CAT_JA[c])}</a>`).join('')}<a href="#asn">AS 番号表</a></nav>
<div class="legend">${Object.entries(PROSPECT_JA).map(([k, p]) => `<span><span class="chip p-${k === '?' ? 'Q' : k}">${esc(p.mark + ' ' + p.label)}</span> ${esc(p.desc)}</span>`).join('')}</div>
${rows}
<h2 id="asn">AS 番号表 <span class="n">自社ドメイン内の MX の切り分けに使用</span></h2>
<div class="note">MX が <code>mail.example.co.jp</code> のように自社ドメイン内を指す場合、その IP の AS が ISP／通信事業者ならオンプレ（自社設置）、クラウド IaaS なら「IaaS 上で自社運用」、ホスティング事業者ならレンタルサーバーと判定します。</div>
<div class="tbl"><table><thead><tr><th>AS</th><th>事業者</th><th>種別</th></tr></thead><tbody>${asnRows}</tbody></table></div>
<p class="muted" style="margin-top:20px">本体アプリ（貼り付け・CSV 一括判定）はローカルで動作します。この一覧は判定ルールの参照用です。</p>
</div>
`);
