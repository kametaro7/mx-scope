#!/usr/bin/env node
/* 翻訳辞書の検査: node tools/check_i18n.js [言語コード...]
 * 英語（en）を基準に、全言語のキーの過不足・差し込み {name} の一致・HTML タグの一致・空文字を調べる。
 * 問題があれば終了コード 1。
 */
'use strict';
const path = require('path');
const fs = require('fs');
const root = path.join(__dirname, '..');
require(path.join(root, 'i18n.js'));
const { LANGS, DICT } = globalThis.MXC.i18n;
const want = process.argv.slice(2);
const codes = want.length ? want : LANGS.map(l => l[0]);

const load = (c) => { const f = path.join(root, 'i18n', c + '.js'); if (!fs.existsSync(f)) return false; require(f); return !!DICT[c]; };
load('en'); load('ja');
const ref = DICT.en;
const refKeys = Object.keys(ref).filter(k => !k.endsWith('.one'));   // 単数形 "<キー>.one" は任意
const vars = (s) => (String(s).match(/\{\w+\}/g) || []).sort().join(' ');
const tags = (s) => (String(s).match(/<\/?[a-z][^>]*>/gi) || []).map(t => t.replace(/\s+/g, ' ')).sort().join(' ');

let bad = 0, missingFiles = [];
for (const c of codes) {
  if (!load(c)) { missingFiles.push(c); continue; }
  const d = DICT[c], errs = [];
  for (const k of refKeys) {
    if (!(k in d)) { errs.push(`キー無し: ${k}`); continue; }
    const v = d[k];
    // 区切り記号（sep.*）は空白だけでもよい（タイ語の文の区切りなど）
    if (typeof v !== 'string' || (!v.trim() && !(k.startsWith('sep.') && v.length))) { errs.push(`空: ${k}`); continue; }
    if (vars(v) !== vars(ref[k])) errs.push(`差し込み不一致 ${k}: [${vars(v)}] ≠ en [${vars(ref[k])}]`);
    if (tags(v) !== tags(ref[k])) errs.push(`タグ不一致 ${k}: ${tags(v)} ≠ en ${tags(ref[k])}`);
    if (!k.endsWith('_html') && /<[a-z]/i.test(v)) errs.push(`HTML でないキーにタグ: ${k}`);
  }
  for (const k of Object.keys(d)) {
    if (k in ref) continue;
    const base = k.endsWith('.one') ? k.slice(0, -4) : null;   // 単数形（任意）
    if (!base || !(base in ref)) { errs.push(`余分なキー: ${k}`); continue; }
    if (vars(d[k]) !== vars(ref[base])) errs.push(`差し込み不一致 ${k}: [${vars(d[k])}] ≠ en ${base} [${vars(ref[base])}]`);
    if (/<[a-z]/i.test(d[k])) errs.push(`HTML でないキーにタグ: ${k}`);
  }
  // 製品名・技術用語は訳さない
  for (const k of ['th.spf', 'th.dmarc', 'btn.json', 'ex.spf', 'ex.dmarc', 'why.spf', 'ev.dmarc'])
    if (d[k] !== undefined && !/SPF|DMARC|JSON/.test(d[k])) errs.push(`技術用語が消えた: ${k}`);
  if (errs.length) { bad++; console.log(`NG ${c}\n  ` + errs.slice(0, 30).join('\n  ') + (errs.length > 30 ? `\n  … 他 ${errs.length - 30} 件` : '')); }
  else console.log(`OK ${c}（${Object.keys(d).length} キー）`);
}
if (missingFiles.length) console.log(`\n辞書ファイルが無い言語: ${missingFiles.join(', ')}`);
console.log(`\n${codes.length - bad - missingFiles.length}/${codes.length} 言語が合格`);
process.exit(bad || missingFiles.length ? 1 : 0);
