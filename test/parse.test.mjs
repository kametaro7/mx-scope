#!/usr/bin/env node
/* 貼り付け解析の単体テスト（DNS は引かない）
 * 使い方: node test/parse.test.mjs
 */
import { createRequire } from 'node:module';
import path from 'node:path';
const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
require(path.join(root, 'i18n.js'));
require(path.join(root, 'i18n', 'ja.js'));
require(path.join(root, 'i18n', 'en.js'));
require(path.join(root, 'rules.js'));
require(path.join(root, 'dns.js'));
const { extractDomains } = globalThis.MXC.dns;

const CONCAT = 'https://www.united-arrows.co.jp/https://www.cando-web.co.jp/https://www.aoyama-syouji.co.jp/https://www.hardoff.co.jp/https://www.shopchannel.co.jp/https://www.studio-alice.co.jp/https://www.sacs-bar.co.jp/https://www.liondor.jp/https://www.aoki-hd.co.jp/https://www.koike-group.co.jp/https://www.honeys.co.jp/https://www.jeans-mate.co.jp/https://store.alpen-group.jp/https://www.joyfulhonda.com/   https://www.chiyodagrp.co.jp/https://www.g-foot.co.jp/https://komehyo-hd.com/https://right-on.co.jp/https://www.vh-s.jp/https://www.aigan.co.jp/https://www.syuppin.co.jp/   https://www.treasurefactory.co.jp/https://www.watts-jp.com/https://www.sagami-grp.co.jp/https://www.taka-q.com/https://www.sanyo-shokai.co.jp/https://www.mimatsu-group.co.jp/https://www.samantha.co.jp/https://www.mandarake.co.jp/https://www.golfdo.co.jp/';

const cases = [
  { name: '区切り無しで連結された 30 件の URL', input: CONCAT, expect: 30,
    head: ['united-arrows.co.jp', 'cando-web.co.jp'], tail: 'golfdo.co.jp' },
  { name: 'スキーム無しで www が連結', input: 'www.aigan.co.jpwww.syuppin.co.jpwww.taka-q.com',
    domains: ['aigan.co.jp', 'syuppin.co.jp', 'taka-q.com'] },
  { name: 'スキームも www も無い co.jp の連結', input: 'honeys.co.jpjeans-mate.co.jp',
    domains: ['honeys.co.jp', 'jeans-mate.co.jp'] },
  { name: '会社名と URL が混在（タブ区切り）', input: '株式会社さくら\thttps://www.sakura.ad.jp/company/',
    domains: ['sakura.ad.jp'], rest: ['株式会社さくら'] },
  { name: 'カンマ区切り', input: 'メルカリ,https://www.mercari.com/jp/', domains: ['mercari.com'], rest: ['メルカリ'] },
  { name: 'メールアドレス', input: 'ご担当 info@kobe-fugetsudo.co.jp まで', domains: ['kobe-fugetsudo.co.jp'] },
  { name: '全角スペース・読点・かっこ', input: '（株）八天堂　https://hattendo.co.jp/、https://www.honeys.co.jp/',
    domains: ['hattendo.co.jp', 'honeys.co.jp'], rest: ['（株）八天堂'] },
  { name: 'かっこで囲まれた URL', input: '「https://www.aigan.co.jp/」【https://www.samantha.co.jp/】',
    domains: ['aigan.co.jp', 'samantha.co.jp'] },
  { name: '全角の URL', input: 'ｈｔｔｐｓ：／／ｗｗｗ．ｒｉｇｈｔ－ｏｎ．ｃｏ．ｊｐ／', domains: ['right-on.co.jp'] },
  { name: 'ファイル名はドメインにしない', input: '一覧.xlsx README.md 集計.csv', domains: [] },
  { name: 'バージョン番号はドメインにしない', input: 'Ver.1.2 build.3', domains: [] },
  { name: '日本語だけの行', input: '株式会社サンプル', domains: [] },
  { name: 'URL とメールと素のドメインの混在', input: 'https://a.example.jp/x?y=1 info@b.example.jp c.example.jp',
    domains: ['a.example.jp', 'b.example.jp', 'c.example.jp'] },
  { name: 'サブドメインは保持（MX が無ければ判定側で上位を試す）', input: 'https://store.alpen-group.jp/', domains: ['store.alpen-group.jp'] },
  { name: 'www とポートと大文字', input: 'HTTP://WWW.Example.CO.JP:8080/Path', domains: ['example.co.jp'] },
];

let ok = 0, ng = 0;
for (const c of cases) {
  const r = extractDomains(c.input);
  const got = r.domains.map(d => d.domain);
  const errs = [];
  if (c.expect != null && got.length !== c.expect) errs.push(`件数 ${got.length} ≠ ${c.expect}`);
  if (c.domains && got.join(',') !== c.domains.join(',')) errs.push(`結果 [${got}] ≠ [${c.domains}]`);
  if (c.head) for (let i = 0; i < c.head.length; i++) if (got[i] !== c.head[i]) errs.push(`${i} 番目 ${got[i]} ≠ ${c.head[i]}`);
  if (c.tail && got[got.length - 1] !== c.tail) errs.push(`最後 ${got[got.length - 1]} ≠ ${c.tail}`);
  if (c.rest && r.rest.join(',') !== c.rest.join(',')) errs.push(`残り [${r.rest}] ≠ [${c.rest}]`);
  if (errs.length) { ng++; console.log(`NG ${c.name}\n   ${errs.join(' / ')}`); } else { ok++; console.log(`OK ${c.name}（${got.length} 件）`); }
}
console.log(`\n${ok}/${cases.length} 通過`);
process.exit(ng ? 1 : 0);
