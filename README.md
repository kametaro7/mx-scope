# MXスコープ

[English](README.en.md) ・ 日本語

ドメイン（URL・メールアドレスでも可）を入れると、DNS から **メール基盤のブランド** と **オンプレ／クラウド** を判定するローカル Web アプリです。
Google Workspace の営業向けに、判定結果から **見込み度（◎ 有望 / ○ 競合SaaS / △ 要確認 / ✕ 対象外）** も出します。

## すぐ使う（インストール不要）

**https://www.kameishouten.com/mx-scope/** （開発用の確認先: https://kametaro7.github.io/mx-scope/ ）

ブラウザだけで動きます。DNS の問い合わせは Google / Cloudflare の DNS over HTTPS 経由で、判定はすべてブラウザ内で完結します。入力したドメインや結果がサーバーに送られることはありません。

## 対応言語（31 言語）

英語・中国語（簡体／繁体）・スペイン語・ヒンディー語・ロシア語・フランス語・ポルトガル語・アラビア語・日本語・ドイツ語・インドネシア語・トルコ語・イタリア語・韓国語・ペルシア語・ベンガル語・ベトナム語・ウルドゥー語・タイ語・ポーランド語・マラーティー語・テルグ語・タミル語・ジャワ語・オランダ語・グジャラート語・ウクライナ語・カンナダ語・ルーマニア語・アゼルバイジャン語。

- 右上の地球アイコンから切り替えます。URL の `?lang=en` などで直接指定もできます（例: https://www.kameishouten.com/mx-scope/?lang=en ）
- 最初に開いたときは、URL の指定 → 前回選んだ言語 → ブラウザの言語設定の順で決まり、対応していない言語なら英語になります
- 判定したあとに言語を切り替えても、表・根拠・集計・書き出す CSV の見出しがその言語で作り直されます（判定そのものは同じ）
- アラビア語・ペルシア語・ウルドゥー語は右から左の表示になります（ドメインや DNS の値は左から右のまま）
- 言語の一覧と自動判定の順序は世界ライブカメラマップと揃えています

## 手元で動かす（大量件数はこちらが速い）

- **かんたん**: `MXスコープ.command` をダブルクリック → ブラウザで http://localhost:8791 が開きます（Node.js が必要。ローカルの Node リゾルバで高速に引きます）
- **Node が無い場合**: `index.html` をブラウザで直接開いてください（上の公開版と同じく DNS over HTTPS で動きます）
- ターミナルから: `node server.js 8791`

## 使い方

1. **貼り付け**: URL / メールアドレス / ドメインを貼る。1 行 1 件でなくても構いません。

   - 区切りが無いまま URL がつながっていても 1 件ずつ取り出します（`…co.jp/https://…`、`…co.jpwww.…`、`…co.jpb-corp.co.jp`）
   - Excel の列（会社名, URL など）をそのまま貼れば、ドメインの列を自動で見つけ、他の列は結果に引き継ぎます
   - 全角の URL、日本語の読点・かっこ・全角スペース混じりでも解釈します
   - ファイル名（`一覧.xlsx`）やバージョン番号（`Ver.1.2`）はドメインとして拾いません
   - 同じドメインは自動で重複を除きます（除いた数は入力欄の下に表示）
2. **CSV アップロード**: CSV / TSV をドロップ。UTF-8 / Shift_JIS 自動判別。ドメイン列は自動検出（変更可）。
3. **判定する** → 数千件でも一括処理（並列数は変更可）。途中で **中止** できます。
4. 結果は **表をコピー (TSV)**（Excel / スプレッドシートにそのまま貼れる）、**CSV ダウンロード**（Excel で開ける UTF-8 BOM 付き）、**JSON** で出力。
5. 前回の結果はブラウザに保存され、「前回の結果を復元」で戻せます。

## 判定の仕組み

1. 入力を組織ドメインに正規化。MX が無ければ上位ドメイン（sub.example.co.jp → example.co.jp）でも試行。MX が無い場合は関連ドメイン（example.jp ⇔ example.co.jp ⇔ example.com）も参考として確認。
2. **MX** のホスト名をベンダー署名 DB（`rules.js` の `VENDORS`）と照合。
3. 署名に無いホスト（Xserver・さくらなどは MX を自社ドメインに向けるのが標準）は、MX の IP の **逆引き (PTR)**、SPF の `a:sv####.xserver.jp` のようなサーバー名、**AS 番号**（Team Cymru の DNS サービス）、ネームサーバーから、レンタルサーバー事業者 / ISP 回線上の自社サーバー（オンプレ）/ IaaS 上の自前サーバーを推定。
4. **SPF** の include、**DKIM**（`google._domainkey`、`selector1._domainkey`）、**autodiscover** から、ゲートウェイ（Proofpoint、Trend Micro など）の裏側で使われている基盤（Google Workspace / Microsoft 365 など）を推定。
5. **DMARC** の有無・ポリシーも表示（セキュリティ提案の切り口に）。

対象サーバーには一切接続せず、DNS の問い合わせだけで判定します。

## 見込み度の意味

| 記号 | 意味 |
|---|---|
| ◎ 有望 | レンタルサーバー / ISP メール / 自社運用（オンプレ・IaaS）。Google Workspace 移行提案が刺さりやすい |
| ○ 競合SaaS | Microsoft 365、LINE WORKS、CYBERMAIL、Zoho など他社クラウド。リプレース提案 |
| △ 要確認 | ゲートウェイ配下で裏側が読めない、など |
| ✕ 対象外 | すでに Google Workspace、またはメール未使用 |

## ファイル構成

- `index.html` … 画面
- `app.js` … 入力解釈・並列判定・集計・表・エクスポート・表示言語の切り替え
- `i18n.js` … 言語一覧と翻訳関数
- `i18n/<言語>.js` … 翻訳辞書（`ja.js` が原文、`en.js` が他言語の翻訳元。同じキーを 31 言語で持つ）
- `dns.js` … DNS リゾルバ（ローカル API → Google DoH → Cloudflare DoH の順にフォールバック）とドメイン単位の収集
- `rules.js` … ベンダー署名 DB と分類ロジック（純粋関数。Node でも動く）
- `server.js` … ローカルサーバー（静的配信 + `/api/resolve`）
- `test/parse.test.mjs` … 貼り付け解析の単体テスト（DNS を引かない。`node test/parse.test.mjs`）
- `test/run.mjs` … ラベル付きコーパス `test/corpus.json`（実在企業約200件）による回帰テスト（`node test/run.mjs`）
- `test/sample.csv` … 動作確認用のサンプル CSV
- `tools/build_reference.js` … 判定ルール一覧ページの生成（`node tools/build_reference.js > reference.html`）
- `tools/research_gap.js` … 調査結果 JSON と署名 DB の差分レポート
- `tools/check_i18n.js` … 翻訳辞書の検査（キーの過不足・`{n}` などの差し込み・HTML タグを英語版と照合。`node tools/check_i18n.js`）
- `tools/publish_to_kameishouten.sh` … www.kameishouten.com/mx-scope/ への反映（辞書の検査に通らないと反映しない）

## 文言を追加・変更するとき

1. `i18n/ja.js` と `i18n/en.js` に同じキーを足す（画面側は `T('キー')`、判定文は `rules.js` の `T('キー', {差し込み})`）
2. 他の 29 言語にも同じキーを足す（足りないキーは英語で表示されるので、表示が壊れることはありません）
3. `node tools/check_i18n.js` で全言語が合格することを確認
4. JavaScript を変えたら `index.html` の `?v=` を上げる（翻訳辞書も同じ番号で読み直されます）

## 署名の追加・修正

`rules.js` の `VENDORS` に要素を追加します。`mx` は MX ホスト名（小文字・末尾ドット無し）に対する正規表現で、`(^|\.)example\.com$` のようにラベル境界で固定してください。
`ptr` は逆引きホスト名、`spf` は include 先、`asn` は事業者の AS 番号です。

## 限界

- Web サイトのドメインとメールのドメインが違う会社は判定できません（関連ドメインのヒントを表示します）。
- ゲートウェイ配下で DKIM / autodiscover も無い場合、裏側は分かりません。
- 「オンプレ」は「自社ドメイン内の MX ＋ ISP 回線 / 自組織 AS」からの推定で、データセンターに預けた自社サーバーも含みます。
