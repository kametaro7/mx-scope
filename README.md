# MXスコープ

ドメイン（URL・メールアドレスでも可）を入れると、DNS から **メール基盤のブランド** と **オンプレ／クラウド** を判定するローカル Web アプリです。
Google Workspace の営業向けに、判定結果から **見込み度（◎ 有望 / ○ 競合SaaS / △ 要確認 / ✕ 対象外）** も出します。

## すぐ使う（インストール不要）

**https://kametaro7.github.io/mx-scope/**

ブラウザだけで動きます。DNS の問い合わせは Google / Cloudflare の DNS over HTTPS 経由で、判定はすべてブラウザ内で完結します。入力したドメインや結果がサーバーに送られることはありません。

## 手元で動かす（大量件数はこちらが速い）

- **かんたん**: `MXスコープ.command` をダブルクリック → ブラウザで http://localhost:8791 が開きます（Node.js が必要。ローカルの Node リゾルバで高速に引きます）
- **Node が無い場合**: `index.html` をブラウザで直接開いてください（上の公開版と同じく DNS over HTTPS で動きます）
- ターミナルから: `node server.js 8791`

## 使い方

1. **貼り付け**: 1 行 1 件で URL / メールアドレス / ドメインを貼る。Excel の列（会社名,URL など）をそのまま貼っても、ドメインの列を自動で見つけ、他の列は結果に引き継ぎます。
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
- `app.js` … 入力解釈・並列判定・集計・表・エクスポート
- `dns.js` … DNS リゾルバ（ローカル API → Google DoH → Cloudflare DoH の順にフォールバック）とドメイン単位の収集
- `rules.js` … ベンダー署名 DB と分類ロジック（純粋関数。Node でも動く）
- `server.js` … ローカルサーバー（静的配信 + `/api/resolve`）
- `test/run.mjs` … ラベル付きコーパス `test/corpus.json`（実在企業約200件）による回帰テスト（`node test/run.mjs`）
- `test/sample.csv` … 動作確認用のサンプル CSV
- `tools/build_reference.js` … 判定ルール一覧ページの生成（`node tools/build_reference.js > reference.html`）
- `tools/research_gap.js` … 調査結果 JSON と署名 DB の差分レポート

## 署名の追加・修正

`rules.js` の `VENDORS` に要素を追加します。`mx` は MX ホスト名（小文字・末尾ドット無し）に対する正規表現で、`(^|\.)example\.com$` のようにラベル境界で固定してください。
`ptr` は逆引きホスト名、`spf` は include 先、`asn` は事業者の AS 番号です。

## 限界

- Web サイトのドメインとメールのドメインが違う会社は判定できません（関連ドメインのヒントを表示します）。
- ゲートウェイ配下で DKIM / autodiscover も無い場合、裏側は分かりません。
- 「オンプレ」は「自社ドメイン内の MX ＋ ISP 回線 / 自組織 AS」からの推定で、データセンターに預けた自社サーバーも含みます。
