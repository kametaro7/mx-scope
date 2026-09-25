#!/bin/sh
# 亀井商店サイト（www.kameishouten.com/mx-scope/）へ、このアプリを反映する。
#   sh tools/publish_to_kameishouten.sh
# 反映先は GitHub Pages のリポジトリ kametaro7/kameishouten-site の作業ツリー。
# ブラウザだけで動くファイル（画面・判定・DNS・翻訳辞書）を置く（server.js・test・tools は不要）。
set -e
SRC=$(cd "$(dirname "$0")/.." && pwd)
DST=${KAMEISHOUTEN_DIR:-$HOME/Desktop/kamei-shoten}
[ -d "$DST/.git" ] || { echo "反映先が見つかりません: $DST"; exit 1; }
node "$SRC/tools/check_i18n.js" > /dev/null || { echo "翻訳辞書に不備があります: node tools/check_i18n.js で確認してください"; exit 1; }
mkdir -p "$DST/mx-scope/i18n"
for f in index.html i18n.js rules.js dns.js app.js; do
  cp "$SRC/$f" "$DST/mx-scope/$f"
done
rsync -a --delete "$SRC/i18n/" "$DST/mx-scope/i18n/"
cd "$DST"
git pull --rebase -q            # 同じサイトを別の作業が更新していることがある
git add mx-scope
git diff --cached --quiet && { echo "変更はありません"; exit 0; }
git commit -q -m "MXスコープを更新" -m "$(cd "$SRC" && git log --oneline -1)"
git push -q
echo "反映しました → https://www.kameishouten.com/mx-scope/"
