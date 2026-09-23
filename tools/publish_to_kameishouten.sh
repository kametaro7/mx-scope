#!/bin/sh
# 亀井商店サイト（www.kameishouten.com/mx-scope/）へ、このアプリを反映する。
#   sh tools/publish_to_kameishouten.sh
# 反映先は GitHub Pages のリポジトリ kametaro7/kameishouten-site の作業ツリー。
# ブラウザだけで動く 4 ファイルを置く（server.js・test・tools は不要）。
set -e
SRC=$(cd "$(dirname "$0")/.." && pwd)
DST=${KAMEISHOUTEN_DIR:-$HOME/Desktop/kamei-shoten}
[ -d "$DST/.git" ] || { echo "反映先が見つかりません: $DST"; exit 1; }
mkdir -p "$DST/mx-scope"
for f in index.html rules.js dns.js app.js; do
  cp "$SRC/$f" "$DST/mx-scope/$f"
done
cd "$DST"
git pull --rebase -q            # 同じサイトを別の作業が更新していることがある
git add mx-scope
git diff --cached --quiet && { echo "変更はありません"; exit 0; }
git commit -q -m "MXスコープを更新" -m "$(cd "$SRC" && git log --oneline -1)"
git push -q
echo "反映しました → https://www.kameishouten.com/mx-scope/"
