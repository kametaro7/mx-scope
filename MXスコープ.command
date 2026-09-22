#!/bin/bash
# ダブルクリックで起動: ローカルサーバーを立ち上げてブラウザで開く
cd "$(dirname "$0")"
PORT=8791
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js が見つかりません。https://nodejs.org からインストールしてください。"
  echo "（Node が無くても index.html をブラウザで直接開けば DNS over HTTPS で動きます）"
  read -n 1 -s -r -p "何かキーを押すと閉じます"
  exit 1
fi
( sleep 1; open "http://localhost:$PORT" ) &
node server.js "$PORT"
