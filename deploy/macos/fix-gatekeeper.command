#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
app=""
if [[ -d "/Applications/CheeseWAF.app" ]]; then
  app="/Applications/CheeseWAF.app"
elif [[ -d "./CheeseWAF.app" ]]; then
  app="$(pwd)/CheeseWAF.app"
else
  osascript -e 'display dialog "先把 CheeseWAF 拖进「应用程序」，再运行这个脚本。\nDrag CheeseWAF into Applications first." buttons {"OK"} default button 1' >/dev/null
  exit 1
fi
xattr -dr com.apple.quarantine "$app" 2>/dev/null || true
open "$app"
