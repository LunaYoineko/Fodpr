#!/usr/bin/env bash
# Build Fodpr Chat for macOS as a double-clickable GUI .app bundle.
#
#   bash macos/build.sh
#     -> macos/FodprChat.app   (Finder からダブルクリックで起動可能)
#
# 前提: macOS + Xcode コマンドラインツール + Homebrew + Nim
#   (SDL2 は brew install sdl2 で自動インストール。静的ではなく dylib 依存)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/.." && pwd)"

APP=FodprChat
APP_DIR="$DIR/$APP.app"
BUILD_DIR="$DIR/build"

# --- SDL2 チェック ---
if ! brew list sdl2 >/dev/null 2>&1; then
  echo "SDL2 not found. Installing via homebrew..."
  brew install sdl2
fi
SDL2_LIB_DIR="$(brew --prefix sdl2)/lib"

# --- クリーン ---
rm -rf "$APP_DIR"
mkdir -p "$BUILD_DIR" "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"

# --- 1. アプリアイコン (.icns) 生成 ---
if [ ! -f "$BUILD_DIR/FodprChat-1024.png" ]; then
  echo "[build] icon -> FodprChat-1024.png"
  python3 "$DIR/gen_icon.py" "$BUILD_DIR/FodprChat-1024.png"
fi
ICONSET="$BUILD_DIR/FodprChat.iconset"
mkdir -p "$ICONSET"
gen_icon() {
  sips -z "$1" "$1" "$BUILD_DIR/FodprChat-1024.png" --out "$ICONSET/$2" >/dev/null
}
gen_icon 16  icon_16x16.png
gen_icon 32  icon_16x16@2x.png
gen_icon 32  icon_32x32.png
gen_icon 64  icon_32x32@2x.png
gen_icon 128 icon_128x128.png
gen_icon 256 icon_128x128@2x.png
gen_icon 256 icon_256x256.png
gen_icon 512 icon_256x256@2x.png
gen_icon 512 icon_512x512.png
gen_icon 1024 icon_512x512@2x.png
iconutil -c icns "$ICONSET" -o "$BUILD_DIR/$APP.icns"

# --- 2. メニューバー shim のコンパイル ---
echo "[build] fodpr_menu.m -> fodpr_menu.o"
clang -c -fobjc-arc -O2 "$DIR/fodpr_menu.m" -o "$BUILD_DIR/fodpr_menu.o"

# --- 3. Nim -> 実行ファイル ---
echo "[build] Nim -> FodprChat.app/Contents/MacOS/$APP"
nim c -d:release --threads:on \
  --path:"$REPO/src" \
  --passL:"$BUILD_DIR/fodpr_menu.o" \
  --passL:"-framework AppKit -framework Foundation" \
  --passL:"-L$SDL2_LIB_DIR" \
  --passL:"-rpath $SDL2_LIB_DIR" \
  --out:"$APP_DIR/Contents/MacOS/$APP" \
  "$REPO/examples/chat_client.nim"

# --- 4. バンドル構成 (Info.plist / フォント / アイコン) ---
cp "$DIR/Info.plist" "$APP_DIR/Contents/Info.plist"
cp "$REPO/examples/assets/DroidSansFallbackFull.ttf" "$APP_DIR/Contents/Resources/"
cp "$REPO/examples/assets/DejaVuSans.ttf" "$APP_DIR/Contents/Resources/"
cp "$BUILD_DIR/$APP.icns" "$APP_DIR/Contents/Resources/"

# --- 5. コード署名 (ad-hoc) ---
codesign --force --sign - "$APP_DIR" 2>/dev/null || true

echo
echo "Done: $APP_DIR"
echo "Run:  open $APP_DIR"
