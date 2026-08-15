#!/usr/bin/env bash
# Build Fodpr Chat for iOS.
#
#   Device (arm64, 実機向け):  bash ios/build.sh
#     -> ios/out/iphoneos/FodprChat.app (ad-hoc 署名) + ios/out/iphoneos/FodprChat.ipa
#   Simulator:                 bash ios/build.sh --sim
#     -> ios/out/iphonesimulator/FodprChat.app (署名不要)
#
# Pipeline:
#   1. Nim -> libfodpr.a   (--os:ios 静的ライブラリ, SDL2 は静的リンク)
#   2. SDL2 -> libSDL2.a   (SDL 公式 Xcode プロジェクト "Static Library-iOS")
#   3. clang でリンクして FodprChat.app を作成 (Info.plist + フォントをバンドル)
#   4. ad-hoc コード署名
#   5. (device) Payload/FodprChat.app を zip して .ipa を生成
#
# 注意: 開発者アカウント不要。ad-hoc 署名の .ipa は AltStore/SideStore 等で
# サイドロードするか、Xcode の無料プロビジョニング (Personal Team) でインストールする。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/env.sh"
REPO="$(cd "$DIR/.." && pwd)"

APP_SRC="${APP_SRC:-$REPO/examples/chat_client.nim}"
case "$APP_SRC" in
  /*) : ;;
  *) APP_SRC="$REPO/$APP_SRC" ;;
esac

SIM=0
LIBS_ONLY=0
for a in "$@"; do
  case "$a" in
    --sim) SIM=1 ;;
    --libs-only) LIBS_ONLY=1 ;;
    *) echo "WARN: unknown arg: $a" ;;
  esac
done

log() { echo "[build] $*"; }

# ---------------------------------------------------------------------------
# 0. 環境チェック
# ---------------------------------------------------------------------------
if [ "$(uname -s)" != "Darwin" ]; then
  echo "ERROR: iOS build requires macOS + Xcode (this machine: $(uname -s))"
  exit 1
fi
if ! command -v nim >/dev/null 2>&1; then
  echo "ERROR: nim not found in PATH. Install via choosenim: https://nim-lang.org/install_unix.html"
  exit 1
fi
if [ ! -d "$SDL_SRC/include/SDL2" ]; then
  echo "ERROR: SDL2 source not found. Run: bash ios/setup_toolchain.sh"
  exit 1
fi

if [ "$SIM" = 1 ]; then
  SDK=iphonesimulator
  # Apple Silicon Mac は arm64、Intel Mac は x86_64 のシミュレータで動作
  case "$(uname -m)" in
    arm64) ARCH=arm64 ;;
    *) ARCH=x86_64 ;;
  esac
else
  SDK=iphoneos
  ARCH=arm64
fi
SYSROOT="$(xcrun --sdk "$SDK" --show-sdk-path)"
MIN="$MIN_IOS"
# デプロイターゲットフラグ (simulator は専用フラグが必要)
if [ "$SIM" = 1 ]; then
  MIN_FLAG="-mios-simulator-version-min=$MIN"
else
  MIN_FLAG="-mios-version-min=$MIN"
fi
OUT="$DIR/out/$SDK"
NIM_LIB="$OUT/libfodpr.a"
APP_DIR="$OUT/$APP_NAME.app"

mkdir -p "$OUT"
rm -rf "$APP_DIR"

# ---------------------------------------------------------------------------
# 1. Nim -> libfodpr.a
# ---------------------------------------------------------------------------
log "1/4  Nim -> libfodpr.a (os:ios cpu:$ARCH sdk:$SDK) [src: $APP_SRC]"
# --dynlibOverride:SDL2 で sdl2 バインディングの dynlib を静的リンクに切り替え
nim c -d:release --os:ios --cpu:"$ARCH" --app:staticlib --cc:clang --threads:on \
  --dynlibOverride:SDL2 \
  --path:"$REPO/src" \
  --passC:"-arch $ARCH -isysroot $SYSROOT -I$SDL_SRC/include $MIN_FLAG -Wno-unused-command-line-argument" \
  --out:"$NIM_LIB" \
  "$APP_SRC" 2>&1 | tail -3
if [ ! -f "$NIM_LIB" ]; then
  echo "ERROR: libfodpr.a was not produced"
  exit 1
fi
log "    -> $NIM_LIB"

# ---------------------------------------------------------------------------
# 2. SDL2 -> libSDL2.a (公式 Xcode プロジェクト)
# ---------------------------------------------------------------------------
log "2/4  SDL2 -> libSDL2.a (target: Static Library-iOS, sdk: $SDK)"
SDL_SYMROOT="$OUT/sdl-symroot"
xcodebuild -quiet -project "$SDL_SRC/Xcode/SDL/SDL.xcodeproj" \
  -target "Static Library-iOS" -configuration Release -sdk "$SDK" \
  -arch "$ARCH" ONLY_ACTIVE_ARCH=YES \
  SYMROOT="$SDL_SYMROOT" OBJROOT="$SDL_SYMROOT/obj" \
  build 2>&1 | tail -5
SDL_LIB="$(find "$SDL_SYMROOT" -name "libSDL2.a" -path "*$SDK*" | head -1)"
if [ -z "$SDL_LIB" ] || [ ! -f "$SDL_LIB" ]; then
  echo "ERROR: libSDL2.a not found under $SDL_SYMROOT"
  exit 1
fi
log "    -> $SDL_LIB"
cp "$SDL_LIB" "$OUT/libSDL2.a"

# ライブラリのみモード (Xcode プロジェクトのプリビルド用)。ここで終了
if [ "$LIBS_ONLY" = 1 ]; then
  echo
  echo "Done (libs only)."
  echo "  $NIM_LIB"
  echo "  $OUT/libSDL2.a"
  exit 0
fi

# ---------------------------------------------------------------------------
# 3. リンクして .app 作成
# ---------------------------------------------------------------------------
log "3/4  Link FodprChat.app"
mkdir -p "$APP_DIR"
cp "$SDL_LIB" "$OUT/libSDL2.a"

# SDL iOS 公式 Demo と同じフレームワーク一式 (config.xcconfig より)
FRAMEWORKS=(
  -framework AVFoundation -framework AudioToolbox -framework CoreGraphics
  -framework CoreHaptics -framework CoreMotion -framework Foundation
  -framework GameController -framework Metal -framework OpenGLES
  -framework QuartzCore -framework UIKit
  -framework CoreAudio -framework CoreVideo -framework CoreBluetooth -framework Security
)

# -Xlinker -all_load: SDL_uikit_main (main を提供) と全 SDL オブジェクトを必ず取込む
xcrun -sdk "$SDK" clang -arch "$ARCH" -isysroot "$SYSROOT" \
  "$MIN_FLAG" \
  -Xlinker -all_load \
  "$NIM_LIB" "$OUT/libSDL2.a" \
  "${FRAMEWORKS[@]}" \
  -o "$APP_DIR/$APP_NAME"
log "    -> $APP_DIR/$APP_NAME"

# Info.plist をテンプレートから生成
sed -e "s|@BUNDLE_ID@|$APP_BUNDLE_ID|g" \
    -e "s|@EXECUTABLE@|$APP_NAME|g" \
    -e "s|@DISPLAY_NAME@|$APP_DISPLAY_NAME|g" \
    -e "s|@VERSION@|$APP_VERSION|g" \
    -e "s|@BUILD@|$APP_BUILD|g" \
    -e "s|@MIN_IOS@|$MIN|g" \
    "$DIR/templates/Info.plist.tpl" > "$APP_DIR/Info.plist"

# フォントをバンドル (SDL_RWFromFile は Apple ではバンドル内を優先して探す)
cp "$REPO/examples/assets/DroidSansFallbackFull.ttf" "$APP_DIR/"
cp "$REPO/examples/assets/DejaVuSans.ttf" "$APP_DIR/"

# ---------------------------------------------------------------------------
# 4. コード署名
# ---------------------------------------------------------------------------
if [ "$SIM" = 1 ]; then
  log "4/4  Simulator: 署名不要"
else
  log "4/4  Codesign (ad-hoc)"
  codesign --force --sign - "$APP_DIR"
fi
log "    -> $APP_DIR"

# ---------------------------------------------------------------------------
# 5. .ipa 生成 (device のみ)
# ---------------------------------------------------------------------------
if [ "$SIM" = 0 ]; then
  IPA_DIR="$OUT/Payload"
  rm -rf "$IPA_DIR"
  mkdir -p "$IPA_DIR"
  cp -R "$APP_DIR" "$IPA_DIR/"
  # AltStore/SideStore は Payload/FodprChat.app の zip を .ipa として扱う
  (cd "$OUT" && zip -q -r "$APP_NAME.ipa" Payload)
  log "IPA: $OUT/$APP_NAME.ipa"
fi

echo
echo "Done."
if [ "$SIM" = 1 ]; then
  echo "Run in Simulator:"
  echo "  xcrun simctl boot \"$(xcrun simctl list devices available | grep -m1 iPhone | grep -o '([^)]*[0-9][^)]*)' | tr -d '()')\" || true"
  echo "  open $OUT/$APP_NAME.app"
else
  echo "Install via Xcode (free provisioning / Personal Team) or sideload the .ipa:"
  echo "  $OUT/$APP_NAME.ipa"
fi
