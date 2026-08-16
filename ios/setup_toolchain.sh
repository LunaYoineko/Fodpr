#!/usr/bin/env bash
# Install SDL2 source for iOS builds. Idempotent: only downloads/extracts what is missing.
# Usage: bash ios/setup_toolchain.sh   (must run on macOS with Xcode installed)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/env.sh"

mkdir -p "$DL_DIR"

# --- macOS + Xcode チェック ---
if [ "$(uname -s)" != "Darwin" ]; then
  echo "ERROR: iOS builds require macOS + Xcode (this machine: $(uname -s))"
  exit 1
fi
if ! command -v xcrun >/dev/null 2>&1 || ! xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1; then
  echo "ERROR: Xcode (iphoneos SDK) not found. Install Xcode from the App Store first."
  exit 1
fi
echo "[ok] Xcode SDK: $(xcrun --sdk iphoneos --show-sdk-path)"

# --- SDL2 ソース ---
if [ ! -d "$SDL_SRC/include/SDL2" ]; then
  echo "[fetch] $SDL_URL"
  curl -sL --retry 3 -o "$SDL_TARBALL" "$SDL_URL"
  echo "[extract] SDL2 $SDL_RELEASE"
  rm -rf "$SDL_SRC"
  mkdir -p "$SDL_SRC"
  tar xzf "$SDL_TARBALL" -C "$SDL_SRC" --strip-components=1
  # SDL2 2.32.10+ flattened include/ (headers directly under include/).
  # Create SDL2/ symlink so bindings and build.sh find <SDL2/SDL.h>
  ln -sfn . "$SDL_SRC/include/SDL2"
fi
echo "[ok] SDL2 source: $SDL_SRC"

# --- SDL2 事前ビルド (実機 + シミュレータ用の静的ライブラリ) ---
# Xcode のスクリプトフェーズからネスト xcodebuild で SDL2 をビルドすると
# シミュレータ向けビルドがクラッシュするため、ここで先にビルドしておく。
build_sdl() {
  local platform="$1" arch="$2"
  local out="$SDL_PREBUILT_DIR/$platform/libSDL2.a"
  if [ -f "$out" ]; then
    echo "[skip] SDL2 ($platform/$arch) already built: $out"
    return
  fi
  local symroot="$SDL_PREBUILT_DIR/.symroot/$platform"
  echo "[build] SDL2 static lib ($platform/$arch)"
  if ! xcodebuild -quiet -project "$SDL_SRC/Xcode/SDL/SDL.xcodeproj" \
    -target "Static Library-iOS" -configuration Release -sdk "$platform" \
    -arch "$arch" ONLY_ACTIVE_ARCH=YES \
    SYMROOT="$symroot" OBJROOT="$symroot/obj" \
    build; then
    echo "ERROR: SDL2 build failed for $platform/$arch"
    exit 1
  fi
  local lib="$(find "$symroot" -name "libSDL2.a" -path "*$platform*" | head -1)"
  if [ -z "$lib" ] || [ ! -f "$lib" ]; then
    echo "ERROR: libSDL2.a not found under $symroot"
    exit 1
  fi
  mkdir -p "$(dirname "$out")"
  cp "$lib" "$out"
  echo "[ok] SDL2 ($platform/$arch): $out"
}

build_sdl iphoneos arm64
if [ "$(uname -m)" = "arm64" ]; then
  build_sdl iphonesimulator arm64
else
  build_sdl iphonesimulator x86_64
fi

echo
echo "All done. Next: bash ios/build.sh  (または ios/FodprChat.xcodeproj を Xcode で開いて Run)"
