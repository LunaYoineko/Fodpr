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
fi
echo "[ok] SDL2 source: $SDL_SRC"

echo
echo "All done. Next: bash ios/build.sh"
