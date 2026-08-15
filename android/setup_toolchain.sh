#!/usr/bin/env bash
# Install JDK 17, Android cmdline-tools, NDK r27c and SDL2 source.
# Idempotent: only downloads/extracts what is missing.
# Usage: bash android/setup_toolchain.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/env.sh"

mkdir -p "$DL_DIR" "$SDK_HOME"

fetch() { # fetch <url> <dest>
  if [ ! -f "$2" ]; then
    echo "[fetch] $1"
    curl -sL --retry 3 -o "$2" "$1"
  fi
}

# --- JDK 17 (Temurin) ---
if [ -z "$JDK_HOME" ] || [ ! -x "$JDK_HOME/bin/java" ]; then
  JDK_TARBALL="$DL_DIR/jdk17.tar.gz"
  fetch "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse" "$JDK_TARBALL"
  echo "[extract] JDK 17"
  tar xzf "$JDK_TARBALL" -C "$TOOLCHAIN_HOME"
  JDK_HOME="$(ls -d "$TOOLCHAIN_HOME"/jdk-17* | head -1)"
fi
echo "[ok] JDK: $JDK_HOME"

# --- cmdline-tools ---
CLT_ZIP="$DL_DIR/commandlinetools.zip"
if [ ! -x "$CMDLINE_TOOLS/bin/sdkmanager" ]; then
  fetch "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip" "$CLT_ZIP"
  echo "[extract] cmdline-tools"
  rm -rf "$SDK_HOME/cmdline-tools"
  mkdir -p "$SDK_HOME/cmdline-tools"
  unzip -q -o "$CLT_ZIP" -d "$SDK_HOME/cmdline-tools"
  mv "$SDK_HOME/cmdline-tools/cmdline-tools" "$CMDLINE_TOOLS"
fi
echo "[ok] cmdline-tools"

# --- NDK r27c ---
if [ ! -x "$NDK_DIR/ndk-build" ]; then
  NDK_ZIP="$DL_DIR/android-ndk-r27c-linux.zip"
  fetch "https://dl.google.com/android/repository/android-ndk-r27c-linux.zip" "$NDK_ZIP"
  echo "[extract] NDK r27c (~1 min)"
  unzip -q -o "$NDK_ZIP" -d "$TOOLCHAIN_HOME"
fi
echo "[ok] NDK: $NDK_DIR"

# --- SDL2 source ---
if [ ! -d "$SDL_SRC/android-project" ]; then
  fetch "$SDL_URL" "$SDL_TARBALL"
  echo "[extract] SDL2 $SDL_RELEASE"
  rm -rf "$SDL_SRC"
  mkdir -p "$SDL_SRC"
  tar xzf "$SDL_TARBALL" -C "$SDL_SRC" --strip-components=1
fi
echo "[ok] SDL2 source: $SDL_SRC"

# --- Android SDK packages (platform-tools + platform) ---
"$CMDLINE_TOOLS/bin/sdkmanager" --sdk_root="$SDK_HOME" --install \
  "platform-tools" "platforms;android-34" "build-tools;34.0.0" >/dev/null

echo
echo "All done. Next: bash android/build_apk.sh"
