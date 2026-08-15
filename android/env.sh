#!/usr/bin/env bash
# Android toolchain paths shared by setup_toolchain.sh / build_apk.sh.
# Usage: source "$(dirname "$0")/env.sh"
set -euo pipefail

export TOOLCHAIN_HOME="${TOOLCHAIN_HOME:-$HOME/fodpr-toolchain}"
export DL_DIR="$TOOLCHAIN_HOME/dl"
export NDK_DIR="$TOOLCHAIN_HOME/android-ndk-r27c"
export TC="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64"
export SDL_SRC="$TOOLCHAIN_HOME/SDL2-2.32.10"
export SDL_RELEASE="2.32.10"
export SDL_TARBALL="$DL_DIR/SDL2-$SDL_RELEASE.tar.gz"
export SDL_URL="https://github.com/libsdl-org/SDL/releases/download/release-$SDL_RELEASE/SDL2-$SDL_RELEASE.tar.gz"

# Find JDK
export JDK_HOME="$(ls -d "$TOOLCHAIN_HOME"/jdk-17* 2>/dev/null | head -1 || true)"
if [ -z "$JDK_HOME" ]; then
  export JDK_HOME="$(ls -d "$HOME/.sdkman/candidates/java"/17* 2>/dev/null | head -1 || true)"
fi

# Android SDK (cmdline-tools)
export SDK_HOME="$TOOLCHAIN_HOME/android-sdk"
export CMDLINE_TOOLS="$SDK_HOME/cmdline-tools/latest"
export ANDROID_HOME="$SDK_HOME"
export ANDROID_SDK_ROOT="$SDK_HOME"

export ADB="$SDK_HOME/platform-tools/adb"
