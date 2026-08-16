#!/usr/bin/env bash
# iOS toolchain paths shared by setup_toolchain.sh / build.sh.
# Usage: source "$(dirname "$0")/env.sh"
set -euo pipefail

export IOS_TOOLCHAIN_HOME="${IOS_TOOLCHAIN_HOME:-$HOME/fodpr-ios-toolchain}"
export DL_DIR="$IOS_TOOLCHAIN_HOME/dl"

export SDL_SRC="$IOS_TOOLCHAIN_HOME/SDL2-2.32.10"
export SDL_RELEASE="2.32.10"
export SDL_TARBALL="$DL_DIR/SDL2-$SDL_RELEASE.tar.gz"
export SDL_URL="https://github.com/libsdl-org/SDL/releases/download/release-$SDL_RELEASE/SDL2-$SDL_RELEASE.tar.gz"

# SDL2 事前ビルド成果物 (実機/シミュレータ向けの静的ライブラリ)
# setup_toolchain.sh が生成する。Xcode のスクリプトフェーズ内でネスト xcodebuild を
# 行うとシミュレータ向けビルドがクラッシュするため、ここからコピーするだけにする。
export SDL_PREBUILT_DIR="$IOS_TOOLCHAIN_HOME/prebuilt"

# 最低 iOS バージョン (A12 Bionic=iPhone XS 以降など)
export MIN_IOS="${MIN_IOS:-13.0}"

# アプリ設定 (ビルド時に上書き可能)
export APP_NAME="${APP_NAME:-FodprChat}"
export APP_BUNDLE_ID="${APP_BUNDLE_ID:-com.fodpr.chat}"
export APP_DISPLAY_NAME="${APP_DISPLAY_NAME:-Fodpr Chat}"
export APP_VERSION="${APP_VERSION:-0.1.0}"
export APP_BUILD="${APP_BUILD:-1}"

# ペルソナチーム (無料プロビジョニング時のみ Xcode で設定。環境変数でも指定可)
export DEVELOPMENT_TEAM="${DEVELOPMENT_TEAM:-}"
