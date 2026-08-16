#!/usr/bin/env bash
# Generate an Xcode project (FodprChat.xcodeproj) for on-device debug install
# with free provisioning (Personal Team), no Apple Developer account needed.
#
# Requires: xcodegen (brew install xcodegen)
#
# Usage:
#   bash ios/setup_toolchain.sh        # once: download SDL2 source
#   bash ios/make_xcodeproj.sh         # generates ios/FodprChat.xcodeproj
#   open ios/FodprChat.xcodeproj       # set your Apple ID as "Personal Team", Run
#
# The Xcode project's pre-build phase (project.yml: "Build Libraries") compiles
# libfodpr.a (Nim) + libSDL2.a, then the target links them into the app.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "ERROR: Xcode project generation requires macOS."
  exit 1
fi
if ! command -v xcodegen >/dev/null 2>&1; then
  echo "ERROR: xcodegen not found. Install with:  brew install xcodegen"
  exit 1
fi

cd "$DIR"
xcodegen generate
echo
echo "Generated: $DIR/FodprChat.xcodeproj"
echo
echo "Next:"
echo "  1. open $DIR/FodprChat.xcodeproj"
echo "  2. Signing & Capabilities -> Team: あなたの Apple ID (Personal Team)"
echo "  3. 接続した iPhone を選んで Run (デバイス側で開発者モードの許可が必要)"
