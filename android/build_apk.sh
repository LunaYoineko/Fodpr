#!/usr/bin/env bash
# Build Fodpr IPv6 F2F test demo as an Android APK (arm64-v8a).
#
# Pipeline:
#   1. Cross-compile examples/ipv6test.nim -> libmain.so  (Nim + NDK clang)
#   2. Build libSDL2.so from the SDL2 source              (NDK ndk-build, cached)
#   3. Stage libs + font asset into app/src/main/jniLibs|assets
#   4. Gradle assembleDebug -> android/app/build/outputs/apk/debug/app-debug.apk
#   5. Optionally adb install if a device is connected.
#
# Usage: bash android/build_apk.sh [--install]
# Optional env overrides (app profile):
#   APP_SRC     Nim main source       (default: examples/ipv6test.nim)
#   APP_PACKAGE Android package name  (default: com.fodpr.ipv6test)
#   APP_LABEL   App display name      (default: Fodpr IPv6test)
#
# Example (Fodpr Chat):
#   APP_SRC=examples/chat_client.nim APP_PACKAGE=com.fodpr.chat \
#     APP_LABEL="Fodpr Chat" bash android/build_apk.sh --install
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/env.sh"
REPO="$(cd "$DIR/.." && pwd)"

APP_SRC="${APP_SRC:-$REPO/examples/ipv6test.nim}"
APP_PACKAGE="${APP_PACKAGE:-com.fodpr.ipv6test}"
APP_LABEL="${APP_LABEL:-Fodpr IPv6test}"
case "$APP_SRC" in
  /*) : ;;
  *) APP_SRC="$REPO/$APP_SRC" ;;
esac

INSTALL=0
if [ "${1:-}" = "--install" ]; then INSTALL=1; fi

export PATH="$TC/bin:$JDK_HOME/bin:$PATH"
AARCH=aarch64-linux-android24
SYSROOT="$TC/sysroot"
ABI=arm64-v8a

OUT="$DIR/out"
JNI_DIR="$DIR/app/src/main/jniLibs/$ABI"
ASSETS_DIR="$DIR/app/src/main/assets"
mkdir -p "$OUT" "$JNI_DIR" "$ASSETS_DIR"

log() { echo "[build] $*"; }

# --- 1. libmain.so (Nim cross-compile) ---
log "1/4  Nim -> libmain.so ($AARCH) [src: $APP_SRC]"
nim c -d:release --os:android --cpu:arm64 --app:lib --cc:clang --threads:on \
  --path:"$REPO/src" \
  --passC:"--target=$AARCH --sysroot=$SYSROOT -fPIC" \
  --passL:"--target=$AARCH --sysroot=$SYSROOT -shared -lm -ldl -llog" \
  --out:"$OUT/libmain.so" \
  "$APP_SRC" 2>&1 | tail -3
"$TC/bin/llvm-readelf" -s "$OUT/libmain.so" > "$OUT/libmain.syms"
grep -q SDL_main "$OUT/libmain.syms" \
  || { echo "ERROR: SDL_main not exported"; exit 1; }
cp "$OUT/libmain.so" "$JNI_DIR/libmain.so"
log "    -> $JNI_DIR/libmain.so"

# --- 2. libSDL2.so (cached in toolchain dir) ---
SDL_LIB="$TOOLCHAIN_HOME/SDL2-2.32.10/libs/$ABI/libSDL2.so"
if [ ! -f "$SDL_LIB" ]; then
  log "2/4  NDK ndk-build libSDL2.so"
  "$NDK_DIR/ndk-build" NDK_PROJECT_PATH="$SDL_SRC" APP_BUILD_SCRIPT="$SDL_SRC/Android.mk" \
    APP_ABI="$ABI" APP_PLATFORM=android-24 -j"$(nproc)" >/dev/null
fi
cp "$SDL_LIB" "$JNI_DIR/libSDL2.so"
log "    -> $JNI_DIR/libSDL2.so"

# --- 3. Assets (font) ---
log "3/4  Stage assets"
cp "$REPO/examples/assets/DroidSansFallbackFull.ttf" "$ASSETS_DIR/"
cp "$REPO/examples/assets/DejaVuSans.ttf" "$ASSETS_DIR/"

# --- 4. Gradle assembleDebug ---
log "4/4  Render templates (pkg=$APP_PACKAGE label=$APP_LABEL) + Gradle assembleDebug"
cd "$DIR"
sed -e "s|@PACKAGE@|$APP_PACKAGE|g" -e "s|@APP_NAME@|$APP_LABEL|g" \
    templates/AndroidManifest.xml.tpl > app/src/main/AndroidManifest.xml
sed "s|@PACKAGE@|$APP_PACKAGE|g" templates/build.gradle.tpl > app/build.gradle
sed "s|@APP_NAME@|$APP_LABEL|g" \
    templates/strings.xml.tpl > app/src/main/res/values/strings.xml
export ANDROID_HOME="$SDK_HOME" ANDROID_SDK_ROOT="$SDK_HOME" JAVA_HOME="$JDK_HOME"
cat > local.properties <<EOF
sdk.dir=$SDK_HOME
EOF
./gradlew --no-daemon -q assembleDebug

APK="$DIR/app/build/outputs/apk/debug/app-debug.apk"
log "APK: $APK"

if [ "$INSTALL" = 1 ]; then
  if "$ADB" get-state 2>/dev/null | grep -q device; then
    log "adb install -r $APK"
    "$ADB" install -r "$APK"
  else
    echo "WARN: no device connected via adb; skipping install"
  fi
fi
