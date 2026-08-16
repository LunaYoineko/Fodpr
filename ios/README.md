# iOS ビルド (Fodpr Chat)

macOS + Xcode が必要です (このディレクトリのスクリプトは Mac 上で実行してください)。

開発者アカウントは不要です。以下の 2 通りの実機インストールに対応します。

| 経路 | 手順 | 条件 |
|------|------|------|
| **A. .ipa サイドロード** | `bash ios/build.sh` で `FodprChat.ipa` を生成 → AltStore / SideStore 等でインストール | Mac + Xcode (署名は ad-hoc) |
| **B. Xcode デバッグインストール** | `ios/make_xcodeproj.sh` で Xcode プロジェクト生成 → Apple ID を Personal Team に登録して Run | Mac + Xcode + xcodegen (`brew install xcodegen`) |

## 必要環境
- macOS + Xcode (App Store から、初回起動でコンポーネントインストール)
- Nim (Linux と同じ `~/.nimble` 構成で可。`nim` が PATH にあること)
- 実機インストールは iPhone 側で「開発者モード」を有効にすること (iOS 16+)

## 手順 (A: .ipa サイドロード)

```bash
# 1. SDL2 ソース取得 (初回のみ)
bash ios/setup_toolchain.sh

# 2. ビルド (実機 arm64)
bash ios/build.sh

# 3. 成果物
#    ios/out/iphoneos/FodprChat.app   (ad-hoc 署名済み)
#    ios/out/iphoneos/FodprChat.ipa   (AltStore/SideStore でサイドロード用)
```

生成される `FodprChat.ipa` は `Payload/FodprChat.app` を zip 化したものです。
AltStore / SideStore (PC版) で iPhone にインストールしてください。

## 手順 (B: Xcode デバッグインストール / 無料プロビジョニング)

```bash
bash ios/setup_toolchain.sh     # 初回のみ
bash ios/make_xcodeproj.sh      # ios/FodprChat.xcodeproj 生成
open ios/FodprChat.xcodeproj
```

Xcode で:
1. iPhone を Mac に接続 (有線推奨)
2. TARGET -> Signing & Capabilities で「Team: Apple ID (Personal Team)」を選択
3. 実行先デバイスを選んで Run

Xcode のプリビルドフェーズ (`Build Libraries`) が自動で以下を実行し、リンクします。
- `nim c --os:ios` で `libfodpr.a` (Nim の `SDL_main` をエクスポート) を生成
- `setup_toolchain.sh` が事前ビルドした `libSDL2.a` をプラットフォーム (実機/シミュレータ) に応じてコピー

フォントはビルド後のスクリプトフェーズで `.app` 直下にコピーされます。

## シミュレータ

実機と同じ Xcode プロジェクトをシミュレータ向けにもビルドできます。

```bash
bash ios/setup_toolchain.sh     # 初回のみ (SDL2 ソース + 実機/シミュレータ両方の libSDL2.a を事前ビルド)
bash ios/make_xcodeproj.sh
open ios/FodprChat.xcodeproj    # 実行先をシミュレータに切り替えて Run (署名不要)
```

CLI からも実行できます (Intel Mac は x86_64、Apple Silicon は arm64 のシミュレータ):
```bash
xcodebuild -project ios/FodprChat.xcodeproj -scheme FodprChat \
  -configuration Debug -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build

# 起動済みシミュレータへインストール・起動
xcrun simctl boot "iPhone 16e"    # または任意のデバイス
xcrun simctl install booted ~/Library/Developer/Xcode/DerivedData/FodprChat-*/Build/Products/Debug-iphonesimulator/FodprChat.app
xcrun simctl launch booted com.fodpr.chat
```

> **注意**: iOS 26 シミュレータは非常にメモリを消費します。4GB RAM の Mac では
> インストール・起動が完了しない場合があります (ビルド自体は成功します)。
> シミュレータでの動作確認は 8GB 以上の RAM を推奨します。

## 環境変数 (ビルド設定)

`ios/env.sh` のデフォルトを以下の環境変数で上書きできます。

| 変数 | デフォルト | 説明 |
|------|-----------|------|
| `APP_NAME` | `FodprChat` | アプリ名 (実行ファイル名) |
| `APP_BUNDLE_ID` | `com.fodpr.chat` | Bundle Identifier |
| `APP_DISPLAY_NAME` | `Fodpr Chat` | ホーム画面表示名 |
| `APP_VERSION` | `0.1.0` | CFBundleShortVersionString |
| `APP_BUILD` | `1` | CFBundleVersion |
| `MIN_IOS` | `13.0` | 最低 iOS バージョン |
| `APP_SRC` | `examples/chat_client.nim` | Nim メインソース |
| `DEVELOPMENT_TEAM` | (空) | Xcode 署名の Team ID (B 経路で設定) |

例:
```bash
APP_NAME=MyChat APP_BUNDLE_ID=com.example.mychat bash ios/build.sh
```

## 技術メモ

- **Nim**: `--os:ios --cpu:arm64 --app:staticlib` で静的ライブラリ化し `SDL_main` をエクスポート。
  エントリポイント (`main`) は libSDL2.a 内の `SDL_uikit_main.m` が提供し、それが `SDL_main` を呼ぶ。
- **SDL2 静的リンク**: sdl2 バインディングは `dynlib` 方式のため、iOS では
  `--dynlibOverride:SDL2` で静的リンクに切替 (iOS は dlopen 不可)。
- **フォント**: `DroidSansFallbackFull.ttf` / `DejaVuSans.ttf` を `.app` 直下にバンドル。
  SDL の `SDL_RWFromFile` は Apple 環境ではアプリバンドル内を優先して探す。
- **ローカルネットワーク権限**: UDP ホールパンチ (iOS 14+) のため Info.plist に
  `NSLocalNetworkUsageDescription` を設定済み。
- **フレームワーク**: SDL 公式 iOS Demo (`config.xcconfig`) と同一の一式をリンク
  (AVFoundation, AudioToolbox, CoreGraphics, CoreHaptics, CoreMotion, Foundation,
  GameController, Metal, OpenGLES, QuartzCore, UIKit ほか)。
