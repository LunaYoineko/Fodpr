# Fodpr

**Fully Open Decentralized Protocol**

Fodpr は、WebSocket 上で動作する軽量なイベント配信プロトコルです。
クライアントは署名付きイベントをリレーサーバーへ投稿し、購読要求（REQ）によって
条件に一致するイベントをリアルタイムに受信できます。

> English version is available at [README.en.md](README.en.md)

## 特徴

- **署名付きイベント** — イベントは secp256k1 (ECDSA) で署名され、サーバーが改ざん・偽装を検証します
- **シンプルなバイナリプロトコル** — 固定サイズ整数（ビッグエンディアン）+ 長さプレフィックス方式
- **Bech32 エンコード** — 秘密鍵は `fsec1...`、公開鍵は `fpub1...` 形式でやり取り可能
- **メモリ内ストレージ** — リレーサーバーは受信したイベントをメモリに保持して配信します（デモ実装）
- **安全な終了** — サーバーは Ctrl+C (SIGINT) でリスニングソケットを閉じて正常終了します

## ディレクトリ構成

```
Fodpr/
├── Fodpr.nimble        # Nimble パッケージ定義
├── config.nims         # ビルド設定
├── nimble.paths        # 依存ライブラリのパス設定
├── src/
│   ├── Fodpr.nim       # クライアント（送信者）のデモ
│   ├── server.nim      # リレーサーバー
│   ├── protocol.nim    # ワイヤプロトコルのエンコード / デコード
│   └── crypto.nim      # Bech32 と secp256k1（鍵生成・署名・検証）
└── examples/
    └── protocol_demo.nim  # protocol.nim を使ったサンプル
```

## 必要環境

- [Nim](https://nim-lang.org/) 2.2.10 以上
- [Nimble](https://github.com/nim-lang/nimble)（依存ライブラリのインストールに使用）

## ビルド方法

依存ライブラリのインストール:

```bash
nimble install -d
```

リレーサーバーのビルド:

```bash
nim c src/server.nim
```

クライアントのビルド（`nimble build` でも可）:

```bash
nim c src/Fodpr.nim
```

## 使い方

### 1. リレーサーバーを起動

```bash
./src/server
```

```
================================================
 Fodpr Relay Server running on ws://0.0.0.0:8000/ws
 (Ctrl+C で安全に終了できます)
================================================
```

終了するときは **Ctrl+C** を押します。リスニングソケットを閉じて正常終了します。

### 2. クライアントを起動

別のターミナルで:

```bash
./src/Fodpr
```

クライアントは以下を行います:

1. `ws://localhost:8000/ws` へ接続
2. 鍵ペアを生成してテストイベントに署名し、EVENT として投稿
3. サーバーが署名を検証して保存（応答: `OK: Event accepted`）
4. REQ（購読要求）を送信
5. サーバーが保存済みイベントを PUSH 形式で返却
6. 配信終了通知（`EOE: ...`）を受信して接続を閉じる

### 3. サンプルを実行（サーバー不要）

プロトコルのエンコード / デコードだけを試したい場合は:

```bash
nim c -r examples/protocol_demo.nim
```

鍵ペア生成、イベントの作成・署名、エンコード → デコード、署名検証、REQ の
エンコード / デコードまでをオフラインで確認できます。

## プロトコル仕様

### メッセージ種別（先頭 1 バイト）

| 値   | 種別  | 方向                     | 説明                       |
|------|-------|--------------------------|----------------------------|
| 0x01 | EVENT | クライアント → サーバー | 署名付きイベントの投稿     |
| 0x02 | REQ   | クライアント → サーバー | サブスクリプション要求     |
| 0x81 | PUSH  | サーバー → クライアント | イベント配信               |

数値はすべて **ビッグエンディアン** でエンコードされます。

### EVENT のバイナリ形式

```
kind(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `kind` — イベント種別（uint16）
- `createdAt` — Unix タイムスタンプ（秒, uint64）
- `pubkey` — 送信者の公開鍵（圧縮形式 33 バイト）
- `tags` — タグ文字列のリスト
- `content` — 本文（UTF-8）
- `signature` — content の SHA-256 ダイジェストに対する ECDSA 署名（64 バイト）

### REQ のバイナリ形式

```
MsgTypeReq(1) | subIdLen(2) | subId | kind(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `kind` が `0` の場合はすべての種別を購読
- `tagKey` / `tagVal` でタグによる絞り込みが可能（空文字で指定なし）

### PUSH のバイナリ形式

```
MsgTypePush(1) | subIdLen(2) | subId | EVENT 本体
```

## 暗号仕様（crypto.nim）

- 鍵ペア: secp256k1 楕円曲線（`nim-secp256k1`）
- ハッシュ: SHA-256（`nimSHA2`）
- 乱数生成: OS 由来の暗号学的に安全な乱数（`nimcrypto/sysrand`）
- Bech32: BIP-173 準拠。HRP は秘密鍵が `fsec`、公開鍵が `fpub`

```nim
let kp = generateFodprKey()                    # 鍵ペア生成
let sig = signContent(kp.privateKey, content)  # 署名
let ok   = verifyContent(kp.publicKey, content, sig)  # 検証
let priv = fsecEncode(kp.privateKey)           # fsec1... 形式へ変換
```

## ライセンス

Fodpr 自体は MIT ライセンスです。

使用しているサードパーティライブラリのライセンス情報は
[LICENSES/](LICENSES/README.md) にまとめています。
