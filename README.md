# Fodpr

**Fully Open Decentralized Protocol**

Fodpr は、Nostrを元にした完全に自由なオープンプロトコルです。
WebSocket 上で動作する軽量なイベント配信プロトコルであり、
クライアントは署名付きイベントをリレーサーバーへ投稿し、購読要求（REQ）によって
条件に一致するイベントをリアルタイムに受信できます。

> English version is available at [README.en.md](README.en.md)

## 特徴

- **署名付きイベント** — イベントは secp256k1 (ECDSA) で署名され、サーバーが改ざん・偽装を検証します
- **シンプルなバイナリプロトコル** — 固定サイズ整数（ビッグエンディアン）+ 長さプレフィックス方式
- **Bech32 エンコード** — 秘密鍵は `fsec1...`、公開鍵は `fpub1...` 形式でやり取り可能
- **LMDB による永続ストレージ** — 受信したイベントは送信タイプ（JSON / String / Binary）ごとの DBI に分けて `./data/` に保存され、再起動後も保持されます
- **送信タイプ (TransType)** — 各ユーザーが JSON / String / Binary の 3 タイプから自由に送信方法を選べます。サーバーは content の意味を解釈せず、送信タイプに基づいて保存・配信するだけです（プロフィール管理などの意味解釈はすべてクライアント側の責務）
- **Docker 対応** — 付属の `Dockerfile` / `docker-compose.yml` でワンコマンド起動（LMDB データはボリュームに永続化）
- **安全な終了** — サーバーは Ctrl+C (SIGINT) でリスニングソケットを閉じて正常終了します

## ディレクトリ構成

```
Fodpr/
├── Fodpr.nimble        # Nimble パッケージ定義
├── Dockerfile          # リレーサーバー用の Docker イメージ定義
├── docker-compose.yml  # Docker Compose での起動設定（ポート 8000 / データボリューム）
├── src/
│   ├── Fodpr.nim       # クライアント（送信者）のデモ
│   ├── server.nim      # リレーサーバー
│   ├── protocol.nim    # ワイヤプロトコルのエンコード / デコード
│   └── crypto.nim      # Bech32 と secp256k1（鍵生成・署名・検証）
├── examples/
│   └── protocol_demo.nim  # protocol.nim を使ったサンプル
├── LICENSES/           # サードパーティライブラリのライセンス情報
├── README.en.md        # 英語版 README
└── data/               # LMDB データベース（起動時に自動作成・gitignore）
```

## 必要環境

- [Nim](https://nim-lang.org/) 2.2.10 以上
- [Nimble](https://github.com/nim-lang/nimble)（依存ライブラリのインストールに使用）
- ネイティブ実行時は LMDB のランタイムライブラリ（Debian/Ubuntu では `liblmdb0`）が必要
- Docker で実行する場合は [Docker Engine](https://docs.docker.com/engine/) と [Docker Compose](https://docs.docker.com/compose/)

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

ネイティブで起動する場合:

```bash
./src/server
```

```
================================================
 Fodpr Relay Server running on ws://0.0.0.0:8000/
 (Ctrl+C で安全に終了できます)
================================================
```

終了するときは **Ctrl+C** を押します。リスニングソケットを閉じて正常終了します。

Docker で起動する場合:

```bash
docker compose up -d --build
```

ビルド後、`http://localhost:8000/` へアクセスすると動作確認用の
テキストが返ります。ログは `docker compose logs -f` で確認できます。

### 2. クライアントを起動

別のターミナルで:

```bash
./src/Fodpr
```

クライアントは以下を行います:

1. `ws://localhost:8000/` へ接続
2. 鍵ペアを生成し、JSON・String・Binary の 3 タイプを EVENT として投稿（各 `OK: Event accepted`）
3. REQ（購読要求, TransType: All）で全タイプを購読
4. サーバーが保存済みイベントを PUSH 形式で返却
5. クライアントは送信タイプごとに適した配信方法で表示（JSON はパースして整形 / String はそのまま / Binary はサイズのみ）
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

### 送信タイプ（TransType）と配信方法

`protocol.nim` に定数として定義しています。`transType` は「どのように送るか」を
表す**送信方法**であり、各ユーザーが自由に選べます。サーバーは content の意味
（プロフィール / 投稿 / メディア など）を一切解釈せず、送信タイプに基づいて
保存・配信するだけです。意味の解釈やプロフィール管理はすべてクライアント側の
責務となります（例: content が JSON なら特定のキー/値でプロフィールと判定する）。

| 定数              | 値 | 説明                                        | 配信方法                                        |
|-------------------|----|---------------------------------------------|-------------------------------------------------|
| `TransTypeJSON`   | 1  | JSON 構造化データ（content は UTF-8 の JSON） | サーバーが受信時に JSON 構文を検証。クライアントは受信後に JSON としてパースし整形表示 |
| `TransTypeString` | 2  | 文字列（content は UTF-8）                   | そのまま文字列として配信・表示                   |
| `TransTypeBinary` | 3  | バイナリデータ（content は任意のバイト列）    | バイナリのまま配信。クライアントはサイズのみ表示 |
| `TransTypeAll`    | 0  | すべてのタイプ（REQ でのみ使用）             | サーバーが全タイプの保存イベントを配信           |

### EVENT のバイナリ形式

```
transType(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `transType` — 送信タイプ（uint16: 1 = JSON, 2 = String, 3 = Binary）
- `createdAt` — Unix タイムスタンプ（秒, uint64）
- `pubkey` — 送信者の公開鍵（圧縮形式 33 バイト）
- `tags` — タグ文字列のリスト
- `content` — 本文（タイプに応じて JSON / 文字列 / バイナリ）
- `signature` — content の SHA-256 ダイジェストに対する ECDSA 署名（64 バイト）

### REQ のバイナリ形式

```
MsgTypeReq(1) | subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `transType` が `0`（`TransTypeAll`）の場合はすべてのタイプを購読
- `transType` が `1` / `2` / `3` の場合は、対応するタイプ（JSON / String / Binary）のイベントを購読
- `tagKey` / `tagVal` でタグによる絞り込みが可能（現在は `tagKey = "pubkey"` で公開鍵を絞り込み、空文字で指定なし）

### PUSH のバイナリ形式

```
MsgTypePush(1) | subIdLen(2) | subId | EVENT 本体
```

## ストレージ（server.nim）

イベントは送信タイプごとの DBI に分けて LMDB に永続化されます
（`./data/` ディレクトリ、起動時に自動作成）。

| DBI         | 保存するイベント | キー                    |
|-------------|------------------|-------------------------|
| `json`      | TransTypeJSON    | 現在時刻 + 乱数         |
| `string`    | TransTypeString  | 現在時刻 + 乱数         |
| `binary`    | TransTypeBinary  | 現在時刻 + 乱数         |

- サーバーは content を解釈しないため、どのタイプも一意なキーで追記保存されます
- サーバー終了時（Ctrl+C）に環境をクローズし、データは再起動後も保持されます

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
