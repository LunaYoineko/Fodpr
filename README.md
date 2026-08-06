# Fodpr（ふぉどぷる）

**Fully Open Decentralized Protocol**

Fodpr（ふぉどぷる）は、SNS のような「投稿」を、特定の会社やサービスに依存せずに
やりとりするための**プロトコル**（通信の約束事）です。投稿（**イベント**）を
**リレーサーバー**という中継所を通して送受信します。

> 英語版は [README.en.md](README.en.md) をご覧ください。
> English version is available at [README.en.md](README.en.md)

---

## Fodpr でできること

- **だれもが自由に使える**
  オープンなルールで動くため、特定の企業やサービスに縛られません。

- **なりすまし・改ざんを防げる**
  投稿には「電子署名」が付いており、本人が書いたものか、書き換えられていないかを
  だれでも確認できます。

- **サーバーが 1 台に依存しない**
  リレーサーバーはだれでも立てられます。ひとつのサーバーが停止しても、
  ほかのサーバーがあればやりとりは続きます。

- **投稿の形式を自由に選べる**
  投稿の形式は、JSON（構造化データ）/ 文字列 / バイナリ（画像などのデータ）の
  3 種類から、投稿する人が自由に選べます。

## しくみをひとことで

まるで郵便のしくみに似ています。「リレーサーバー」は郵便局、「イベント」は手紙、
「電子署名」は本人の印鑑のようなものです。

1. **投稿する** — 投稿者が電子署名を付けて投稿をリレーサーバーへ送る
2. **保存する** — リレーサーバーが署名をチェックして投稿を保管する
3. **頼む** — 読む人が「この種類の投稿をください」とリレーサーバーへ頼む
4. **受け取る** — リレーサーバーが該当する投稿をリアルタイムに届ける

## よく出てくる言葉

| 用語             | よみ         | やさしい説明                                       |
|------------------|--------------|----------------------------------------------------|
| プロトコル       | ぷろとこる   | コンピューター同士がやりとりするときの「約束事」     |
| イベント         | いべんと     | 投稿ひとつぶんのデータ                             |
| リレーサーバー   | りれーさーばー | 投稿を預かって配達する「中継所」                  |
| クライアント     | くらいあんと | Fodpr を利用するアプリやツール                    |
| 公開鍵・秘密鍵   | こうかいかぎ・ひみつかぎ | 自分を証明するための「鍵」のペア       |
| 電子署名         | でんししょめい | 本人だけが作れる「電子サイン」                    |
| 購読（REQ）      | こうどく     | 「この投稿をください」とリレーサーバーへ頼むこと    |

---

## はじめよう（開発者向け）

### 必要なもの

- [Nim](https://nim-lang.org/) 2.2.10 以上
- [Nimble](https://github.com/nim-lang/nimble)（依存ライブラリのインストールに使用）
- リレーサーバーをネイティブ実行する場合は、FodprRelay 側で LMDB の
  ランタイムライブラリ（Debian/Ubuntu では `liblmdb0`）が必要
- Docker でリレーサーバーを実行する場合は
  [Docker Engine](https://docs.docker.com/engine/) と
  [Docker Compose](https://docs.docker.com/compose/)

### 手順の全体像

1. リレーサーバー（中継所）を起動する
2. クライアント（投稿・購読ツール）を実行する

### 1. リレーサーバーを起動（FodprRelay）

リレーサーバーは別リポジトリ [FodprRelay](https://github.com/LunaYoineko/FodprRelay)
にあります。`git clone` して実行してください。

```bash
git clone https://github.com/LunaYoineko/FodprRelay
cd FodprRelay
nimble build -y
./src/server
```

起動すると、次のように表示されます。

```
================================================
 Fodpr Relay Server running on ws://0.0.0.0:8000/
 (Ctrl+C で安全に終了できます)
================================================
```

終了するときは **Ctrl+C** を押します。リスニングソケットを閉じて正常終了します。

Docker で起動する場合:

```bash
cd FodprRelay
docker compose up -d --build
```

ビルド後、`http://localhost:8000/` へアクセスすると動作確認用のテキストが返ります。
ログは `docker compose logs -f` で確認できます。

### 2. クライアントを実行

別のターミナルで:

```bash
nim c -r examples/fodpr_client.nim
```

クライアントは以下の流れで動作します。

1. `ws://localhost:8000/` へ接続
2. 鍵ペアを生成し、JSON・文字列・バイナリの 3 タイプを EVENT として投稿
   （各 `OK: Event accepted`）
3. REQ（購読要求, TransType: All）で全タイプを購読
4. サーバーが保存済みイベントを PUSH 形式で返却
5. 送信タイプごとに適した配信方法で表示
   （JSON はパースして整形 / 文字列はそのまま / バイナリはサイズのみ）
6. 配信終了通知（`EOE: ...`）を受信して接続を閉じる

### 3. サンプルを実行（サーバー不要）

サーバーを立てずに、プロトコルのエンコード / デコードだけを試したい場合は:

```bash
nim c -r examples/protocol_demo.nim
```

鍵ペア生成、イベントの作成・署名、エンコード → デコード、署名検証、REQ の
エンコード / デコードまでをオフラインで確認できます。

---

## 開発者向け詳細（技術仕様）

### ディレクトリ構成

```
Fodpr/
├── Fodpr.nimble        # Nimble パッケージ定義（Library 型）
├── src/
│   ├── Fodpr.nim       # ライブラリのメインモジュール（protocol / crypto を再エクスポート）
│   ├── protocol.nim    # ワイヤプロトコルのエンコード / デコード
│   └── crypto.nim      # Bech32 と secp256k1（鍵生成・署名・検証）
├── examples/
│   ├── fodpr_client.nim    # リレーサーバーと通信するクライアントのサンプル
│   └── protocol_demo.nim   # protocol.nim を使ったサンプル（サーバー不要）
├── LICENSES/           # サードパーティライブラリのライセンス情報
├── README.md           # 日本語版 README
├── README.en.md        # 英語版 README
└── data/               # LMDB データベース（リレーサーバー側で使用・gitignore）
```

リレーサーバー（FodprRelay）は別リポジトリで管理しています。

```
FodprRelay/
├── FodprRelay.nimble   # Nimble パッケージ定義（requires "https://github.com/LunaYoineko/Fodpr"）
├── Dockerfile          # リレーサーバー用の Docker イメージ定義
├── docker-compose.yml  # Docker Compose での起動設定（ポート 8000 / データボリューム）
└── src/
    └── server.nim      # リレーサーバー
```

### メッセージ種別（先頭 1 バイト）

| 値   | 種別  | 方向                     | 説明                       |
|------|-------|--------------------------|----------------------------|
| 0x01 | EVENT | クライアント → サーバー | 署名付きイベントの投稿     |
| 0x02 | REQ   | クライアント → サーバー | サブスクリプション要求     |
| 0x03 | DEL   | クライアント → サーバー | イベント削除要求（署名付き）|
| 0x81 | PUSH  | サーバー → クライアント | イベント配信               |

数値はすべて **ビッグエンディアン** でエンコードされます。

### 送信タイプ（TransType）と配信方法

`transType` は「どのように送るか」を表す**送信方法**であり、投稿する人が
自由に選べます。サーバーは投稿の中身の意味（プロフィール / 投稿 / メディア など）を
一切解釈せず、送信タイプに基づいて保存・配信するだけです。意味の解釈は
すべてクライアント側の役割です（例: JSON なら特定のキー / 値をプロフィールと判定する）。

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

### DEL のバイナリ形式（イベント削除 API）

投稿者は自分のイベントを削除できます。要求全体に署名を付けることで、
**送信者本人だけが自分の投稿を削除できる**仕組みです。

```
MsgTypeDel(1) | transType(2) | targetType(1) | pubkey(33)
| [createdAt(8) | contentHash(32)] | signature(64)
```

**署名対象**（`signature` を除いた以下のバイト列）:

```
transType(2) | targetType(1) | pubkey(33) | [createdAt(8) | contentHash(32)]
```

- `transType` — 削除対象の送信タイプ（`0`=全タイプ, `1`=JSON, `2`=String, `3`=Binary）
- `targetType` — 削除対象の指定方法
  - `0`（`DelTargetPubkey`）: その公開鍵のイベントを `transType` 単位で全削除
  - `1`（`DelTargetEvent`）: `createdAt` と `contentHash`（content の SHA-256）が一致する特定イベントを削除
- `pubkey` — 削除対象イベントの公開鍵（自分の公開鍵のみ）
- `signature` — 上記の署名対象を送信者の秘密鍵で署名した ECDSA 署名（64 バイト）

サーバーは署名を検証し、イベントの公開鍵が要求の公開鍵と一致するものだけを
削除します（他人のイベントは削除できません）。

ライブラリが提供する API:

```nim
var req = FodprDelReq(
  transType: TransTypeJSON,   # 削除対象の送信タイプ
  targetType: DelTargetPubkey,# 公開鍵単位で削除 / DelTargetEvent で特定イベント
  pubkey: kp.publicKey,       # 自分の公開鍵
  createdAt: ev.createdAt,    # DelTargetEvent のときのみ有効
  contentHash: hash,          # DelTargetEvent のときのみ有効 (content の SHA-256)
  signature: sig)             # 下記で署名した値
let packet = encodeDel(req)   # 完全な DEL パケット（先頭 0x03 + 署名つき）
```

署名は `encodeDelSignedData(req)` の返すバイト列に対して行います:

```nim
let signed = encodeDelSignedData(req)
req.signature = signContent(kp.privateKey, signed)
```

サーバー側では `decodeDelReq(stream)` でパケットを復元し、`verifyContent` で
署名を検証します。

### ストレージ（FodprRelay の server.nim）

リレーサーバー（FodprRelay）は、イベントを送信タイプごとに分けて LMDB に
永続化します（`./data/` ディレクトリ、起動時に自動作成）。

| DBI         | 保存するイベント | キー                    |
|-------------|------------------|-------------------------|
| `json`      | TransTypeJSON    | 現在時刻 + 乱数         |
| `string`    | TransTypeString  | 現在時刻 + 乱数         |
| `binary`    | TransTypeBinary  | 現在時刻 + 乱数         |

- サーバーは content を解釈しないため、どのタイプも一意なキーで追記保存されます
- サーバー終了時（Ctrl+C）に環境をクローズし、データは再起動後も保持されます

### 暗号仕様（crypto.nim）

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

---

## ライセンス

Fodpr 自体は MIT ライセンスです。

使用しているサードパーティライブラリのライセンス情報は
[LICENSES/](LICENSES/README.md) にまとめています。
