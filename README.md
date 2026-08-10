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

- **メタデータまで守れる（全体署名）**
  「全体署名」イベント（TransTypeSigned）を使うと、本文だけでなく
  送信日時・公開鍵・タグも含めて署名できます。リレーによる
  メタデータの改ざんを検出でき、イベント ID で特定イベントを
  一意に参照できます（メールのスレッド参照などの土台）。

- **宛先別に暗号化できる（E2EE エンベロープ）**
  暗号化イベント（TransTypeEncrypted）は、本文を AES-256-GCM で暗号化した
  「エンベロープ」を content に載せます。受信者ごとに鍵をラップするので、
  宛先にした本人だけが本文を復号できます（gift-wrap 相当）。
  リレーは構造だけを検証し、内容は復号できません。

  - **読む人を認証できる（読取認証）**
    宛先限定イベント（`to:<fpub>` タグ）は、その宛先本人として
    チャレンジ認証（NIP-42 相当の AUTH）を通した購読にだけ配信されます。

  - **WebRTC シグナリング**
    `TransTypeWebRTC`（6）でシグナリング専用チャネルを確立し、SDP/ICE candidate
    （IPv6 一時アドレスを含む）を secp256k1 署名付きで中継します。
    シグナリングメッセージは保存されず（即座に中継）、P2P 接続確立後は
    リレーを通りません。ホスト-ゲスト星形トポロジで自動ホスト昇格機能付き。

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
│   ├── Fodpr.nim       # ライブラリのメインモジュール（protocol / crypto / envelope を再エクスポート）
│   ├── protocol.nim    # ワイヤプロトコルのエンコード / デコード（EVENT / REQ / DEL / AUTH）
│   ├── crypto.nim      # Bech32 と secp256k1（鍵生成・署名・検証・ECDH）
│   └── envelope.nim    # 宛先別暗号化エンベロープ（TransTypeEncrypted）
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
| 0x04 | AUTH  | クライアント → サーバー | 読取認証の署名応答（NIP-42 相当）|
| 0x05 | SIGNAL | クライアント → サーバー | WebRTC シグナリングメッセージ |
| 0x81 | PUSH  | サーバー → クライアント | イベント配信               |
| 0x82 | CHALLENGE | サーバー → クライアント | 認証チャレンジ（nonce 32 バイト）|
| 0x83 | SIGNAL_PUSH | サーバー → クライアント | WebRTC シグナリングの中継 |

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
| `TransTypeSigned` | 4  | 全体署名イベント（content は任意）           | 本文だけでなく全フィールドを署名。その SHA-256 がイベント ID になる |
| `TransTypeEncrypted` | 5  | 暗号化イベント（content はエンベロープ）    | content は envelope.nim の宛先別暗号化エンベロープ。全体署名 + to: タグ一致を検証 |
| `TransTypeWebRTC`  | 6  | WebRTC シグナリング専用                    | SIGNAL (0x05) / SIGNAL_PUSH (0x83) で中継。保存せず即座に配信 |
| `TransTypeAll`    | 0  | すべてのタイプ（REQ でのみ使用）             | サーバーが全タイプの保存イベントを配信           |

### EVENT のバイナリ形式

```
transType(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `transType` — 送信タイプ（uint16: 0=All(REQ のみ), 1=JSON, 2=String, 3=Binary, 4=Signed, 5=Encrypted, 6=WebRTC）
- `createdAt` — Unix タイムスタンプ（秒, uint64）
- `pubkey` — 送信者の公開鍵（圧縮形式 33 バイト）
- `tags` — タグ文字列のリスト
- `content` — 本文（タイプに応じて JSON / 文字列 / バイナリ / エンベロープ）
- `signature` — 署名（64 バイト）。
  - TransType 1〜3（JSON / String / Binary）: content の SHA-256 ダイジェストに対する ECDSA 署名
  - TransType 4・5（Signed / Encrypted）: `createdAt`・`pubkey`・`tags` を含む
    **全フィールド**（`encodeEventSignedData()` のバイト列）に対する署名

### 全体署名（TransTypeSigned）とイベント ID

`TransTypeSigned` は、`signature` を除いた全フィールド
（`transType | createdAt | pubkey | tags | content`）を署名対象とします。
署名対象バイト列（`encodeEventSignedData(ev)`）の **SHA-256** が
**イベント ID**（`eventId`）になります。

```nim
let evId = eventIdHex(ev)      # 64 桁の 16 進文字列
let ok   = verifyEvent(ev.pubkey, ev, ev.signature)  # 全体署名の検証
```

イベント ID はタグ規約の `e:<eventId>` で参照できるため、
**reply-to（スレッド参照）** を厳密に表現できます。

### 宛先別暗号化（TransTypeEncrypted）とエンベロープ

`TransTypeEncrypted` の `content` は `envelope.nim` が作る
**宛先別暗号化エンベロープ**（gift-wrap / seal 相当）です。

エンベロープの形式（すべてビッグエンディアン）:

```
version(1) | recipientCount(2) |
(recipientPubkey(33) | wrapNonce(12) | wrappedKey(32) | wrappedKeyTag(16)) × recipientCount |
bodyNonce(12) | bodyTag(16) | bodyCiphertext
```

鍵スキーム:

- メッセージ鍵 **K**（32 バイトの乱数）で本文（body）を **AES-256-GCM** 暗号化
- K を各受信者向けに、ECDH 共有鍵から導出したラップ鍵 **W** でラップ
  - `W = SHA-256(ECDH(送信者秘密鍵, 受信者公開鍵) || "FodprEnvelopeV1" || 受信者公開鍵)`
- 受信者は `ECDH(自分の秘密鍵, 送信者の公開鍵)` で同じ W を復元し、K を取り出して本文を復号

```nim
# 送信者: 複数受信者へ暗号化
let envelope = encryptEnvelope(body, senderPriv, @[recip1.publicKey, recip2.publicKey])
# 受信者: 自分の秘密鍵とイベントの pubkey (送信者) で復号
let body = decryptEnvelope(ev.content, myPriv, ev.pubkey)
```

リレー用 API（内容は復号せず構造だけを見る）:

```nim
let ok     = isValidEnvelope(ev.content)         # 構造検証
let recips = envelopeRecipients(ev.content)      # 受信者の公開鍵一覧 (to: タグと突合)
```

暗号化イベントには `to:<fpub>` タグが必須で、リレーはタグがエンベロープ内の
受信者と一致することを検証します（「読めない人への配送」を防ぐ）。

### 読取認証（AUTH, NIP-42 相当）

`to:<fpub>` 宛先限定イベントは、宛先本人しか受け取れないようにするため、
リレーが **チャレンジ → 署名応答** の認証を行います。

```
1. クライアント → REQ(subId, tagKey="to", tagVal=fpub)
2. サーバー   → チャレンジ (0x82) nonce(32) を送る
3. クライアント → AUTH (0x04) nonce(32) | pubkey(33) | signature(64)
   (署名対象: nonce | pubkey)
4. サーバー   → 認証OK 後、宛先本人として REQ を再開
```

```nim
var auth = FodprAuth(nonce: nonce, pubkey: kp.publicKey, signature: placeholder)
auth.signature = signContent(kp.privateKey, encodeAuthSignedData(auth))
await ws.send(encodeAuth(auth), Binary)
```

認証に成功した購読だけが `to:` 宛先限定イベントを受け取れます
（公開イベントは従来どおり認証なしで購読できます）。

### タグ規約

Fodpr のタグは `"<キー>:<値>"` 形式の文字列です。

| タグ          | 説明                                        |
|---------------|---------------------------------------------|
| `to:<fpub>`   | 宛先の公開鍵（fpub 形式、小文字）。宛先限定イベントで必須 |
| `p:<fpub>`    | 関係者（participant）の公開鍵（参照用）      |
| `e:<eventId>` | 参照イベント（reply-to / スレッド結合に使用）|

### REQ のバイナリ形式

```
MsgTypeReq(1) | subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `transType` が `0`（`TransTypeAll`）の場合はすべてのタイプを購読
- `transType` が `1`〜`5` の場合は、対応するタイプ（JSON / String / Binary / Signed / Encrypted）のイベントを購読
- `transType` が `6`（`TransTypeWebRTC`）の場合は WebRTC シグナリング専用。`to:` タグ
  (宛先 fpub) が必須。保存済みイベントはなく EOE のみ送信され、以後は SIGNAL メッセージの
  リアルタイム中継のみを行う
- `tagKey` / `tagVal` でタグによる絞り込みが可能（`tagKey = "pubkey"` で公開鍵、`tagKey = "to"` で宛先を指定）

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

- `transType` — 削除対象の送信タイプ（`0`=全タイプ, `1`=JSON, `2`=String, `3`=Binary, `4`=Signed, `5`=Encrypted）
- `targetType` — 削除対象の指定方法
  - `0`（`DelTargetPubkey`）: その公開鍵のイベントを `transType` 単位で全削除
  - `1`（`DelTargetEvent`）: `createdAt` と `contentHash`（content の SHA-256）が一致する特定イベントを削除
  - `2`（`DelTargetEventId`）: `eventId`（全体署名イベントのイベント ID）が一致する特定イベントを削除
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

### WebRTC シグナリング（TransTypeWebRTC）

`TransTypeWebRTC`（6）は WebRTC の P2P 確立のためのシグナリング専用です。
リレーはシグナリングメッセージを保存せず、署名検証後に即座に宛先へ中継します。

#### シグナリングメッセージ (SIGNAL / SIGNAL_PUSH)

**SIGNAL パケット (0x05, クライアント → サーバー):**

```
MsgTypeSignal(1) | signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content | signature(64)
```

**SIGNAL_PUSH パケット (0x83, サーバー → クライアント):**

```
MsgTypeSignalPush(1) | subIdLen(2) | subId | signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content | signature(64)
```

**署名対象バイト列:**

```
signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content
```

| フィールド | 説明 |
|----------|------|
| `signalType` | `1`=Offer, `2`=Answer, `3`=Candidate, `4`=HostChange |
| `senderPubkey` | 送信者の公開鍵 (圧縮 33 バイト) |
| `targetPubkey` | 宛先の公開鍵 (圧縮 33 バイト) |
| `content` | SDP offer/answer JSON や ICE candidate JSON (IPv6 一時アドレスを含む) |
| `signature` | 上記フィールド全体の secp256k1 ECDSA 署名 (64 バイト) |

ライブラリ API:

```nim
# シグナリングメッセージ作成・署名
var sig = FodprSignal(
  signalType: SignalOffer,
  sender: kp.publicKey,
  target: targetPub,
  content: """{"sdp":"..."," candidates":[...]," ipv6TempAddr":"2001:db8::1"}""")
sig.signature = signSignal(kp.privateKey, sig)
let packet = $MsgTypeSignal & encodeSignal(sig)

# 受信・検証
let received = decodeSignal(strm)
if verifySignal(received):
  # 署名 OK — 信頼できる送信者
  echo signalTypeName(received.signalType), ": ", received.content
```

#### ホスト-ゲスト星形トポロジと自動ホスト昇格

複数のゲストが 1 人のホストに対して WebRTC 接続を張る星形トポロジをサポートします。

- **グループ ID** = ホストの fpub (小文字)
- クライアントは `REQ(TransTypeWebRTC, tagKey="to", tagVal=<ホスト fpub>)` で
  ホストのグループに参加 (AUTH 必須)
- ホストが切断された場合、**最古の guest** (join 時刻が最も古いメンバー) が
  自動でホストに昇格
- リレーは全メンバーにテキスト通知 `HOST_CHANGE: <new_host_fpub>` を送信
- メンバーは新ホストの fpub で REQ を再送信し直す

```
ホスト (B)  ── シグナリング ──>  リレー  <── ゲスト (A) へ中継
ホスト (B)  ── シグナリング ──>  リレー  <── ゲスト (C) へ中継

B が切断 → A (最古の guest) が新ホストに昇格 → HOST_CHANGE 通知 → 全員再接続
```

- P2P 通信は **IPv6 一時アドレス** 同士で行われます (SDP/ICE candidate の
  content に JSON として含まれる)
- リレーは content を解釈・復号せず、署名検証 + 宛先照合のみを行う
- 双方はシグナリングメッセージの secp256k1 署名を検証し、P2P データチャネル
  での直接通信後はリレーを通らない

### ストレージ（FodprRelay の server.nim）

リレーサーバー（FodprRelay）は、イベントを送信タイプごとに分けて LMDB に
永続化します（`./data/` ディレクトリ、起動時に自動作成）。

| DBI         | 保存するイベント | キー                    |
|-------------|------------------|-------------------------|
| `json`      | TransTypeJSON    | 現在時刻 + 乱数         |
| `string`    | TransTypeString  | 現在時刻 + 乱数         |
| `binary`    | TransTypeBinary  | 現在時刻 + 乱数         |
| `signed`    | TransTypeSigned  | 現在時刻 + 乱数         |
| `encrypted` | TransTypeEncrypted | 現在時刻 + 乱数        |

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
