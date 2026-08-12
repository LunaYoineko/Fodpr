# Fodpr（ふぉどぷる） — v0.6 "Mesh"

**Fully Open Decentralized Protocol — P2P Mesh Edition**

Fodpr（ふぉどぷる）は、SNS のような「投稿」を、特定の会社やサービス・リレーサーバーに依存せずにやりとりするための**完全 P2P メッシュプロトコル**です。投稿（**イベント**）は **WebRTC データチャネル**上でピア間（F2F）に直接やりとりされます。

> 英語版は [README.en.md](README.en.md) をご覧ください。
> English version is available at [README.en.md](README.en.md)

---

## v0.6 "Mesh" で変わったこと

| 項目 | v0.5 以前 (Relay) | v0.6 "Mesh" |
|------|-------------------|-------------|
| **アーキテクチャ** | リレーサーバー経由 / ホスト昇格型 P2P | **完全 P2P メッシュ (リレーなし、ホストなし)** |
| **接続形態** | Client ↔ Relay / Star topology | **F2F (Friend-to-Friend) メッシュ** |
| **IP 発見** | リレーが仲介 / 固定アドレス | **Kademlia DHT over WebRTC データチャネル** (SHA-256(pubkey) = nodeId) |
| **信頼モデル** | リレー信頼 / ホスト信頼 | **WoT (Web of Trust) スコアゲート** (最小スコア開始、閾値到達でダイヤル) |
| **ブートストラップ** | リレーのシード / 招待 | **招待コード `f2finv1...` / 設定シードノード / 手動 IP / ビルトインアンカー** |
| **メッセージング** | リレー経由 PUSH / WebRTC シグナリング | **ゴシップ (MAX_HOPS=2, eventId 重複排除) / FodprData 直接 P2P** |
| **リレーサーバー** | 必須 (FodprRelay) | **不要・廃止** |
| **ホスト昇格 (RtcGroup)** | 有り | **廃止** |

---

## Fodpr でできること

- **だれもが自由に使える** — オープンなルールで動くため、特定の企業やサービスに縛られません。
- **なりすまし・改ざんを防げる** — 投稿には「電子署名」が付いており、本人が書いたものか、書き換えられていないかをだれでも確認できます。
- **サーバーが 1 台にも依存しない** — **リレーサーバーは存在しません**。すべての接続はピア間 (F2F) の WebRTC データチャネルです。
- **投稿の形式を自由に選べる** — JSON（構造化データ）/ 文字列 / バイナリ（画像など）の 3 種類から投稿者が自由に選べます。
- **メタデータまで守れる（全体署名）** — 「全体署名」イベント（`TransTypeSigned`）を使うと、本文だけでなく送信日時・公開鍵・タグも含めて署名できます。イベント ID で特定イベントを一意に参照できます。
- **宛先別に暗号化できる（E2EE エンベロープ）** — 暗号化イベント（`TransTypeEncrypted`）は、本文を AES-256-GCM で暗号化した「エンベロープ」を content に載せます。受信者ごとに鍵をラップするので、宛先にした本人だけが本文を復号できます（gift-wrap 相当）。

---

## v0.6 核心技術スタック

### 1. F2F メッシュ + WebRTC データチャネル
- すべての接続はクライアント間 (F2F) の **WebRTC データチャネル**。
- ホスト/星形トポロジは廃止。すべてのピアはメッシュの隣接ピア群へ直接接続。
- 最大 50 接続まで連鎖的に拡大。

### 2. Kademlia DHT over WebRTC
- **ノード ID = SHA-256(compressed pubkey)** (256 ビット)。
- k-buckets ルーティングテーブル、`PING` / `FIND_NODE` / `FIND_VALUE` / `STORE` をデータチャネル上で RPC。
- `FIND_VALUE` で公開鍵 → IPv6 アドレスを解決し直接ダイヤル。

### 3. WoT (Web of Trust) 信頼ゲート
- 各ピアに `0.0 ~ 1.0` のスコア。新規/未検証ピアは **最小スコアから開始**。
- スコアが **閾値 (デフォルト 0.0) に達したピアのみダイヤル**。
- WoT 紹介 (`MsgTypeWoTIntroPush`) で紹介者の信頼を継承。
- 接続成功で上昇、失敗で低下、時間経過で減衰 (`decayTrustScores`)。

### 4. ゴシップによるイベント同期
- 署名済みイベントをメッシュ隣接へ `MsgTypeEvent(0x01)` でフラッシュ。
- ホップ制限 (`MAX_HOPS=2`)、`Set<eventIdHex>` で重複排除。
- 直接 P2P メッセージは `FodprData` (`TransTypeSigned` 等) で運ぶ。

### 5. ブートストラップ (リレーなし)
- **招待コード** (`f2finv1...` Bech32) — 知人から受け取り即ダイヤル。
- **設定シードノード** (`fpub1...@[ipv6]:port`) — `fodpr_bootstrap_nodes` に登録。
- **手動 IP 入力** — 直接 IPv6 アドレスを指定。
- **ビルトインコミュニティアンカー** (`FODPR_BOOTSTRAP_ANCHORS`) — 完全孤立時に自動フォールバック (Bitcoin DNS seed / IPFS bootnodes 方式)。

### 6. IPv6 一時アドレス + プライバシー
- IPv6 一時アドレス (RFC 4941 / RFC 8981) を `addresses` に含め、接続ごとにローテーション。
- `/64` プレフィクスで ISP 割り当て単位を判定し GeoIP で国コードを推定。

### 7. GeoIP ベース接続多様性
- ダイヤル候補選抜時に **国ごとに最大 2 本を優先確保**。
- 残りはグローバル信頼順。GeoIP 失敗は 'XX' バケツで信頼順フォールバック。

---

## IPv6 インバウンドブロッキングの現状と対策 ⚠️

**重要:** 一般的な家庭用インターネット接続では、IPv6 インバウンド接続が **デフォルトでブロック** されていることが多いです。

### 現状
| 環境 | インバウンド IPv6 | 備考 |
|------|------------------|------|
| **一般家庭用ルーター (ISP 提供/市販)** | **デフォルト遮断** が多数 | Verizon, AT&T などの ISP 提供 CPE は IPv6 ファイアウォールでインバウンドを遮断。手動で「ピンホール/ポート開放」が必要。 |
| **Unifi / pfSense / OPNsense 等** | デフォルト遮断 | 明示的な「External → Internal」IPv6 ファイアウォールルール追加まで到達不能。 |
| **ISP 側での遮断** | 一部 ISP で遮断 | AT&T などはプロトコル 41 (6in4 トンネル) を遮断する事例あり。ネイティブ IPv6 でもインバウンド遮断のケースあり。 |
| **モバイル回線 (4G/5G)** | ほぼ遮断 | CGNAT 的な構成でインバウンド不可。IPv6 アドレスが割り当てられても到達不能。 |
| **データセンター / VPS / クラウド** | **到達可能** | 適切なファイアウォール設定さえあればネイティブ IPv6 インバウンドが通る。 |

### 影響
- **Fodpr メッシュでは「インバウンドを受け入れられるピアが最低 1 つ」必要**です。完全に遮断された環境同士では直接接続できません。
- 現状、WebRTC の ICE/STUN で NAT トラバーサルを試みますが、ステートフルファイアウォールでインバウンドが遮断されている場合は **シグナリング経由のフォールバック** (既接続メッシュピアを中継) に頼ります。

### 対策・推奨設定
1. **ルーターの IPv6 ファイアウォールで「ピンホール/ポート開放」** を設定 (対象ポート: WebRTC 用 UDP 範囲、または全 IPv6 UDP 一時許可)。
2. **Unifi 等の場合**: `IPv6 Firewall` → `WAN_IN` に `Action: Accept` / `Protocol: All` / `Source: Any` / `Destination: Internal Network` ルールを追加。
3. **モバイル/遮断環境では**: 到達可能なピア (VPS, データセンター, IPv6 開放済み自宅) を **ブートストラップノード/アンカー** として登録し、そこを経由してメッシュに参加。
4. **ICE/STUN サーバー** をクライアント設定で指定 (Google `stun:stun.l.google.com:19302` 等) し、NAT トラバーサル成功率を上げる。
5. **ICMPv6 (Packet Too Big 等) はフィルタしない** — PMTU 発見が動かなくなり、大容量転送が失敗する原因になります。

> **参考文献**: "Where Have All the Firewalls Gone? Security Consequences of Residential IPv6 Transition" (arXiv:2509.04792, 2025) — 数百万の住宅 IPv6 ホストがステートフルファイアウォールなしで公開されている実態を大規模測定。NAT が事実上のファイアウォールだったことが判明。

---

## しくみをひとことで

v0.5 までは「郵便局 (リレーサーバー) 経由」でしたが、v0.6 からは **「知り合いの家を訪ねて手紙を直接渡す」** イメージです。

1. **最初の 1 人** と繋ぐ — 招待コード / 設定シードノード / ビルトインアンカーのいずれかで最初のピアと F2F 接続確立。
2. **署名付き PeerList** を交換 — 相手の知り合い (最大 50 件) を教えてもらい、WoT スコア閾値を超える相手へ自動ダイヤル。
3. **メッシュ形成** — 最大 50 接続まで連鎖的に拡大。以降はリレーなしで直接通信。
4. **DHT で IP 解決** — 公開鍵を鍵に `FIND_VALUE` を発行し、相手の IPv6 を解決して直接ダイヤル。
5. **ゴシップで同期** — 署名済みイベントを隣接へフラッシュ (MAX_HOPS=2)。eventId で重複排除。
6. **WoT で質維持** — 紹介で信頼を引き継ぎ、接続成功でスコア上昇、失敗で低下、時間で減衰。

---

## はじめよう（開発者向け）

### 必要なもの

- [Nim](https://nim-lang.org/) 2.2.10 以上
- [Nimble](https://github.com/nim-lang/nimble)
- (Web クライアント開発時) Node.js 20+ / pnpm

### 1. プロトコルライブラリ (このリポジトリ) を使う

```bash
git clone https://github.com/LunaYoineko/Fodpr
cd Fodpr
nimble install -y
```

#### サンプル実行 (サーバー不要・プロトコル動作確認)

```bash
nim c -r examples/protocol_demo.nim
```

鍵ペア生成、イベントの作成・署名、エンコード → デコード、署名検証までをオフラインで確認できます。

### 2. Web クライアント (FodprWebClient) でメッシュに参加

```bash
cd ../FodprWebClient
pnpm install
pnpm dev --port 5199
```

ブラウザで `http://localhost:5199` を開き、設定画面 (歯車アイコン) → 「ネットワーク」タブで：
- 招待コード (`f2finv1...`) を入力して接続、または
- `fpub1...@[ipv6]:port` 形式のブートストラップノードを追加、または
- 何もしなければ **ビルトインコミュニティアンカー** へ自動接続を試行

### 3. 本番運用 (静的ファイル配信)

```bash
# ビルド
pnpm build
# 静的ファイルを配信ディレクトリへ同期
cp -r dist/assets /var/www/fodpr/assets
cp dist/index.html /var/www/fodpr/index.html
cp public/docs.html /var/www/fodpr/docs.html

# 静的ファイルサーバー起動 (Node.js)
FODPR_STATIC_ROOT=/var/www/fodpr FODPR_API_PORT=8088 nohup node api/server.mjs > /tmp/fodpr-api.log 2>&1 &
```

---

## ディレクトリ構成

```
Fodpr/
├── Fodpr.nimble        # Nimble パッケージ定義 (Library 型)
├── src/
│   ├── Fodpr.nim       # ライブラリのメインモジュール (protocol / crypto / envelope / f2f/* を再エクスポート)
│   ├── protocol.nim    # ワイヤプロトコル: メッセージ種別 / TransType / DhtOp / データ構造 (PeerInfo, PeerList, WoTIntro, InvitationCode, DhtMessage, FodprData)
│   ├── crypto.nim      # secp256k1 (鍵生成・署名・検証・ECDH・Bech32)
│   ├── envelope.nim    # 宛先別暗号化エンベロープ (TransTypeEncrypted)
│   └── f2f/            # F2F メッシュ実装
│       ├── dht.nim           # Kademlia ルーティングテーブル (256bit ID, k-buckets, PING/FIND_NODE/FIND_VALUE/STORE)
│       ├── wot.nim           # WoT グラフ (addWoTIntroduction / findTrustPath / recommendPeersByTrust / decayTrustScores)
│       ├── discovery.nim     # WoT グラフ構築, getNextCandidates, requestPeerList/sendPeerList, WoT 紹介処理
│       ├── peer_cache.nim    # ピアキャッシュ永続化 (50 件 LRU+スコア順), selectPeers
│       ├── invitation.nim    # Bech32 招待コード encode/decode/verify (f2finv1...)
│       ├── signaling.nim     # F2F SDP offer/answer/candidate サポート
│       ├── transport.nim     # WebRTC データチャネル send/receive, IPv6 プレフィックス + IID 生成
│       └── bootstrap.nim     # 設定シードノードからのブートストラップ
├── examples/
│   └── protocol_demo.nim   # protocol.nim を使ったサンプル (サーバー不要)
├── LICENSES/           # サードパーティライブラリのライセンス情報
├── README.md           # 日本語版 README (このファイル)
├── README.en.md        # 英語版 README
└── data/               # ローカル実行時のピアキャッシュ等 (gitignore)
```

> **注意**: 旧 `FodprRelay/` リポジトリ、`src/server.nim`、`f2f/group.nim` (RtcGroup) は v0.6 で **削除済み** です。リレーサーバーは存在しません。

---

## メッセージ種別（先頭 1 バイト）

| 値   | 定数                    | 方向             | 説明                                    |
|------|-------------------------|------------------|-----------------------------------------|
| 0x01 | `MsgTypeEvent`          | ピア → ピア      | 署名付きイベント (ゴシップ配信)           |
| 0x05 | `MsgTypeSignal`         | ピア → ピア      | WebRTC シグナリング (offer/answer/ICE)   |
| 0x06 | `MsgTypeData`           | ピア → ピア      | 直接 P2P メッセージ (FodprData)           |
| 0x07 | `MsgTypePeerListReq`    | ピア → ピア      | ピアリスト要求                            |
| 0x87 | `MsgTypePeerListPush`   | ピア → ピア      | ピアリスト配信 (WoTキャッシュ同期)         |
| 0x08 | `MsgTypeWoTIntro`       | ピア → ピア      | WoT 紹介要求                              |
| 0x88 | `MsgTypeWoTIntroPush`   | ピア → ピア      | WoT 紹介配信                              |
| 0x09 | `MsgTypeInvitationReq`  | ピア → ピア      | 招待コード要求                            |
| 0x89 | `MsgTypeInvitationPush` | ピア → ピア      | 招待コード配信                            |
| 0x0B | `MsgTypeDht`            | ピア → ピア      | DHT RPC (PING/FIND_NODE/FIND_VALUE/STORE) |
| 0x8B | `MsgTypeDhtNodes`       | ピア → ピア      | DHT 近傍ノード応答                         |
| 0x8C | `MsgTypeDhtValue`       | ピア → ピア      | DHT 値応答 (FIND_VALUE ヒット / STORE 完了) |

---

## 送信タイプ（TransType）

| 定数 | 値 | 説明 |
|------|----|------|
| `TransTypeJSON` | 1 | JSON 構造化データ (UTF-8) |
| `TransTypeString` | 2 | 文字列 (UTF-8) |
| `TransTypeBinary` | 3 | バイナリデータ (任意バイト列) |
| `TransTypeSigned` | 4 | 全体署名イベント (全フィールド署名、SHA-256 = eventId) |
| `TransTypeEncrypted` | 5 | 暗号化イベント (エンベロープ、E2EE、gift-wrap 相当) |
| `TransTypeData` | 7 | WebRTC データチャネル専用 (直接 P2P メッセージ) |
| `TransTypePeerList` | 9 | F2F: ピアリスト交換 (WoTキャッシュ同期) 専用 |
| `TransTypeWoTIntro` | 10 | F2F: WoT 紹介メッセージ専用 |
| `TransTypeInvitation` | 11 | F2F: 招待コード専用 |

---

## DHT 操作種別 (Kademlia)

| 定数 | 値 | 説明 |
|------|----|------|
| `DhtOpPing` | 0 | 生存確認 |
| `DhtOpPong` | 1 | 生存応答 |
| `DhtOpFindNode` | 2 | キー (nodeId) に最も近いノードを探す |
| `DhtOpFindValue` | 3 | キーに対応する値を探す (IP アドレス解決) |
| `DhtOpStore` | 4 | 値を保存する (自ノードの IP 記録等) |

---

## データ構造 (主要)

### PeerInfo (ピア情報)
```nim
PeerInfo = object
  pubkey: SkPublicKey      # 公開鍵 (圧縮形式 33 バイト)
  addresses: seq[string]   # 接続アドレス (IPv6 一時アドレス "[ipv6]:port" 等)
  lastSeen: uint64         # 最後に見た時刻 (Unix秒)
  trustScore: float        # 信頼スコア (0.0-1.0)
```

### PeerList (キャッシュ交換, TransTypePeerList)
`version(8) | peerCount(2) | PeerInfo[] | signature(64)` — 最大 50 件。

### WoTIntro (WoT 紹介, TransTypeWoTIntro)
`introducer: SkPublicKey | newPeer: PeerInfo | signature: FodprSignature`

### InvitationCode (招待コード, TransTypeInvitation)
Bech32: `f2finv1...` — `version(1) | issuer(33) | targetPeer: PeerInfo | expiresAt(8) | scope(1) | signature(64)`

### DhtMessage (DHT RPC, MsgTypeDht/DhtNodes/DhtValue)
```
op(1) | msgId(16) | key(32) | nodes[] | value(string) | sender(33) | signature(64)
```
- `nodeId = SHA-256(compressed pubkey)` (256 ビット)。XOR 距離で近傍判定。

### FodprData (直接 P2P メッセージ, MsgTypeData)
`sender | target | seq | timestamp | tags[] | content | signature` — `TransTypeSigned/Encrypted` 等を content に包む。

---

## 関連プロジェクト

- **FodprWebClient** (TypeScript/React) — ブラウザ向けメッシュクライアント (`../FodprWebClient`)
- **FodprTSSDK** (TypeScript) — 共通プロトコル/暗号 SDK (`../FodprTSSDK`)
- **reference.md** (`../FodprWebClient/reference.md`) — イベント送信リファレンス (v0.6 ゴシップ版)

---

## ライセンス

MIT License (see LICENSES/)

---

## 更新履歴 (v0.6 主な変更)

- **2026-08-12**: v0.6 "Mesh" リリース — リレー廃止、完全 P2P メッシュ化。Kademlia DHT over WebRTC、WoT 信頼ゲート、ゴシップ、招待コード/ビルトインアンカーブートストラップ、GeoIP 接続多様性、IPv6 インバウンド遮断対策ドキュメント化。