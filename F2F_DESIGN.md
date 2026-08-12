# F2F (Friend-to-Friend) / WoT (Web of Trust) 設計思想  — v0.6 "Mesh"

## 概要

F2F は、Fodpr プロトコルにおける **友人ベースの P2P メッシュネットワーク層** です。
` /root/Fodpr/src` (Nim) が実装する、**リレーサーバーなし**の
クライアント間 F2F 接続と、それに乗せる DHT / WoT / ゴシップのプロトコル群を定義します。

- **接続形態**: クライアント間 F2F (WebRTC データチャネル)。ホスト/星形トポロジは廃止。
  すべてのピアはメッシュの隣接ピア群へ直接接続する。
- **IP 発見**: Kademlia DHT を **WebRTC データチャネル上** で走らせる
  (`f2f/dht.nim`)。ノード ID = SHA-256(compressed pubkey)。
  ピアの IPv6 は公開鍵で `FIND_NODE` / `FIND_VALUE` により解決する。
- **WoT (Web of Trust)**: DHT で発見した IPv6 ピアを `f2f/wot.nim`
  でスコア化する。**新規/未検証ピアは最小スコアから開始**し、スコアが接続閾値
  (デフォルト 0.0) に達した時点で初めてダイヤルされる。スコアは WoT 紹介と
  成功体験で上昇し、時間経過で減衰する (`decayTrustScores`)。
- **メッセージング**: 署名済みイベントをメッシュ上でゴシップ
  (`f2f/discovery.nim`) — ホップ制限 (MAX_HOPS=2)、
  eventId で重複排除。直接 P2P メッセージは `FodprData` で運ぶ。
- **ブートストラップ (リレーなし)**: 招待コード (`f2finv1...`)、設定シードノード
  (`fpub1...@[ipv6]:port`)、手動 IP 入力。

v0.6 で削除されたもの: リレークライアント、ホスト昇格型グループ (`f2f/group.nim`)、
3モード切替 (`f2f`/`rtcgroup`/`relay`)、リレー経由イベント REST、メディアアップロード API。

---

## 核心設計原則

### 1. F2F + WoT の信頼ゲート
- 招待コードかブートストラップノードで **最初の 1 人** と接続。
- 接続確立直後に **署名付き PeerList** (`TransTypePeerList`) を相互交換し、
    ローカルキャッシュ (`peer_cache.nim`) へマージ。
- キャッシュ中の未接続ピアへ **自動ダイヤル**。WoT スコアが閾値に達したピアのみ接続。
- 最大 50 件まで連鎖的に P2P 接続を広げ、以降はリレーなしで通信可能。

### 2. 自己署名による改ざん検知
- `PeerList` / `WoTIntro` / `DhtMessage` は送信者の秘密鍵で **ECDSA 署名** される
  (`crypto.nim`)。
- 受信側は署名を検証し、正当なピアからのものだけを採用。中間者攻撃やキャッシュ汚染を防止。

### 3. 信頼スコア (trustScore) による質の管理
- 各ピアに `0.0 ~ 1.0` のスコアを付与 (`f2f/wot.nim:decayTrustScores`)。
- 接続成功で上昇、失敗/タイムアウトで低下。**最小値から開始** (新規はダイヤル対象外)。
- WoT 紹介 (`MsgTypeWoTIntro(0x08/0x88)`) で紹介者の信頼を継承し、スコアが閾値
  (connect threshold) に達した時点でダイヤルを許可。
- 時間経過で減衰 (`f2f/wot.nim:decayTrustScores`)。

### 4. 最大 50 件のキャッシュ上限 (LRU + スコア順)
- `peer_cache.nim` (ファイル) に永続化。`selectPeers` はスコア順で選択、古い物から LRU 削除。
- 再起動時にキャッシュから即座に自動ダイヤル開始。

### 5. WoT 紹介 (WoT Introduction)
- 信頼できるピアから `MsgTypeWoTIntroPush` で新ピアを紹介 (`f2f/discovery.nim:processWoTIntroduction`)。
  紹介者の trustScore をベースに評価し、知り合いの知り合いを
  「紹介」として受け取れる。

### 6. Kademlia DHT によるピア発見と IP 解決
- 256ビット ID (`nodeId = SHA-256(compressed pubkey)`)、k-buckets ルーティングテーブル
  (`f2f/dht.nim`)。
- `PING` / `FIND_NODE` / `FIND_VALUE` / `STORE` を **データチャネル上** で RPC。
  `FIND_VALUE` により公開鍵 → IPv6 の解決。ルーティングテーブルは少なくとも 1 つの
  メッシュ隣接が生きていれば生存する。

### 7. ゴシップによるイベント同期
- 署名済みイベントをメッシュ隣接へ `MsgTypeEvent(0x01)` でフラッシュ。
- ホップ制限 (`MAX_HOPS=2`)、`Set<eventIdHex>` で重複排除。
- 直接 P2P メッセージは `FodprData` (`TransTypeSigned` 等) で運ぶ。

---

## プロトコルフロー

```
ブートストラップ
┌──────────────┐     招待コード / 設定ブートストラップ    ┌──────────────┐
│  Alice       │ ─────────────────────────────▶ │  Bob          │
│  (新規参入)  │  初回 1 対 1 F2F 接続確立        │  (既存ピア)   │
└──────────────┘                                └──────────────┘
        │                                  WebRTC データチャネル
        ▼                                          ▼
┌──────────────┐  PeerList + WoTIntro 交換   ┌──────────────┐
│  Alice       │ ◀────────────────────────▶ │  Bob         │
│  (キャッシュ) │  (署名付き, 最大 50 件)      │  (キャッシュ) │
└──────────────┘                              └──────────────┘
        │
        │ キャッシュマージ & WoT スコア>=閾値ピアへ自動ダイヤル
        ▼
   ... 最大 50 接続まで連鎖的に拡大 ...
        │  (DHT FIND_VALUE で IPv6 を解決し直接ダイヤル)
        ▼
┌──────────────┐   ゴシップ: 署名イベントを隣接へフラッシュ (MAX_HOPS=2)
│  Mesh        │ ─────────────────────────────────────────▶
│ (リレー不要) │
└──────────────┘
```

---

## データ構造

### PeerInfo (ピア情報) — `protocol.nim:FodprData.PeerInfo`
```typescript
interface F2FPeerInfo {
  pubkey: string;        // 公開鍵 (HEX, 33 bytes compressed)
  addresses: string[];   // 接続アドレス (IPv6 一時アドレス [ipv6]:port 等)
  lastSeen: number;      // 最後に見た時刻 (Unix秒)
  trustScore: number;    // WoT 信頼スコア (0.0 ~ 1.0, 新規は最小値)
}
```

### PeerList (キャッシュ交換) — `TransTypePeerList (0x09)` / `MsgTypePeerListPush (0x87)`
- 構造: `version(8) | peerCount(2) | PeerInfo[] | signature(64)` (署名領域は `envelope.nim` の SignedData で)
- 最大 50 件。WoT キャッシュ同期専用。

### WoTIntro (WoT 紹介) — `TransTypeWoTIntro (0x0A)` / `MsgTypeWoTIntro(0x08)` / `MsgTypeWoTIntroPush(0x88)` (`protocol.nim:WoTIntro`)
```
introducer: SkPublicKey(33)      # 紹介者の公開鍵
newPeer: PeerInfo                 # 紹介する新ピアの情報
signature: FodprSignature(64)     # 紹介者の署名 (introducer/newPeer 全体)
```
- 紹介者の信頼をベースに、`newPeer` の初期 trustScore を決定 (シビル耐性)。

### 招待コード (InvitationCode) — `TransTypeInvitation (0x0B)` / `MsgTypeInvitationReq(0x09)` / `MsgTypeInvitationPush(0x89)`
- Bech32: `f2finv1...` (`f2f/invitation.nim`)。
- 構造: `version(1) | issuer(33) | targetPeer(PeerInfo) | expiresAt(8) | scope(1) | signature(64)`
- `scope`: 0 = 単発接続, 1 = WoT 招待 (キャッシュ共有含む)。

### DHT メッセージ — `MsgTypeDht (0x0B)` / `MsgTypeDhtNodes (0x8B)` / `MsgTypeDhtValue (0x8C)` (`f2f/dht.nim`)
```typescript
interface DhtMessage {
  op: number;            // DhtOpPing(0)/Pong(1)/FindNode(2)/FindValue(3)/Store(4)
  msgId: Uint8Array;     // 16B ランダム ID (要求/応答対応)
  key: Uint8Array;       // 32B nodeId (FindNode/FindValue/Store)
  nodes: DhtNodeInfo[];  // FindNode 応答: 近傍ノード (最大 k=20)
  value: Uint8Array;     // FindValue/Store のペイロード (例: "[ipv6]:port" レコード)
  sender: Uint8Array;    // 33B compressed pubkey
  signature: Uint8Array; // 64B ECDSA
}
interface DhtNodeInfo {
  nodeId: Uint8Array;    // 32B SHA-256(pubkey)
  pubkey: Uint8Array;    // 33B compressed
  addresses: string[];
  lastSeen: number;
  trustScore: number;
}
```
- Node ID = `nodeId(pub) = SHA-256(compressed pubkey)` (256ビット)。XOR 距離で近傍を判定。

### FodprData (直接 P2P メッセージ) — `protocol.nim:FodprData`
- `MsgTypeData (0x06)` で運ぶ。`TransTypeSigned / TransTypeEncrypted` 等の content 型を取る。

---

## 実装箇所

### `/root/Fodpr/src` (Nim — プロトコル/ツールキット)

| ファイル | 役割 |
|---------|------|
| `src/protocol.nim` | メッセージ種別 / TransType / DhtOp / データ構造 (PeerInfo, PeerList, WoTIntro, InvitationCode, DhtMessage, FodprData) |
| `src/crypto.nim` | ECDSA 鍵生成・署名・検証 |
| `src/envelope.nim` | 署名付きイベント/メッセージのフレーム (SignedData) |
| `src/Fodpr.nim` | ライブラリエントリ (全モジュール re-export)。HTTP/リレーサーバーはなし |
| `f2f/dht.nim` | Kademlia ルーティングテーブル (256ビット ID, k-buckets), PING/FIND_NODE/FIND_VALUE/STORE |
| `f2f/wot.nim` | WoT グラフ (addWoTIntroduction / findTrustPath / recommendPeersByTrust / decayTrustScores) |
| `f2f/discovery.nim` | WoT グラフ構築, getNextCandidates, requestPeerList/sendPeerList, WoT 紹介処理 |
| `f2f/peer_cache.nim` | ピアキャッシュ永続化 (50 件 LRU+スコア順), selectPeers |
| `f2f/invitation.nim` | Bech32 招待コード encode/decode/verify (`f2finv1...`) |
| `f2f/signaling.nim` | F2F SDP offer/answer/candidate サポート |
| `f2f/transport.nim` | WebRTC データチャネル send/receive, IPv6 プレフィックス + インターフェース ID 生成 |
| `f2f/bootstrap.nim` | 設定シードノード (`fpub1...@[ipv6]:port`) からのブートストラップ |

---

## 運用上の考慮点

1. **初回ブートストラップ (リレーなし)**
   - 完全新規ユーザーは招待コード (`f2finv1...`, `f2f/invitation.nim`) か、設定シードノード
     (`f2f/bootstrap.nim`) から開始。
   - 明示アドレス (招待/シード/手動 IP) は **WoT ゲートをバイパスし直接ダイヤル可能**
     (信頼済みピア)。アンカーを 1 本繋ぐと DHT が残りのグラフを解決する。
   - 到達できない場合のみ手動 IPv6 入力でフォールバック。
   - DHT `FIND_VALUE` で公開鍵 → IPv6 を解決し直接ダイヤル。
     ダイヤル失敗時は既接続メッシュピア経由シグナリングへフォールバック。

2. **NAT トラバーサル / アドレス**
   - IPv6 一時アドレス (`f2f/transport.nim:getCurrentIpv6Prefix()` + インターフェース ID)
     を `addresses` に含める。STUN/TURN は基本使わず、直接 IPv6 ダイヤルを優先。

3. **オフライン耐性**
   - ピアキャッシュ / WoT グラフは `peer_cache.nim` (ファイル) に永続化。
   - 次回起動時にキャッシュから即座に自動ダイヤル開始。

4. **プライバシー**
   - PeerList / WoTIntro / DhtMessage の交換は **暗号化データチャネル** で行う。
   - ゴシップイベントは署名検証により正当性を担保。直接メッセージは `FodprData` 内で
     `TransTypeEncrypted` により暗号化可能。

5. **スパム / 悪意あるピア対策**
   - WoT スコアが低いピアはダイヤル対象外 (connect threshold ゲート)。
   - 署名検証で正当なピア以外の PeerList / DhtMessage を拒否。
   - スコア低下で接続を切断・優先度を下げる。

---

## 関連ドキュメント

- [Fodpr プロトコル仕様 (README.md)](../README.md)
