# F2F (Friend-to-Friend) / WoT (Web of Trust) 設計思想 — v0.6 "Mesh"

## 概要
F2F は、Fodpr プロトコルにおける **友人ベースの P2P メッシュネットワーク層** です。` /root/Fodpr/src` (Nim) が実装する、**リレーサーバーなし**のクライアント間 F2F 接続と、それに乗せる DHT / WoT / ゴシップのプロトコル群を定義します。

- **接続形態**: クライアント間 F2F (WebRTC データチャネル)。ホスト/星形トポロジは廃止。すべてのピアはメッシュの隣接ピア群へ直接接続する。
- **IP 発見**: Kademlia DHT を **WebRTC データチャネル上** で走らせる (`f2f/dht.nim`)。ノード ID = SHA-256(compressed pubkey)。ピアの IPv6 は公開鍵で `FIND_NODE` / `FIND_VALUE` により解決する。
- **WoT (Web of Trust)**: DHT で発見した IPv6 ピアを `f2f/wot.nim` でスコア化する。**新規/未検証ピアは最小スコアから開始**し、スコアが接続閾値 (デフォルト 0.0) に達した時点で初めてダイヤルされる。スコアは**接続実績（成功/失敗）と時間減衰のみ**で変動し、WoT 紹介による影響はない。
- **メッセージング**: 署名済みイベントをメッシュ上でゴシップ (`f2f/discovery.nim`) — ホップ制限 (MAX_HOPS=2)、eventId で重複排除。直接 P2P メッセージは `FodprData` で運ぶ。
- **ブートストラップ (リレーなし)**: 招待コード (`f2finv1...`)、設定シードノード (`fpub1...@[ipv6]:port`)、手動 IP 入力。
- **GeoIP 排多様性**: ダイヤル候補選抜時に **国ごとに最大 2 本を優先確保**し、地域分断リスクを低減。
- **IPv6 インバウンド遮断対策**: 住宅用 CPE/ファイアウォールのデフォルト遮断を前提に、招待コード・シードノード経由、シグナリングフォールバック、ICE/STUN を多層で防御。

v0.6 で削除されたもの:
- リレークライアント、ホスト昇格型グループ (`f2f/group.nim`)、3モード切替 (`f2f`/`rtcgroup`/`relay`)、リレー経由イベント REST、メディアアップロード API。
- **ビルトインコミュニティブートストラップアンカー** (`FODPR_BOOTSTRAP_ANCHORS`)。削除理由:
  - プレースホルダだった 2001:db8::/32 は RFC 3849 の「ドキュメント用」予約帯で実回線では到達不可能。実アンカーを 1 件も運用していない状態で番地を同梱しても意味がない。
  - アンカーを 1 本常駐させるには「常時リスン IPv6 + WebRTC 待受ノード」が必要だが、ブラウザのみの構成でそれを保証・運用する手段がない。
  - **ブートストラップは招待コードで十分**。招待コードの faucet サイト (WebUI の「発行」で誰でも生成可) を設ければ、新規参入者は知人/ポータルからコードを受け取って入れる。設定シードノード (`fodpr_bootstrap_nodes`) と手動 IP 入力がフォールバックとして残る。

---

## 核心設計原則

## 1. F2F + WoT の信頼ゲート
招待コードかブートストラップノードで **最初の 1 人** と接続。接続確立直後に **署名付き PeerList** (`TransTypePeerList`) を相互交換し、ローカルキャッシュ (`peer_cache.nim`) へマージ。キャッシュ中の未接続ピアへ **自動ダイヤル**。WoT スコアが閾値に達したピアのみ接続。最大 50 件まで連鎖的に P2P 接続を広げ、以降はリレーなしで通信可能。

## 2. 自己署名による改ざん検知
`PeerList` / `WoTIntro` / `DhtMessage` は送信者の秘密鍵で **ECDSA 署名** される (`crypto.nim`)。受信側は署名を検証し、正当なピアからのものだけを採用。中間者攻撃やキャッシュ汚染を防止。

## 3. 身元信頼とネットワーク信頼性
各ピアに以下 2 つのスコアを付与 (`protocol.nim`)。
- **identityTrust** (0.0 ~ 1.0): 公開鍵による**取得元（issuer）での身元信頼度**。新規ピアはスコア 0.0 から開始。現在は参考情報として保持される。判定ロジックには使用しない。
- **reliabilityScore** (0.0 ~ 1.0): ネットワーク接続実績・安定性。接続成功で上昇、失敗/タイムアウトで低下。

**2 スコア分離の利点**:
- identityTrust: 知人紹介や公開鍵基盤での信頼継承。Sybil耐性の基礎。
- reliabilityScore: 実際の接続品質と持続性。信頼スコアが閾値 (connect threshold) に達したピアのみダイヤル許可。

WoT 紹介 (`MsgTypeWoTIntro(0x08/0x88)`) は**発信情報の記録のみ**。reliabilityScoreは紹介で決定されず、newPeerは常に0.0から開始し、接続実績（成功/失敗）と時間減衰 (`f2f/wot.nim:decayTrustScores`) で変動する。identityTrust は変更されない。connect threshold: reliabilityScore >= 0.0 で初めてダイヤル可能（デフォルト最小値）。

## 4. 最大 50 件のキャッシュ上限 (LRU + スコア順)
`peer_cache.nim` (ファイル) に永続化。`selectPeers` はスコア順で選択、古い物から LRU 削除。再起動時にキャッシュから即座に自動ダイヤル開始。

## 5. WoT 紹介 (WoT Introduction) with Distance Decay
信頼できるピアから `MsgTypeWoTIntroPush` で新ピアを紹介 (`f2f/discovery.nim:processWoTIntroduction`)。

紹介 (`WoTIntro`):
- **introducer**: 紹介者の公開鍵
- **newPeer**: 紹介する新ピアの PeerInfo
- **signature**: 紹介者の署名 (introducer/newPeer 全体)
- **hopCount**: 紹介パスのホップ数 (1 バイト)
- **pathDecay**: 距離減衰係数 (float64, ビッグエンディアン)。ホップ数に応じて信頼が減衰。
- **expiresAt**: 有効期限 (uint64, ビッグエンディアン)。紹介はこのタイムスタント以降無効。

距離減衰数学的モデル:

- **WoT紹介は発見と来歴の記録のみ。reliabilityScoreは紹介で変更されない**。
- expiresAt (秒単位) で紹介の有効期限を設定。古い紹介は無視され、新しい紹介が採用される。

## 6. Kademlia DHT によるピア発見と IP 解決
256ビット ID (`nodeId = SHA-256(compressed pubkey)`)、k-buckets ルーティングテーブル (`f2f/dht.nim`)。`PING` / `FIND_NODE` / `FIND_VALUE` / `STORE` を **データチャネル上** で RPC。`FIND_VALUE` により公開鍵 → IPv6 の解決。ルーティングテーブルは少なくとも 1 つの メッシュ隣接が生きていれば生存する。

## 7. ゴシップによるイベント同期
署名済みイベントをメッシュ隣接へ `MsgTypeEvent(0x01)` でフラッシュ。ホップ制限 (`MAX_HOPS=2`)、**今後増やす予定**。`Set<eventIdHex>` で重複排除。直接 P2P メッセージは `FodprData` (`TransTypeSigned` 等) で運ぶ。

## 8. 設計上の課題と検証項目

- **WebRTC接続の確立経路**: WebRTCは既知のIPv6:portへの直接ダイヤルではなく、SDP/offer-answer経路が必須。両ピアがIPv6ファイアウォール/CGNAT下ならSTUNのみでは不成立となり、TURNサーバーまたはアプリ層中継が必要。現状MAX_HOPS=2では広範囲のイベント届かず。

- **招待IDの一回利用管理**: `invitationId` の「一回限り」利用は、分散環境で「使用済み」を誰が確定するか未定義。spent-setの共有管理または発行者単位の管理が必要。

- **公開鍵と回線情報の紐付けリスク**: DHTのFIND_VALUEで公開鍵→一時IPv6の解決 then 公開することは、鍵と回線情報の紐付け・追跡リスクがある。匿名化ルーティングやランダムIP生成が必要。

- **MAX_HOPSの小規模限定**: MAX_HOPS=2は小規模LAN向け。広がりあるメッシュではイベントが全体に届かず、反エントロピー同期が必要。ホップ制限を緩和しつつ、信頼スコア減衰 (`decayTrustScores`) と組み合わせたゴシッププロトコルの見直しが必要。

## プロトコルフロー
```
<ブートストラップ>
┌────────────┐ 招待コード / 設定ブートストラップ ┌───────────┐
│ Alice      │ ────────────────────────────────▶ │ Bob       │
│ (新規参入) │ 初回 1 対 1 F2F 接続確立          │ (既存ピア)│
└────────────┘                                   └───────────┘
          │                                  WebRTC データチャネル
          ▼                                          ▼
┌──────────────┐  PeerList + WoTIntro 交換   ┌──────────────┐
│ Alice        │ ◀────────────────────────▶  │ Bob          │
│ (キャッシュ) │  (署名付き, 最大 50 件)     │ (キャッシュ) │
└──────────────┘                             └──────────────┘
          │        
          │  キャッシュマージ & WoT スコア>=閾値ピアへ自動ダイヤル
          │   ... 最大 50 接続まで連鎖的に拡大 ...
          ▼  ゴシップ: 署名イベントを隣接へフラッシュ (MAX_HOPS=2)
      ┌────────┐                               ┌──────────────┐
      │  Mesh  │ ─────────────────────────────▶│ (リレー不要) │
      └────────┘                               └──────────────┘
````
## データ構造

> **F2F 用送信タイプ (TransType)** (リレー互換の `TransTypeWebRTC = 6` を**残す**。新規 F2F 通信は 8 以上を使用)
> - `TransTypeData = 7` — 署名付き P2P データチャネルメッセージ
> - `TransTypeF2FSignal = 8` — **P2P 直接シグナリング** (SDP/ICE を P2P データチャネルで直接交換。seed/リレー経由の WebRTC シグナリングと分離)
> - `TransTypePeerList = 9` — ピアリスト交換 (WoT キャッシュ同期)
> - `TransTypeWoTIntro = 10` — WoT 紹介メッセージ
> - `TransTypeInvitation = 11` — インビテーションコード

## PeerInfo (ピア情報) — `protocol.nim:FodprData.PeerInfo`
```typescript
interface F2FPeerInfo {
  pubkey: string;        // 公開鍵 (HEX, 33 bytes compressed)
  addresses: string[];   // 接続アドレス (IPv6 一時アドレス [ipv6]:port 等)
  lastSeen: number;      // 最後に見た時刻 (Unix秒)
  identityTrust: number; // 身元信頼 (0.0 ~ 1.0): 公開鍵による信頼度
  reliabilityScore: number; // ネットワーク信頼性 (0.0 ~ 1.0): 接続実績・安定性
  country?: string;      // GeoIP 国コード (ISO 3166-1 alpha-2), /64 プレフィクスから推定
}
```

## PeerList (キャッシュ交換) — `TransTypePeerList (0x09)` / `MsgTypePeerListPush (0x87)`
構造: `version(8) | peerCount(2) | PeerInfo[] | signature(64)` (署名領域は `envelope.nim` の SignedData で)
最大 50 件。WoT キャッシュ同期専用。

## WoTIntro (WoT 紹介) — `TransTypeWoTIntro (0x0A)` / `MsgTypeWoTIntro(0x08)` / `MsgTypeWoTIntroPush(0x88)` (`protocol.nim:WoTIntro`)
- introducer: SkPublicKey(33) — 紹介者の公開鍵
- newPeer: PeerInfo — 紹介する新ピアの情報
- signature: FodprSignature(64) — 紹介者の署名 (introducer/newPeer 全体)

WoT紹介は発見と来歴の記録にのみ使用され、`newPeer` のスコアに影響はない。

## 招待コード (InvitationCode) — `TransTypeInvitation (0x0B)` / `MsgTypeInvitationReq(0x09)` / `MsgTypeInvitationPush(0x89)` Bech32: `f2finv1...` (`f2f/invitation.nim`)。
構造: `version(1) | issuer(33) | targetPeer(PeerInfo) | expiresAt(8) | scope(1) | invitationId(16) | usedAt(8) | signature(64)`
- `invitationId`: anti-reuse 用ランダム 16 バイト (1 回限り利用)
- `usedAt`: 使用時刻 (uint64)。同じ invitationId が 2 回使われると無効。
- `scope`: 0 = 単発接続, 1 = WoT 招待 (キャッシュ共有含む)。
- **招待コードはブートストラップにのみ必要**: 通常時は既存ピアからWoTキャッシュを介して接続可能。新規参入時のみブートストラップ段階で使用する。

## DHT メッセージ — `MsgTypeDht (0x0B)` / `MsgTypeDhtNodes (0x8B)` / `MsgTypeDhtValue (0x8C)` (`f2f/dht.nim`)
```typescript
interface DhtMessage {
  op: number;            // DhtOpPing(0)/Pong(1)/FindNode(2)/FindValue(3)/Store(4)
  msgId: Uint8Array;     // 16B ランダム ID (要求/応答対応)
  key: Uint8Array;       // 32B nodeId (FindNode/FindValue/Store)
  nodes: DhtNodeInfo[];  // FindNode 応答: 近傍ノード (最大 k=20)
  value: Uint8Array;     // FindValue/Store ペイロード (EndpointRecord: seq(8) + expiresAt(8) + signature(64) + [ipv6]:port)
  sender: Uint8Array;    // 33B compressed pubkey
  signature: Uint8Array; // 64B ECDSA
}
interface DhtNodeInfo {
  nodeId: Uint8Array;    // 32B SHA-256(pubkey)
  pubkey: Uint8Array;    // 33B compressed
  addresses: string[];   // 接続アドレス
  lastSeen: number;      // 最後に見た時刻
  identityTrust: number; // 身元信頼
  reliabilityScore: number; // ネットワーク信頼性
}
```
- `value` ペイロード: `EndpointRecord` (シーケンス番号 + 有効期限 + 署名付き IP:ポート レコード)。
- `STORE` で保存される値は `EndpointRecord` 形式で、送信者の署名により改ざん検知可能。
- `FIND_VALUE` により公開鍵 → 有効な EndpointRecord (IP:ポート + 有効期限 + 署名) を解決。
- replay protection: seq + expiresAt で同じ value の再保存を防止。

## FodprData (直接 P2P メッセージ) — `protocol.nim:FodprData`
`MsgTypeData (0x06)` で運ぶ。`TransTypeSigned / TransTypeEncrypted` 等の content 型を取る。

## 実装箇所

## `/root/Fodpr/src` (Nim — プロトコル/ツールキット)
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
| `f2fMesh.ts` (TS) | メッシュマネージャ: WebRTC ピア接続 / ダイヤル / ゴシップ / **GeoIP 多様性選抜** / 招待コード・シードノードによるブートストラップ |
| TypeScript SDK: WebUI/CLI用。実装の大元はNim (`src/`) |

## 運用上の考慮点

1. **初回ブートストラップ (リレーなし)**
    - 完全新規ユーザーは招待コード (`f2finv1...`, `f2f/invitation.nim`) で開始。招待コードの `faucetサイト` は誰でも作成可能 (WebUI の「発行」で誰でも生成できるため、ポータル/知人がコードを配布すればよい)。新規ユーザーは WebUI の「招待コードで接続」にコードを貼って入場する。
    - 招待コードが無い場合は設定シードノード (`f2f/bootstrap.nim`, `fodpr_bootstrap_nodes`) または手動 IP 入力で開始。**ビルトインアンカーは持たない** (理由は「v0.6 で削除されたもの」参照)。
   - 明示アドレス (招待/シード/手動 IP) は **WoT ゲートをバイパスし直接ダイヤル可能** (信頼済みピア)。1 本繋ぐと DHT が残りのグラフを解決する。
   - 到達不能時は手動 IPv6 入力でフォールバック。
   - DHT `FIND_VALUE` で公開鍵 → IPv6 を解決し直接ダイヤル。ダイヤル失敗時は既接続メッシュピア経由シグナリングへフォールバック。

2. **NAT トラバーサル / アドレス**
   - IPv6 一時アドレス (`f2f/transport.nim:getCurrentIpv6Prefix()` + インターフェース ID) を `addresses` に含める。STUN/TURN は基本使わず、直接 IPv6 ダイヤルを優先。
   - ICE 候補に IPv6 一時アドレス + ポートを含め、STUN (Google `stun.l.google.com:19302` 等) で NAT タイプ検出・ホールパンチングを試行。

3. **IPv6 インバウンド遮断の現状と多層防御 ⚠️**
   - 一般家庭用 CPE/ルーターはデフォルトで IPv6 インバウンドを遮断しています (Verizon, AT&T, Unifi 等のデフォルトファイアウォール設定)。
   - モバイル回線 (4G/5G) は CGNAT 的構成でほぼインバウンド不可。
   - データセンター / VPS / クラウドのみ適切な設定で到達可能。

4. **影響**: 完全遮断環境同士では直接 F2F 接続不能。メッシュ参加には **少なくとも 1 つの到達可能ピア (知人/VPS)** が必要。

5. **多層防御**:
   1. **到達可能な知人/シードノード** (VPS/データセンター/開放済み自宅) をユーザー設定 `fodpr_bootstrap_nodes` に登録し、そこを入り口にする (招待コードはその知人からもらう)。
   2. **シグナリングフォールバック**: 直接ダイヤル失敗時、既接続メッシュピアを経由して SDP/ICE を中継し、ホールパンチングを試行。
   3. **ICE/STUN**: Google STUN 等で NAT タイプ検出・ホールパンチング成功率を向上。
   4. **ICE リスタート**: 接続断検知時、新しい ICE 候補で再ネゴシエーション。

6. **ユーザー側設定ガイド**: ルーターの IPv6 ファイアウォールで「ピンホール/ポート開放」を有効にする。

## 実装ステータス / 開発コマンド

- `src/protocol.nim` に F2F 拡張 (`TransTypeF2FSignal = 8`, `PeerInfo` with `identityTrust`/`reliabilityScore`, `InvitationCode` with `invitationId`/`usedAt`) を追加済み。
- `src/f2f/peer_cache.nim`, `discovery.nim`, `bootstrap.nim`, `wot.nim`, `invitation.nim`, `dht.nim` は **コンパイル修正済** (`reliabilityScore` 基準, `Option`/`Thread` API, `createInvitation`/`encodeInvitation`/`verifyInvitation` を `f2f/invitation.nim` が公開 API とし `protocol.nim` のバイナリ版は `*Binary`/`*Sig` へリネーム)。既存 `TransTypeWebRTC(6)`/`MsgTypeSignal` は互換性維持。

参考実装 (IPv6 到達性のみを端末で検証する TUI ツール):

- `examples/ipv6test.nim` — Nim + illwill ターミナル TUI。
  - 起動時に秘密鍵を `~/.fodpr/ipv6test/identity.fsec` へ生成/永続化。
  - `/proc/net/if_inet6` をパースして自身の IPv6 (Global / Link-local) を表示。
  - `[1]` 招待コード発行 (`f2finv1...`, Bech32)。
  - `[2]` 招待コード入力 (貼り付け対応) → `[3]` IPv6:port へ TCP 接続テスト (別スレッド, タイムアウト 5s, RTT 表示)。
   - ビルド (Linux): `nimble c -d:release --threads:on --out:examples/ipv6test examples/ipv6test.nim`
   - ビルド (Android ARM64, x86_64 Linux からクロス): `nimble c -d:release --threads:on --cpu:arm64 --passC:"-O2" --out:examples/ipv6test_arm64 examples/ipv6test.nim` (必要: `aarch64-linux-gnu-gcc`)
   - 実行: `./examples/ipv6test` → `q`/`Ctrl-C` 終了

```bash
# ビルド
nimble build -y
# テスト実行
nim c -r tests/test_f2f.nim
# プロトコルデモ（サーバー不要）
nim c -r examples/protocol_demo.nim
# IPv6 F2F 接続テスト (TUI, サーバー不要)
./examples/ipv6test        # x86_64 Linux
./examples/ipv6test_arm64  # Android ARM64
# クライアント（リレー必要）
nim c -r examples/fodpr_client.nim
```

## 関連ドキュメント
- [Fodpr プロトコル仕様 (README.md)](../README.md)
- [イベント/ワイヤフォーマットリファレンス (v0.6 ゴシップ版)](../FodprWebClient/reference.md)