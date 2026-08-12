# Fodpr F2F ネットワーク実装 AGENTS.md

## 概要
Fodpr（Fully Open Decentralized Protocol）を基盤とした完全分散型（F2F: Friend-to-Friend）ネットワークの実装ガイド。
中央リレーに常時依存せず、Web of Trust (WoT) ベースの自律的ピア交換を基本とし、インビテーション優先・リレーフォールバックのハイブリッド接続モデルを採用する。

## アーキテクチャ

### コアモジュール構成
```
src/
├── Fodpr.nim          # メインモジュール（再エクスポート）
├── protocol.nim       # ワイヤプロトコル（既存 + F2F拡張）
├── crypto.nim         # 暗号プリミティブ（既存）
├── envelope.nim       # 暗号化エンベロープ（既存）
├── f2f/
│   ├── peer_cache.nim     # ピアキャッシュ・ローテーション管理
│   ├── discovery.nim      # WoTベースピア発見
│   ├── bootstrap.nim      # シードリレー・フォールバック（最終手段）
│   ├── wot.nim            # Web of Trust 構築・管理
│   ├── invitation.nim     # インビテーションコード生成・検証
│   ├── signaling.nim      # P2Pシグナリング（リレー非依存）
│   └── transport.nim      # IPv6一時アドレス + WebRTCデータチャネル
```

### ネットワークモデル
- **平常時**: 完全P2P（IPv6一時アドレス + Fodpr署名付きWebRTCデータチャネル）
- **トポロジ**: ソーシャルグラフ（知人のつながり）ベースのピアツリー構造（WoT）
- **救済手段**: インビテーションコード（第1救済） → シードリレー（最終フォールバック）

## 接続・リカバリー優先順位

```
[クライアント起動]
       │
       ├── 1. 【通常時】WoTキャッシュローテーション
       │      └─ 成功 ──> P2P（一時IPv6 ＋ 署名付きWebRTC）で自律通信
       │      └─ 失敗（キャッシュ切れ・デッドエンド）
       │
       ├── 2. 【第1救済】インビテーションコードの入力（手動/QR/URI）
       │      └─ 成功 ──> 接続先のWoTリストを取得してキャッシュ更新
       │      └─ 失敗（コードが無効・接続不可）
       │
       └── 3. 【最終フォールバック】リレーサーバーからのシード取得
              └─ 成功 ──> アクティブなノードリストを取得してネットワークに合流
```

## 実装仕様

### 1. ピアキャッシュ・ローテーション (peer_cache.nim)
```nim
const MAX_CACHE_SIZE = 50

type
  PeerInfo* = object
    pubkey*: SkPublicKey        # 公開鍵 (fpub)
    addresses*: seq[string]     # 接続アドレス (IPv6一時アドレス等)
    lastSeen*: uint64           # 最後に見た時刻 (Unix秒)
    trustScore*: float          # 信頼スコア (0.0-1.0)

  PeerCache* = object
    peers*: seq[PeerInfo]       # 最大50件
    version*: uint64            # キャッシュバージョン（更新毎にインクリメント）

proc loadCache*(): PeerCache
proc saveCache*(cache: PeerCache)
proc selectPeers*(cache: PeerCache, count: int): seq[PeerInfo]
proc updateCache*(cache: PeerCache, newPeers: seq[PeerInfo]): PeerCache
```
- 接続成功時、相手から最大50件の有効ピアリストを取得
- 取得完了後、古いキャッシュを破棄し新しいキャッシュに完全置換
- ローカルストレージ（ファイル/DB）に永続化

### 2. インビテーションコード (invitation.nim) - 第1救済・F2Fの原則
```nim
type
  InvitationCode* = object
    version*     : uint8        # バージョン
    issuer*      : SkPublicKey  # 発行者の公開鍵
    targetPeer*  : PeerInfo     # 接続対象のピア情報
    expiresAt*   : uint64       # 有効期限 (Unix秒)
    scope*       : uint8        # 0=単発接続, 1=WoT招待(キャッシュ共有含む)
    signature*   : FodprSignature # 発行者の署名

proc createInvitation*(issuerPriv: SkSecretKey, targetPeer: PeerInfo,
                       expiresInSec: uint64, scope: uint8): InvitationCode
proc encodeInvitation*(inv: InvitationCode): string  # Bech32エンコード (f2finv1...)
proc decodeInvitation*(code: string): InvitationCode
proc verifyInvitation*(inv: InvitationCode): bool
```
- 知人から共有される招待データ（QRコード、URIスキーム `fodpr://invite/...`、テキスト）
- 署名検証により改ざん・なりすましを防止
- 有効期限・スコープ（単発接続 vs WoT招待）を持つ

### 3. WoTベースピア発見 (discovery.nim, wot.nim)
```nim
type
  WoTNode* = object
    pubkey*: SkPublicKey
    connections*: seq[SkPublicKey]  # 直接知っているピア
    introducedBy*: Option[SkPublicKey]  # 紹介者（信頼の連鎖）

proc buildWoT*(cache: PeerCache, myPubkey: SkPublicKey): seq[WoTNode]
proc getPeerListFromPeer*(conn: WebRTCConnection, maxPeers: int = 50): seq[PeerInfo]
proc introducePeer*(myPriv: SkSecretKey, targetPub: SkPublicKey, newPeer: PeerInfo): string
  # 署名付き紹介メッセージを生成
```

### 4. シードブートストラップ・フォールバック (bootstrap.nim) - 最終手段
```nim
const
  DEFAULT_SEED_RELAYS* = @[
    "wss://seed1.fodpr.example.com/",
    "wss://seed2.fodpr.example.com/"
  ]

type
  SeedNode* = object
    pubkey*: SkPublicKey
    addresses*: seq[string]

proc bootstrapFromSeed*(seedUrl: string): seq[SeedNode]
proc fallbackToSeed*(cache: PeerCache): seq[SeedNode]
  # インビテーションも失敗しキャッシュ全滅時のみ発動
```

### 5. P2Pシグナリング (signaling.nim) - リレー非依存
```nim
# WebRTCシグナリングをP2Pデータチャネル経由で直接行う
# 既存の TransTypeWebRTC / MsgTypeSignal はシード/リレー用として残す
# 新規: TransTypeF2FSignal (8) = P2P直接シグナリング

type
  F2FSignal* = object
    signalType*: uint8        # Offer/Answer/Candidate
    sender*: SkPublicKey
    target*: SkPublicKey
    content*: string          # SDP/ICE JSON
    signature*: FodprSignature
    viaRelay*: bool           # false = 直接P2P

proc createF2FOffer*(priv: SkSecretKey, target: SkPublicKey, sdp: string): F2FSignal
proc sendSignalDirect*(conn: WebRTCDataChannel, signal: F2FSignal)
```

### 6. トランスポート層 (transport.nim)
```nim
type
  F2FConnection* = object
    dataChannel*: WebRTCDataChannel
    remotePubkey*: SkPublicKey
    localIpv6Temp*: string    # 自分のIPv6一時アドレス
    remoteIpv6Temp*: string   # 相手のIPv6一時アドレス
    seq*: uint64              # メッセージシーケンス

proc establishF2FConnection*(localPriv: SkSecretKey, remotePeer: PeerInfo): F2FConnection
proc sendF2FData*(conn: F2FConnection, content: string, tags: seq[string])
proc rotateIpv6Address*(conn: F2FConnection)
  # 定期的なIPv6一時アドレスローテーション
```

## メッセージフロー

### 通常起動（キャッシュあり）
```
1. クライアント起動 → ローカルキャッシュ確認
2. キャッシュからピア選択 (信頼スコア順・ランダム化)
3. 選択ピアへ並列ダイアル (最大3-5並列)
4. 接続成功 → 相手から最新ピアリスト(最大50)取得
5. 取得完了 → 古いキャッシュ破棄 → 新キャッシュ保存
6. 以降のライブ通信は確立したP2Pデータチャネルで直接
```

### 初回起動・キャッシュ切れ時（インビテーション）
```
1. クライアント起動 → ローカルキャッシュ確認 → 空または全滅
2. ユーザーにインビテーションコード入力を促す (QR/URI/テキスト)
3. コード検証成功 → 指定ピアへ直接接続
4. 接続成功 → WoTリスト(最大50)取得 → ローカルキャッシュ保存
5. 以降は通常フローへ
```

### 孤立検知・最終フォールバック
```
1. キャッシュ内ピアへ全並列ダイアル失敗
2. または 全ピアがオフライン（lastSeen が閾値超過）
3. インビテーションコード入力を促す → 入力・検証成功なら手順4へ
4. インビテーションも失敗/入手不可 → シードリレーへ一時接続
5. 新しいシードリスト取得 → アクティブノードへ並列ダイアル
6. 1つでも成功 → WoT参加完了 → シード切断
7. 成功したピアからピアリスト取得 → ローカルキャッシュ保存
8. 以降の通信は完全P2P
```

## データ構造拡張 (protocol.nim へ追加)

### 新しい TransType
- `TransTypeF2FSignal = 8` - P2P直接シグナリング
- `TransTypePeerList = 9` - ピアリスト交換 (WoTキャッシュ同期)
- `TransTypeWoTIntro = 10` - WoT紹介メッセージ

### 新しいメッセージタイプ
- `MsgTypePeerListReq = 0x07` - ピアリスト要求
- `MsgTypePeerListPush = 0x87` - ピアリスト配信
- `MsgTypeWoTIntro = 0x08` - WoT紹介
- `MsgTypeWoTIntroPush = 0x88` - WoT紹介配信

### ピアリスト交換フォーマット
```
PeerList (content for TransTypePeerList):
  version(8) | peerCount(2) | 
  (pubkey(33) | addrCount(1) | (addrLen(2) | addr)* | lastSeen(8) | trustScore(4))* peerCount
```

### インビテーションコードフォーマット (Bech32: f2finv1...)
```
InvitationCode (エンコード前):
  version(1) | issuerPubkey(33) | targetPeer(PeerInfo) | expiresAt(8) | scope(1) | signature(64)
```

## セキュリティ考慮事項
- すべてのP2PメッセージにFodpr署名必須（送信者身元保証・改ざん検知）
- IPv6一時アドレスの定期ローテーション（プライバシー保護、RFC 4941）
- WoT紹介には紹介者の署名付与（シビル耐性）
- インビテーションコードは署名付き・有効期限付き・スコープ限定
- シードリレーはメタデータのみ取り扱い、内容は復号しない
- リプレイ攻撃防止：シーケンス番号 + タイムスタンプ
- キャッシュファイルは暗号化して保存（将来拡張）

## 開発・テストコマンド
```bash
# ビルド
nimble build -y

# テスト実行
nim c -r tests/test_f2f.nim

# プロトコルデモ（サーバー不要）
nim c -r examples/protocol_demo.nim

# クライアント（リレー必要）
nim c -r examples/fodpr_client.nim

# リンター/型チェック（設定後）
nimble lint
nimble typecheck
```

## 移行計画
1. **Phase 1**: protocol.nim に F2F 用 TransType/MsgType/データ構造 追加
2. **Phase 2**: f2f/ モジュール実装（peer_cache, discovery, bootstrap, wot, invitation, signaling, transport）
3. **Phase 3**: 既存クライアントを F2F 対応にリファクタリング
4. **Phase 4**: シードリレー実装・統合テスト
5. **Phase 5**: ドキュメント更新・サンプル追加

## 注意事項
- 既存の TransTypeWebRTC (6) / MsgTypeSignal (0x05/0x83) はシード/リレー経由の互換性維持のため**削除しない**
- 新規 F2F 通信は TransTypeF2FSignal (8) 以上を使用
- IPv6一時アドレスは OS のプライバシー拡張 (RFC 4941) を利用
- インビテーションコードは Bech32 形式 (`f2finv1...`) で共有
- リレーは「迷子を救うための非常口」としてのみ機能