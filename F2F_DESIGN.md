# F2F (Friend-to-Friend) / WoT (Web of Trust) 設計思想

## 概要

F2F は、Fodpr プロトコルにおける **友人ベースの P2P ネットワーク層** です。
「知り合い（信頼できるピア）を介して、さらにその知り合いへ接続していく」という
**Web of Trust（信頼の網）** を実装し、リレーサーバーへの依存を最小限にしながら
P2P 接続を連鎖的に確立することを目的としています。

---

## 核心設計原則

### 1. 信頼の連鎖
- **招待コード (`f2finv1...`)** または **リレーのシード機能** で最初の 1 人と接続
- 接続確立直後に **署名付き PeerList** を相互交換
- 受信した PeerList をローカルキャッシュにマージし、未接続のピアへ **自動ダイヤル**
- 最大 50 件まで連鎖的に P2P 接続を広げ、以降はリレーなしで通信可能

### 2. 自己署名による改ざん検知
- PeerList は送信者の秘密鍵で **ECDSA 署名** される
- 受信側は署名を検証し、正当なピアからのものだけを採用
- 中間者攻撃やキャッシュ汚染を防止

### 3. 信頼スコア (trustScore) による質の管理
- 各ピアに `0.0 ~ 1.0` のスコアを付与
- 接続成功で `+0.1`（上限 1.0）、失敗で `-0.15`（下限 0.05）
- スコア順で接続優先度を決定し、信頼できるピアから接続

### 4. 最大 50 件のキャッシュ上限
- `localStorage.fodpr_f2f_peer_cache` に永続化
- ブラウザを閉じても再起動時に復元可能
- 古い・スコアの低いピアから削除（LRU + スコア順）

### 5. WoT 紹介 (WoT Introduction)
- 信頼できるピアから `MsgTypeWoTIntroPush` で新ピアを紹介
- 紹介者の trustScore を継承（またはベーススコアで加算）
- 知り合いの知り合いを「紹介」として受け取れる

### 6. グループ管理 (ホスト-ゲスト星形)
- F2F 接続上でグループを作成 (`TransTypeGroup` でリレーに永続化)
- ホスト切断時は最古のゲストが自動昇格
- 端末を変えてもグループ状態を `TransTypeGroup` (`group:<groupId>`) で復元可能

---

## プロトコルフロー

```
┌─────────────┐     招待コード / シード      ┌─────────────┐
│   Alice     │ ──────────────────────────▶ │    Bob      │
│ (新規参入)  │  初回 1 対 1 接続確立        │ (既存ピア)  │
└─────────────┘                             └─────────────┘
        │                                           │
        │ P2P データチャネル確立                     │
        ▼                                           ▼
┌─────────────┐     PeerList 交換         ┌─────────────┐
│   Alice     │ ◀────────────────────────▶ │    Bob      │
│ (キャッシュ)│  (署名付き、最大 50 件)    │ (キャッシュ)│
└─────────────┘                             └─────────────┘
        │                                           │
        │ キャッシュマージ & 未接続ピアへ自動ダイヤル   │
        ▼                                           ▼
   ... 最大 50 接続まで連鎖的に拡大 ...
        │
        ▼
┌─────────────┐
│   Relay     │ 以降はリレー不要（P2P 直通）
│  不要       │
└─────────────┘
```

---

## データ構造

### PeerInfo (ピア情報)
```typescript
interface F2FPeerInfo {
  pubkey: string;        // 公開鍵 (HEX, 33 bytes compressed)
  addresses: string[];   // 接続アドレス (WebSocket URL, IPv6 一時アドレス等)
  lastSeen: number;      // 最後に見た時刻 (Unix秒)
  trustScore: number;    // 信頼スコア (0.0 ~ 1.0)
}
```

### PeerList (キャッシュ交換用)
- `TransTypePeerList` (0x09) / `MsgTypePeerListPush` (0x87)
- 構造: `version(8) | peerCount(2) | PeerInfo[] | signature(64)`
- 最大 50 件

### 招待コード (InvitationCode)
- Bech32: `f2finv1...`
- 構造: `version(1) | issuer(33) | targetPeer(PeerInfo) | expiresAt(8) | scope(1) | signature(64)`
- `scope`: 0 = 単発接続, 1 = WoT 招待 (キャッシュ共有含む)

---

## 実装箇所

| ファイル | 役割 |
|---------|------|
| `src/lib/fodprF2f.ts` | F2FManager / F2FPeerConnection (メイン実装) |
| `src/lib/rtcGroup.ts` | RtcGroupManager (ホスト昇格型 P2P、別仕様) |
| `src/lib/network.ts` | NetworkManager (3モード切替: f2f / rtcgroup / relay) |
| `src/App.tsx` (SettingsView) | 設定 UI: モード選択 / 招待コード発行・接続 / シード取得 |

---

## 運用上の考慮点

1. **初回ブートストラップ**
   - 完全新規ユーザーは招待コードをもらうか、リレーのシード取得 (`bootstrap()`) から開始
   - シード取得は信頼スコア 0.5 の候補を返すため、そこから接続を試みる

2. **NAT トラバーサル**
   - IPv6 一時アドレスや WebSocket URL を `addresses` に含める
   - STUN/TURN サーバーはクライアント側で設定可能

3. **オフライン耐性**
   - キャッシュは localStorage に永続化
   - 次回起動時にキャッシュから即座に自動ダイヤル開始

4. **プライバシー**
   - PeerList 交換は P2P データチャネル (暗号化済み) で行う
   - リレーを経由する場合も `to:` タグ + AUTH で宛先限定配信

5. **スパム/悪意あるピア対策**
   - trustScore 低下で接続優先度を下げ、最終的に切断
   - 署名検証で正当なピア以外の PeerList を拒否

---

## 今後の拡張余地

- **DHT ベースのピア発見** (現状は WoT のみ)
- **グループ内での PeerList 再配布** (ホストがメンバーに配布)
- **信頼スコアのオンチェーン/永続化** (より強固な評判システム)
- **モバイル端末向けの省電力モード** (接続数制限、バックグラウンド同期)

---

## 関連ドキュメント

- [Fodpr プロトコル仕様 (README.md)](../README.md)
- [Fodpr Relay 仕様 (README.md)](../FodprRelay/README.md)
- [TypeScript SDK API (README.md)](../FodprTSSDK/README.md)
- [Web Client 実装ガイド](../FodprWebClient/public/docs.html)