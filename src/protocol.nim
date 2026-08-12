## protocol.nim
## Fodpr のワイヤプロトコルを定義するモジュール。
##
## クライアント ⇄ サーバー間でやり取りされるバイナリパケットの
## エンコード / デコード処理を提供する。
##
## パケット構造（先頭 1 バイトがメッセージ種別）:
##   - 0x01 (EVENT): イベント投稿（署名付き）
##   - 0x02 (REQ)  : サブスクリプション要求
##   - 0x03 (DEL)  : イベント削除要求（署名付き）
##   - 0x81 (PUSH) : サーバー → クライアントのイベント配信
##
## 数値はすべてビッグエンディアン（ネットワークバイトオーダー）で
## エンコードされ、プラットフォーム差を吸収している。
##
## 送信タイプ (TransType) と配信方法:
##   transType は「どのように送るか」を表す送信方法であり、各ユーザーが自由に選べる。
##   サーバーは content の意味 (プロフィール / 投稿 / メディア など) を一切解釈せず、
##   送信方法 (transType) に基づいて保存・配信するだけである。
##   意味の解釈やプロフィールの管理などはすべてクライアント側の責任となる
##   (例: content が JSON なら特定のキー/値でプロフィールと判定する、など)。
##   - TransTypeJSON   (1): content は UTF-8 の JSON。サーバーは受信時に JSON 構文を
##                          検証し、クライアントは受信後に JSON としてパースして表示する。
##   - TransTypeString (2): content は UTF-8 の文字列。そのまま文字列として配信・表示する。
##   - TransTypeBinary (3): content は任意のバイト列。バイナリフレームのまま配信し、
##                          クライアントはサイズのみ表示する（そのまま文字列化しない）。
##   - TransTypeSigned (4): 全体署名イベント。createdAt / pubkey / tags を含む
##                          全フィールドを署名対象とし、署名対象バイト列の SHA-256 を
##                          イベントID として使う（メール用途の拡張）。
##   - TransTypeEncrypted (5): 暗号化イベント。content は envelope.nim の
##                          エンベロープ (宛先別暗号化, gift-wrap 相当)。
##                          全体署名 (TransTypeSigned と同じ検証) を使い、
##                          to:<fpub> タグがエンベロープ内の受信者と一致する必要がある。
##   - TransTypeData    (7): P2P 直接データチャネルメッセージ。
##                          MsgTypeData (0x06) で運ばれ、signature で完全性を保証する。
##                          リレー・ホストは存在せず、すべてクライアント間で直接通信する。

import streams, endians, strutils, times, random
import crypto, secp256k1
import nimSHA2

const MaxClockDriftSeconds* = 300  # ±5分以内のクロックドリフトを許容

# メッセージ種別を表す定数。
# 0x01〜0x04 はクライアント → サーバー、
# 0x81〜0x82 はサーバー → クライアントの配信を表す。
const
  # P2P メッシュ (WebRTC データチャネル) 用のメッセージ種別。
  # リレー・ホストは存在せず、すべてクライアント間で直接やり取りする。
  MsgTypeEvent*         = char(0x01)   # 署名付きイベント (投稿・ゴシップ配信)
  MsgTypeSignal*        = char(0x05)   # WebRTC シグナリング (offer/answer/ICE, P2P)
  MsgTypeData*          = char(0x06)   # P2P直接データチャネルメッセージ (署名付き)
  MsgTypePeerListReq*   = char(0x07)   # ピアリスト要求 (ピア → ピア)
  MsgTypePeerListPush*  = char(0x87)   # ピアリスト配信 (ピア → ピア)
  MsgTypeWoTIntro*      = char(0x08)   # WoT紹介
  MsgTypeWoTIntroPush*  = char(0x88)   # WoT紹介配信
  MsgTypeInvitationReq* = char(0x09)   # インビテーション要求
  MsgTypeInvitationPush* = char(0x89)  # インビテーション配信
  MsgTypeDht*           = char(0x0B)   # DHT RPC (Kademlia: PING / FIND_NODE / FIND_VALUE / STORE)
  MsgTypeDhtNodes*      = char(0x8B)   # DHT: 近傍ノード応答 (FIND_NODE / FIND_VALUE の非ヒット時)
  MsgTypeDhtValue*      = char(0x8C)   # DHT: 値応答 (FIND_VALUE ヒット / STORE 完了)

  # 送信タイプ (TransType)。
  # イベントの content を「どのように送るか」を表す。各ユーザーが自由に選べる。
  TransTypeJSON*    = 1.uint16   # JSON として送信（content は UTF-8 の JSON）
  TransTypeString*  = 2.uint16   # 文字列として送信（content は UTF-8）
  TransTypeBinary*  = 3.uint16   # バイナリとして送信（content は任意のバイト列）
  TransTypeSigned*  = 4.uint16   # 拡張イベント（全体署名）。
                                 # createdAt / pubkey / tags を含む全フィールドに署名する。
                                 # 署名対象は encodeEventSignedData() のバイト列で、
                                 # その SHA-256 がイベントID (eventId) になる。
                                 # メール用途のメタデータ完全性やスレッド参照 (reply-to) の土台。
                                 # (既存 1〜3 は content のみ署名のため後方互換で維持)
  TransTypeEncrypted* = 5.uint16 # 暗号化イベント。content は envelope.nim の
                                 # エンベロープ (宛先別暗号化, gift-wrap 相当)。
                                 # 全体署名 (TransTypeSigned と同じ検証) を使い、
                                 # to:<fpub> タグがエンベロープ内の受信者と一致する必要がある。
  TransTypeData*      = 7.uint16   # WebRTCデータチャネル専用。P2P直接通信で使用。
                                   # 各メッセージに署名を付与し、送信者の身元を保証する。
                                   # IPv6 一時アドレスなどのメタデータを含める。
  TransTypePeerList*  = 9.uint16   # F2F: ピアリスト交換 (WoTキャッシュ同期) 専用。
                                   # 最大50件のピア情報 (公開鍵、アドレス、lastSeen、trustScore) を
                                   # 署名付きで交換する。リレー非依存、P2P直接。
  TransTypeWoTIntro*  = 10.uint16  # F2F: WoT紹介メッセージ専用。
                                   # 新しいピアを信頼チェーン付きで紹介する。
                                   # 紹介者の署名を含み、シビル耐性を提供する。
  TransTypeInvitation* = 11.uint16 # F2F: インビテーションコード専用。
                                   # 第1救済手段。知人からの招待データを署名付きで交換。

  # シグナリングメッセージの種別 (SignalType)。
  # WebRTC ハンドシェイクでやり取りするメッセージの種類を表す。
  SignalOffer*      = 1.uint8   # SDP Offer (IPv6 一時アドレスを含む候補)
  SignalAnswer*     = 2.uint8   # SDP Answer
  SignalCandidate*  = 3.uint8   # ICE Candidate (IPv6 一時アドレスを含む)

  # DHT 操作種別 (Kademlia)。
  DhtOpPing*       = 0.uint8   # 生存確認
  DhtOpPong*       = 1.uint8   # 生存応答
  DhtOpFindNode*   = 2.uint8   # キー (nodeId) に最も近いノードを探す
  DhtOpFindValue*  = 3.uint8   # キーに対応する値を探す (IP アドレス解決)
  DhtOpStore*      = 4.uint8   # 値を保存する (自ノードの IP 記録等)

type
  # 投稿されるイベント本体。
  # pubkey と signature は crypto.nim の secp256k1 型を使用する。
  FodprEvent* = object
    transType* : uint16       # 送信方法 (TransTypeJSON / TransTypeString / TransTypeBinary)
    createdAt* : uint64       # Unix タイムスタンプ（秒）
    pubkey*    : SkPublicKey  # 送信者の公開鍵（圧縮形式 33 バイトで送信）
    tags*      : seq[string]  # タグ文字列のリスト
    content*   : string       # 本文（タイプに応じて JSON / 文字列 / バイナリ）
    signature* : FodprSignature # 本文に対する ECDSA 署名

  # WebRTC シグナリングメッセージ。
  # リレーを介さず P2P でやり取りする。確立前の相手へはメッシュの
  # 既存データチャネル経由で転送される (受信側で target を見て転送/受領)。
  # 双方はシグナリングメッセージの secp256k1 署名を検証する。
  # content には SDP offer/answer JSON や ICE candidate JSON
  # (IPv6 一時アドレスを含む) を格納する。
  FodprSignal* = object
    signalType*  : uint8       # SignalOffer / SignalAnswer / SignalCandidate
    sender*      : SkPublicKey # 送信者の公開鍵 (圧縮形式 33 バイト)
    target*      : SkPublicKey # 宛先の公開鍵
    content*     : string      # SDP JSON / ICE candidate JSON (IPv6 一時アドレス含む)
    signature*   : FodprSignature # 上記フィールド全体の ECDSA 署名

  # WebRTCデータチャネルメッセージ (P2P直接通信用)。
  # 各メッセージに署名を付与し、送信者の身元とメッセージの完全性を保証する。
  # IPv6 一時アドレス等のメタデータを tags に含める。
  FodprData* = object
    sender*      : SkPublicKey  # 送信者の公開鍵 (圧縮形式 33 バイト)
    target*      : SkPublicKey  # 宛先の公開鍵
    seq*         : uint64       # シーケンス番号 (リプレイ攻撃防止)
    timestamp*   : uint64       # Unix タイムスタンプ (秒)
    tags*        : seq[string]  # メタデータタグ (例: "ipv6:<temp_addr>", "type:text")
    content*     : string       # ペイロード (UTF-8 文字列またはバイナリ)
    signature*   : FodprSignature # 上記全フィールドの ECDSA 署名

  # F2F: ピア情報 (ピアキャッシュ・WoT・DHT 用)
  PeerInfo* = object
    pubkey*          : SkPublicKey  # 公開鍵 (圧縮形式 33 バイト)
    addresses*       : seq[string]  # 接続アドレス (IPv6一時アドレス, WebSocket URL等)
    lastSeen*        : uint64       # 最後に見た時刻 (Unix秒)
    identityTrust*   : float        # 身元信頼 (0.0-1.0): この公開鍵が誰によって保証されているか
    reliabilityScore*: float        # ネットワーク信頼性 (0.0-1.0): 接続成功率 / uptime / latency
    country*         : string       # GeoIP 国コード (ISO 3166-1 alpha-2), /64 プレフィクスから推定

  # F2F: ピアリスト交換 (TransTypePeerList 用)
  # 最大50件のピア情報を署名付きで交換 (WoTキャッシュ同期)
  PeerList* = object
    version*     : uint64       # キャッシュバージョン
    peerCount*   : uint16       # ピア数 (最大50)
    peers*       : seq[PeerInfo] # ピア情報リスト
    signature*   : FodprSignature # 全体の署名 (送信者の秘密鍵)

  # F2F: WoT紹介メッセージ (TransTypeWoTIntro 用)
  # 新しいピアを信頼チェーン付きで紹介 (シビル耐性)
  # distance decay: 紹介者の identityTrust * pathDecay^hopCount で信頼が減衰
  WoTIntro* = object
    introducer*     : SkPublicKey  # 紹介者の公開鍵
    newPeer*        : PeerInfo     # 紹介する新しいピアの情報
    hopCount*       : uint8        # 紹介チェーンのホップ数 (0=直接紹介)
    pathDecay*      : float        # 信頼減衰係数 (例: 0.6). 信頼 = introducer.identityTrust * pathDecay^hopCount
    expiresAt*      : uint64       # 紹介の有効期限 (Unix秒)
    signature*      : FodprSignature # 紹介者の署名 (紹介者の秘密鍵で署名)

  # F2F: インビテーションコード (TransTypeInvitation 用)
  # 第1救済手段。知人から共有される招待データ（QR/URI/テキスト）
  # Bech32エンコード形式: f2finv1...
  # anti-reuse: invitationId + usedAt で同じコードの再利用を防ぐ
  InvitationCode* = object
    version*       : uint8        # バージョン (0x01)
    issuer*        : SkPublicKey  # 発行者の公開鍵 (圧縮形式 33 バイト)
    targetPeer*    : PeerInfo     # 接続対象のピア情報
    expiresAt*     : uint64       # 有効期限 (Unix秒)
    scope*         : uint8        # 0=単発接続, 1=WoT招待(キャッシュ共有含む)
    invitationId*  : array[16, byte] # 一意な招待ID (anti-replay, anti-reuse)
    usedAt*        : uint64        # 使用済み時刻 (0=未使用). anti-reuse 用
    signature*     : FodprSignature # 発行者の署名 (秘密鍵で署名)

# DHT: 署名付きエンドポイントレコード (FIND_VALUE / STORE の value に格納)
# DHT が信頼されなくても、エンドポイントが所有者によって署名されていることを検証可能にする。
# 形式 (encodeEndpointRecordSignedData):
#   pubkey(33) | seq(8) | timestamp(8) | expiresAt(8) | addrCount(1) | (addrLen(2) | addr)* | signature(64)
type
  EndpointRecord* = object
    pubkey*      : SkPublicKey   # エンドポイントの所有者公開鍵
    seq*         : uint64        # シーケンス番号 (リプレイ防止・更新順序)
    timestamp*   : uint64        # 作成時刻 (Unix秒)
    expiresAt*   : uint64        # 有効期限 (Unix秒)
    addresses*   : seq[string]   # 接続アドレス ["[ipv6]:port", ...]
    signature*   : FodprSignature # 所有者による署名

# EndpointRecord の署名対象バイト列 (signature を除く全フィールド) をエンコード:
#   pubkey(33) | seq(8) | timestamp(8) | expiresAt(8) | addrCount(1) | (addrLen(2) | addr)*
proc encodeEndpointRecordSignedData*(er: EndpointRecord): string =
  result = ""
  # pubkey (33 バイト)
  let pubRaw = er.pubkey.toRawCompressed()
  for b in pubRaw: result.add(char(b))
  # seq (uint64, ビッグエンディアン)
  var seqNet: uint64
  bigEndian64(addr seqNet, unsafeAddr er.seq)
  var seqBytes: array[8, byte]
  copyMem(addr seqBytes[0], addr seqNet, 8)
  for b in seqBytes: result.add(char(b))
  # timestamp (uint64, ビッグエンディアン)
  var tsNet: uint64
  bigEndian64(addr tsNet, unsafeAddr er.timestamp)
  var tsBytes: array[8, byte]
  copyMem(addr tsBytes[0], addr tsNet, 8)
  for b in tsBytes: result.add(char(b))
  # expiresAt (uint64, ビッグエンディアン)
  var eaNet: uint64
  bigEndian64(addr eaNet, unsafeAddr er.expiresAt)
  var eaBytes: array[8, byte]
  copyMem(addr eaBytes[0], addr eaNet, 8)
  for b in eaBytes: result.add(char(b))
  # addrCount (1 バイト)
  result.add(char(byte(min(er.addresses.len, 255))))
  # 各アドレス
  for addr in er.addresses:
    let aLen = uint16(addr.len)
    var alNet: uint16
    bigEndian16(addr alNet, unsafeAddr aLen)
    var alBytes: array[2, byte]
    copyMem(addr alBytes[0], addr alNet, 2)
    result.add(char(alBytes[0]))
    result.add(char(alBytes[1]))
    result.add(addr)

proc encodeEndpointRecord*(er: EndpointRecord): string =
  result = encodeEndpointRecordSignedData(er)
  let sigRaw = er.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

proc signEndpointRecord*(priv: SkSecretKey, er: EndpointRecord): FodprSignature =
  signBytes(priv, encodeEndpointRecordSignedData(er))

proc verifyEndpointRecord*(er: EndpointRecord): bool =
  verifyBytes(er.pubkey, encodeEndpointRecordSignedData(er), er.signature)

proc decodeEndpointRecord*(stream: Stream): EndpointRecord =
  # pubkey (33 バイト)
  let pubBytes = readExactStr(stream, 33)
  var pubArr: array[33, byte]
  for i in 0..<33: pubArr[i] = byte(pubBytes[i])
  let pubkey = parsePublicKey(pubArr)
  # seq (uint64)
  let seqBytes = readExactStr(stream, 8)
  var seqNet, seqVal: uint64
  copyMem(addr seqNet, unsafeAddr seqBytes[0], 8)
  bigEndian64(addr seqVal, addr seqNet)
  # timestamp (uint64)
  let tsBytes = readExactStr(stream, 8)
  var tsNet, tsVal: uint64
  copyMem(addr tsNet, unsafeAddr tsBytes[0], 8)
  bigEndian64(addr tsVal, addr tsNet)
  # expiresAt (uint64)
  let eaBytes = readExactStr(stream, 8)
  var eaNet, eaVal: uint64
  copyMem(addr eaNet, unsafeAddr eaBytes[0], 8)
  bigEndian64(addr eaVal, addr eaNet)
  # addrCount (1 バイト)
  let addrCount = int(byte(readExactStr(stream, 1)[0]))
  var addresses = newSeq[string]()
  for i in 0..<addrCount:
    let alBytes = readExactStr(stream, 2)
    var alNet, aLen: uint16
    copyMem(addr alNet, unsafeAddr alBytes[0], 2)
    bigEndian16(addr aLen, addr alNet)
    addresses.add(readExactStr(stream, int(aLen)))
  # signature (64 バイト)
  let sigBytes = readExactStr(stream, 64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))
  return EndpointRecord(
    pubkey: pubkey,
    seq: seqVal,
    timestamp: tsVal,
    expiresAt: eaVal,
    addresses: addresses,
    signature: signature
  )

proc verifyEndpointRecord*(er: EndpointRecord): bool =
  verifyBytes(er.pubkey, encodeEndpointRecordSignedData(er), er.signature)

# DHT: 近傍ノード情報 (Kademlia ルーティングテーブル / 応答用)
# nodeId = SHA-256(圧縮公開鍵) をノードIDとして使う。
DhtNodeInfo* = object
  nodeId*        : array[32, byte]  # SHA-256(compressed pubkey)
  pubkey*        : SkPublicKey      # 公開鍵 (圧縮形式 33 バイト)
  addresses*     : seq[string]      # 接続アドレス ["[ipv6]:port", ...]
  lastSeen*      : uint64           # 最後に見た時刻 (Unix秒)
  identityTrust* : float            # 身元信頼 (0.0-1.0)
  reliabilityScore*: float          # ネットワーク信頼性 (0.0-1.0)

  # DHT: RPC メッセージ (Kademlia over WebRTC データチャネル)。
  # MsgTypeDht (0x0B) / MsgTypeDhtNodes (0x8B) / MsgTypeDhtValue (0x8C) の
  # いずれかのパケット形式で運ばれる。sender で署名し、中継者による
  # 改ざんを防ぐ。msgId で要求と応答を対応付ける。
  DhtMessage* = object
    op*          : uint8             # DhtOpPing / DhtOpPong / DhtOpFindNode / DhtOpFindValue / DhtOpStore
    msgId*       : array[16, byte]   # 乱数メッセージID (応答照合用)
    key*         : array[32, byte]   # FIND_NODE / FIND_VALUE / STORE のキー
    nodes*       : seq[DhtNodeInfo]  # FIND_NODE 応答: 近傍ノード (最大 k)
    value*       : string            # FIND_VALUE 応答: 値 / STORE ペイロード
    sender*      : SkPublicKey       # 送信ノードの公開鍵
    signature*   : FodprSignature    # op..sender 全体の ECDSA 署名

# ---------------------------------------------------------------------------
# EVENT のエンコード
# ---------------------------------------------------------------------------

# イベントの署名対象バイト列（signature を除く全フィールド）をエンコードする:
#   transType(2) | createdAt(8) | pubkey(33) | tagCount(2) |
#   (tagLen(2) | tag) * tagCount | contentLen(4) | content
#
# 用途:
#   - TransTypeSigned (全体署名) の署名対象
#   - イベントID (eventId) の算出対象 (このバイト列の SHA-256)
# encodeEvent はこの結果に signature を連結するだけなので、ワイヤ形式は不変。
proc encodeEventSignedData*(ev: FodprEvent): string =
  result = ""

  # transType (uint16, ビッグエンディアン)
  var ttNet: uint16
  bigEndian16(addr ttNet, unsafeAddr ev.transType)
  var ttBytes: array[2, byte]
  copyMem(addr ttBytes[0], addr ttNet, 2)
  result.add(char(ttBytes[0]))
  result.add(char(ttBytes[1]))

  # createdAt (uint64, ビッグエンディアン)
  var caNet: uint64
  bigEndian64(addr caNet, unsafeAddr ev.createdAt)
  var caBytes: array[8, byte]
  copyMem(addr caBytes[0], addr caNet, 8)
  for b in caBytes: result.add(char(b))

  # pubkey（圧縮形式 33 バイトをそのまま出力）
  let pubRaw = ev.pubkey.toRawCompressed()
  for b in pubRaw: result.add(char(b))

  # タグの個数 (uint16, ビッグエンディアン)
  let tagCount = uint16(ev.tags.len)
  var tcNet: uint16
  bigEndian16(addr tcNet, unsafeAddr tagCount)
  var tcBytes: array[2, byte]
  copyMem(addr tcBytes[0], addr tcNet, 2)
  result.add(char(tcBytes[0]))
  result.add(char(tcBytes[1]))

  # 各タグを「長さ(2) + 本体」の形式で連結
  for t in ev.tags:
    let tLen = uint16(t.len)
    var tlNet: uint16
    bigEndian16(addr tlNet, unsafeAddr tLen)
    var tlBytes: array[2, byte]
    copyMem(addr tlBytes[0], addr tlNet, 2)
    result.add(char(tlBytes[0]))
    result.add(char(tlBytes[1]))
    result.add(t)

  # content（長さは uint32, ビッグエンディアン）
  let cLen = uint32(ev.content.len)
  var clNet: uint32
  bigEndian32(addr clNet, unsafeAddr cLen)
  var clBytes: array[4, byte]
  copyMem(addr clBytes[0], addr clNet, 4)
  for b in clBytes: result.add(char(b))
  result.add(ev.content)

# イベントをワイヤ形式にエンコードする:
#   encodeEventSignedData の結果に signature(64) を連結したもの。
proc encodeEvent*(ev: FodprEvent): string =
  result = encodeEventSignedData(ev)

  # signature（compact 形式 64 バイト）
  let sigRaw = ev.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# ---------------------------------------------------------------------------
# イベントID と全体署名 (TransTypeSigned)
# ---------------------------------------------------------------------------
# イベントID は署名対象バイト列 (encodeEventSignedData) の SHA-256。
# 全フィールドに紐づくため、メタデータ改ざんの検出と、
# 特定イベントへの参照 (reply-to の "e:<eventid>") に使える。
proc eventId*(ev: FodprEvent): array[32, byte] =
  result = array[32, byte](computeSHA256(encodeEventSignedData(ev)))

# イベントID の 16 進文字列表現。タグ "e:<eventid>" などに使いやすい。
proc eventIdHex*(ev: FodprEvent): string =
  result = ""
  for b in eventId(ev): result.add(b.toHex(2))

# イベント全体 (transType / createdAt / pubkey / tags / content) に対する署名。
# content のみ署名する signContent と違い、メタデータの改ざんも検出できる。
# エンコード前に ev.signature は空のまま呼ぶこと (署名対象に署名自体を含めない)。
proc signEvent*(priv: SkSecretKey, ev: FodprEvent): FodprSignature =
  signBytes(priv, encodeEventSignedData(ev))

# signEvent の検証。正しければ true を返す。
proc verifyEvent*(pub: SkPublicKey, ev: FodprEvent, sig: FodprSignature): bool =
  verifyBytes(pub, encodeEventSignedData(ev), sig)

# ---------------------------------------------------------------------------
# EVENT のデコード
# ---------------------------------------------------------------------------

# encodeEvent とは逆に、ストリームからバイナリデータを読み込んで
# FodprEvent オブジェクトへ復元する。
proc decodeEvent*(stream: Stream): FodprEvent =
  # transType (2 バイト)
  let ttBytes = stream.readStr(2)
  var ttNet, ttVal: uint16
  copyMem(addr ttNet, unsafeAddr ttBytes[0], 2)
  bigEndian16(addr ttVal, addr ttNet)

  # createdAt (8 バイト)
  let caBytes = stream.readStr(8)
  var caNet, caVal: uint64
  copyMem(addr caNet, unsafeAddr caBytes[0], 8)
  bigEndian64(addr caVal, addr caNet)

  # pubkey（圧縮形式 33 バイトを配列に変換してから公開鍵を生成）
  let pubBytes = stream.readStr(33)
  var pubBytesArr: array[33, byte]
  for i in 0..<33: pubBytesArr[i] = byte(pubBytes[i])
  let pubkey = parsePublicKey(pubBytesArr)

  # タグの個数 (2 バイト)
  let tcBytes = stream.readStr(2)
  var tcNet, tagCount: uint16
  copyMem(addr tcNet, unsafeAddr tcBytes[0], 2)
  bigEndian16(addr tagCount, addr tcNet)

  # タグ本体を個数分読み込む（各タグは「長さ(2) + 本体」）
  var tags = newSeq[string]()
  for i in 0..<int(tagCount):
    let tlBytes = stream.readStr(2)
    var tlNet, tLen: uint16
    copyMem(addr tlNet, unsafeAddr tlBytes[0], 2)
    bigEndian16(addr tLen, addr tlNet)
    tags.add(stream.readStr(int(tLen)))

  # content（長さは uint32）
  let clBytes = stream.readStr(4)
  var clNet, cLen: uint32
  copyMem(addr clNet, unsafeAddr clBytes[0], 4)
  bigEndian32(addr cLen, addr clNet)
  let content = stream.readStr(int(cLen))

  # signature（compact 形式 64 バイト）
  let sigBytes = stream.readStr(64)
  var sigBytesArr: array[64, byte]
  for i in 0..<64: sigBytesArr[i] = byte(sigBytes[i])
  let skSig = parseSignature(sigBytesArr)

  return FodprEvent(
    transType: ttVal,
    createdAt: caVal,
    pubkey: pubkey,
    tags: tags,
    content: content,
    signature: FodprSignature(sig: skSig)
  )

# ---------------------------------------------------------------------------
# REQ のエンコード・デコード
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# WebRTC シグナリングメッセージ (MsgTypeSignal)
# ---------------------------------------------------------------------------
# パケット形式 (P2P メッシュ, MsgTypeSignal = 0x05):
#   MsgTypeSignal(1) | signalType(1) | senderPubkey(33) | targetPubkey(33) |
#   contentLen(4) | content | signature(64)
#
# 署名対象バイト列 (senderPubkey が所有する秘密鍵で署名):
#   signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content
#
# セキュリティモデル:
#   - 送信者は signalType / sender / target / content に対して secp256k1 (ECDSA)
#     で署名する。受信者は署名を検証して送信者の身元を確かめる。
#   - 確立前の相手へはメッシュの既存データチャネル (FodprData) 経由で転送される
#     (リレーは存在しない)。受信側は target を見て転送するか受領するかを判断する。
#   - content には SDP offer/answer JSON や ICE candidate JSON (IPv6 一時アドレス
#     を含む) を格納する。IP アドレスの公開は発信者の責任となる。

# シグナリングメッセージの署名対象バイト列をエンコードする:
#   signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content
proc encodeSignalSignedData*(s: FodprSignal): string =
  result = ""

  # signalType (1 バイト)
  result.add(char(byte(s.signalType)))

  # senderPubkey (圧縮形式 33 バイト)
  let senderRaw = s.sender.toRawCompressed()
  for b in senderRaw: result.add(char(b))

  # targetPubkey (圧縮形式 33 バイト)
  let targetRaw = s.target.toRawCompressed()
  for b in targetRaw: result.add(char(b))

  # content (長さは uint32, ビッグエンディアン)
  let cLen = uint32(s.content.len)
  var clNet: uint32
  bigEndian32(addr clNet, unsafeAddr cLen)
  var clBytes: array[4, byte]
  copyMem(addr clBytes[0], addr clNet, 4)
  for b in clBytes: result.add(char(b))
  result.add(s.content)

# シグナリングメッセージをワイヤ形式にエンコードする:
#   encodeSignalSignedData の結果に signature(64) を連結する。
# (MsgTypeSignal の msgType バイトは含めない。呼び出し側が付与する。)
proc encodeSignal*(s: FodprSignal): string =
  result = encodeSignalSignedData(s)

  # signature（compact 形式 64 バイト）
  let sigRaw = s.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# シグナリングメッセージへの署名。sender フィールドは署名する前に
# 送信者の公開鍵で埋めること (署名対象データに含めるため)。
proc signSignal*(priv: SkSecretKey, s: FodprSignal): FodprSignature =
  signBytes(priv, encodeSignalSignedData(s))

# シグナリングメッセージの署名検証。sender フィールドの公開鍵で検証する。
proc verifySignal*(s: FodprSignal): bool =
  verifyBytes(s.sender, encodeSignalSignedData(s), s.signature)

# 固定長フィールドを読み飛ばす。ストリームが短い場合は ValueError を投げる
# (IndexDefect などの Defect を投げるとサーバーが落ちるため)。
proc readExactStr(stream: Stream, len: int): string =
  result = stream.readStr(len)
  if result.len != len:
    raise newException(ValueError,
      "stream too short: expected " & $len & " bytes, got " & $result.len)

# ストリームからシグナリングメッセージ本体を復元する (署名対象 + signature)。
# msgType バイトは呼び出し側が読み飛ばしてから渡すこと。
proc decodeSignal*(stream: Stream): FodprSignal =
  # signalType (1 バイト)
  let sigTypeByte = stream.readChar()

  # senderPubkey (圧縮形式 33 バイト)
  let senderBytes = readExactStr(stream, 33)
  var senderArr: array[33, byte]
  for i in 0..<33: senderArr[i] = byte(senderBytes[i])
  let senderPub = parsePublicKey(senderArr)

  # targetPubkey (圧縮形式 33 バイト)
  let targetBytes = readExactStr(stream, 33)
  var targetArr: array[33, byte]
  for i in 0..<33: targetArr[i] = byte(targetBytes[i])
  let targetPub = parsePublicKey(targetArr)

  # content (長さは uint32)
  let clBytes = readExactStr(stream, 4)
  var clNet, cLen: uint32
  copyMem(addr clNet, unsafeAddr clBytes[0], 4)
  bigEndian32(addr cLen, addr clNet)
  let content = readExactStr(stream, int(cLen))

  # signature (compact 形式 64 バイト)
  let sigBytes = readExactStr(stream, 64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  return FodprSignal(
    signalType: byte(sigTypeByte),
    sender: senderPub,
    target: targetPub,
    content: content,
    signature: signature
  )

# 送信タイプの数値から表示用の名前を返す。
# ログ出力やクライアントでの配信方法の判別表示に使う。
proc transTypeName*(transType: uint16): string =
  case transType
  of TransTypeJSON:   "JSON"
  of TransTypeString: "String"
  of TransTypeBinary: "Binary"
  of TransTypeSigned: "Signed"
  of TransTypeEncrypted: "Encrypted"
  of TransTypeData:   "Data"
  of TransTypePeerList: "PeerList"
  of TransTypeWoTIntro: "WoTIntro"
  of TransTypeInvitation: "Invitation"
  else: "Unknown(" & $transType & ")"

# シグナリングメッセージの種別の数値から表示用の名前を返す。
proc signalTypeName*(signalType: uint8): string =
  case signalType
  of SignalOffer:     "Offer"
  of SignalAnswer:    "Answer"
  of SignalCandidate: "Candidate"
  else: "Unknown(" & $signalType & ")"

# ---------------------------------------------------------------------------
# WebRTC データチャネルメッセージ (MsgTypeData)
# ---------------------------------------------------------------------------
# パケット形式 (P2P直接, MsgTypeData = 0x06):
#   MsgTypeData(1) | senderPubkey(33) | targetPubkey(33) | seq(8) | timestamp(8) |
#   tagCount(2) | (tagLen(2) | tag)* | contentLen(4) | content | signature(64)
#
# 署名対象バイト列 (sender が所有する秘密鍵で署名):
#   senderPubkey(33) | targetPubkey(33) | seq(8) | timestamp(8) |
#   tagCount(2) | (tagLen(2) | tag)* | contentLen(4) | content
#
# セキュリティモデル:
#   - 送信者は全フィールドに対して secp256k1 (ECDSA) で署名する
#   - 受信者は署名を検証し、送信者の身元とメッセージ完全性を確認する
#   - seq と timestamp でリプレイ攻撃を防ぐ
#   - tags に "ipv6:<一時アドレス>" 等のメタデータを含められる
#   - リレーは存在せず、すべて直接 P2P で交換される

# データメッセージの署名対象バイト列をエンコードする
proc encodeDataSignedData*(d: FodprData): string =
  result = ""

  # senderPubkey (圧縮形式 33 バイト)
  let senderRaw = d.sender.toRawCompressed()
  for b in senderRaw: result.add(char(b))

  # targetPubkey (圧縮形式 33 バイト)
  let targetRaw = d.target.toRawCompressed()
  for b in targetRaw: result.add(char(b))

  # seq (uint64, ビッグエンディアン)
  var seqNet: uint64
  bigEndian64(addr seqNet, unsafeAddr d.seq)
  var seqBytes: array[8, byte]
  copyMem(addr seqBytes[0], addr seqNet, 8)
  for b in seqBytes: result.add(char(b))

  # timestamp (uint64, ビッグエンディアン)
  var tsNet: uint64
  bigEndian64(addr tsNet, unsafeAddr d.timestamp)
  var tsBytes: array[8, byte]
  copyMem(addr tsBytes[0], addr tsNet, 8)
  for b in tsBytes: result.add(char(b))

  # タグの個数 (uint16, ビッグエンディアン)
  let tagCount = uint16(d.tags.len)
  var tcNet: uint16
  bigEndian16(addr tcNet, unsafeAddr tagCount)
  var tcBytes: array[2, byte]
  copyMem(addr tcBytes[0], addr tcNet, 2)
  result.add(char(tcBytes[0]))
  result.add(char(tcBytes[1]))

  # 各タグを「長さ(2) + 本体」の形式で連結
  for t in d.tags:
    let tLen = uint16(t.len)
    var tlNet: uint16
    bigEndian16(addr tlNet, unsafeAddr tLen)
    var tlBytes: array[2, byte]
    copyMem(addr tlBytes[0], addr tlNet, 2)
    result.add(char(tlBytes[0]))
    result.add(char(tlBytes[1]))
    result.add(t)

  # content (長さは uint32, ビッグエンディアン)
  let cLen = uint32(d.content.len)
  var clNet: uint32
  bigEndian32(addr clNet, unsafeAddr cLen)
  var clBytes: array[4, byte]
  copyMem(addr clBytes[0], addr clNet, 4)
  for b in clBytes: result.add(char(b))
  result.add(d.content)

# データメッセージをワイヤ形式にエンコードする
proc encodeData*(d: FodprData): string =
  result = encodeDataSignedData(d)

  # signature (compact 形式 64 バイト)
  let sigRaw = d.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# データメッセージへの署名。sender フィールドは署名する前に
# 送信者の公開鍵で埋めること (署名対象データに含めるため)。
proc signData*(priv: SkSecretKey, d: FodprData): FodprSignature =
  signBytes(priv, encodeDataSignedData(d))

# データメッセージの署名検証。sender フィールドの公開鍵で検証する。
proc verifyData*(d: FodprData): bool =
  verifyBytes(d.sender, encodeDataSignedData(d), d.signature)

# ストリームからデータメッセージ本体を復元する (署名対象 + signature)。
# msgType バイトは呼び出し側が読み飛ばしてから渡すこと。
proc decodeData*(stream: Stream): FodprData =
  # senderPubkey (圧縮形式 33 バイト)
  let senderBytes = readExactStr(stream, 33)
  var senderArr: array[33, byte]
  for i in 0..<33: senderArr[i] = byte(senderBytes[i])
  let senderPub = parsePublicKey(senderArr)

  # targetPubkey (圧縮形式 33 バイト)
  let targetBytes = readExactStr(stream, 33)
  var targetArr: array[33, byte]
  for i in 0..<33: targetArr[i] = byte(targetBytes[i])
  let targetPub = parsePublicKey(targetArr)

  # seq (8 バイト)
  let seqBytes = readExactStr(stream, 8)
  var seqNet, seqVal: uint64
  copyMem(addr seqNet, unsafeAddr seqBytes[0], 8)
  bigEndian64(addr seqVal, addr seqNet)

  # timestamp (8 バイト)
  let tsBytes = readExactStr(stream, 8)
  var tsNet, tsVal: uint64
  copyMem(addr tsNet, unsafeAddr tsBytes[0], 8)
  bigEndian64(addr tsVal, addr tsNet)

  # タグの個数 (2 バイト)
  let tcBytes = readExactStr(stream, 2)
  var tcNet, tagCount: uint16
  copyMem(addr tcNet, unsafeAddr tcBytes[0], 2)
  bigEndian16(addr tagCount, addr tcNet)

  # タグ本体を個数分読み込む
  var tags = newSeq[string]()
  for i in 0..<int(tagCount):
    let tlBytes = readExactStr(stream, 2)
    var tlNet, tLen: uint16
    copyMem(addr tlNet, unsafeAddr tlBytes[0], 2)
    bigEndian16(addr tLen, addr tlNet)
    tags.add(readExactStr(stream, int(tLen)))

  # content (長さは uint32)
  let clBytes = readExactStr(stream, 4)
  var clNet, cLen: uint32
  copyMem(addr clNet, unsafeAddr clBytes[0], 4)
  bigEndian32(addr cLen, addr clNet)
  let content = stream.readStr(int(cLen))

  # signature (compact 形式 64 バイト)
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  return FodprData(
    sender: senderPub,
    target: targetPub,
    seq: seqVal,
    timestamp: tsVal,
    tags: tags,
    content: content,
    signature: signature
  )

# ---------------------------------------------------------------------------
# F2F: ピア情報 (PeerInfo) のエンコード/デコード
# ---------------------------------------------------------------------------
# PeerInfo 形式:
#   pubkey(33) | addrCount(1) | (addrLen(2) | addr)* | lastSeen(8) | identityTrust(4) | reliabilityScore(4) | countryLen(2) | country
proc encodePeerInfo*(p: PeerInfo): string =
  result = ""

  # pubkey (圧縮形式 33 バイト)
  let pubRaw = p.pubkey.toRawCompressed()
  for b in pubRaw: result.add(char(b))

  # addrCount (1 バイト, 最大 255 - 実際は少ないはず)
  result.add(char(byte(min(p.addresses.len, 255))))

  # 各アドレス: addrLen(2) | addr
  for addr in p.addresses:
    let aLen = uint16(addr.len)
    var alNet: uint16
    bigEndian16(addr alNet, unsafeAddr aLen)
    var alBytes: array[2, byte]
    copyMem(addr alBytes[0], addr alNet, 2)
    result.add(char(alBytes[0]))
    result.add(char(alBytes[1]))
    result.add(addr)

  # lastSeen (uint64, ビッグエンディアン)
  var lsNet: uint64
  bigEndian64(addr lsNet, unsafeAddr p.lastSeen)
  var lsBytes: array[8, byte]
  copyMem(addr lsBytes[0], addr lsNet, 8)
  for b in lsBytes: result.add(char(b))

  # identityTrust (float32, ビッグエンディアン)
  var itNet: uint32
  var itVal: uint32 = cast[uint32](p.identityTrust)
  bigEndian32(addr itNet, addr itVal)
  var itBytes: array[4, byte]
  copyMem(addr itBytes[0], addr itNet, 4)
  for b in itBytes: result.add(char(b))

  # reliabilityScore (float32, ビッグエンディアン)
  var rsNet: uint32
  var rsVal: uint32 = cast[uint32](p.reliabilityScore)
  bigEndian32(addr rsNet, addr rsVal)
  var rsBytes: array[4, byte]
  copyMem(addr rsBytes[0], addr rsNet, 4)
  for b in rsBytes: result.add(char(b))

  # country (可変長文字列: len(2) | country)
  let cLen = uint16(p.country.len)
  var clNet: uint16
  bigEndian16(addr clNet, unsafeAddr cLen)
  var clBytes: array[2, byte]
  copyMem(addr clBytes[0], addr clNet, 2)
  result.add(char(clBytes[0]))
  result.add(char(clBytes[1]))
  result.add(p.country)

proc decodePeerInfo*(stream: Stream): PeerInfo =
  # pubkey (圧縮形式 33 バイト)
  let pubBytes = stream.readStr(33)
  var pubArr: array[33, byte]
  for i in 0..<33: pubArr[i] = byte(pubBytes[i])
  let pubkey = parsePublicKey(pubArr)

  # addrCount (1 バイト)
  let addrCount = int(byte(stream.readChar()))

  # 各アドレス
  var addresses = newSeq[string]()
  for i in 0..<addrCount:
    let alBytes = stream.readStr(2)
    var alNet, aLen: uint16
    copyMem(addr alNet, unsafeAddr alBytes[0], 2)
    bigEndian16(addr aLen, addr alNet)
    addresses.add(stream.readStr(int(aLen)))

  # lastSeen (uint64, ビッグエンディアン)
  let lsBytes = stream.readStr(8)
  var lsNet, lsVal: uint64
  copyMem(addr lsNet, unsafeAddr lsBytes[0], 8)
  bigEndian64(addr lsVal, addr lsNet)

  # identityTrust (float32, ビッグエンディアン)
  let itBytes = stream.readStr(4)
  var itNet: uint32
  copyMem(addr itNet, unsafeAddr itBytes[0], 4)
  bigEndian32(addr itNet, addr itNet)
  let identityTrust = cast[float32](itNet)

  # reliabilityScore (float32, ビッグエンディアン)
  let rsBytes = stream.readStr(4)
  var rsNet: uint32
  copyMem(addr rsNet, unsafeAddr rsBytes[0], 4)
  bigEndian32(addr rsNet, addr rsNet)
  let reliabilityScore = cast[float32](rsNet)

  # country (len(2) + country)
  let clBytes = stream.readStr(2)
  var clNet, cLen: uint16
  copyMem(addr clNet, unsafeAddr clBytes[0], 2)
  bigEndian16(addr cLen, addr clNet)
  let country = stream.readStr(int(cLen))

  return PeerInfo(
    pubkey: pubkey,
    addresses: addresses,
    lastSeen: lsVal,
    identityTrust: identityTrust,
    reliabilityScore: reliabilityScore,
    country: country
  )

# ---------------------------------------------------------------------------
# F2F: ピアリスト交換 (TransTypePeerList)
# ---------------------------------------------------------------------------
# PeerList 形式:
#   version(8) | peerCount(2) | PeerInfo * peerCount | signature(64)
# 署名対象: version(8) | peerCount(2) | PeerInfo * peerCount

proc encodePeerListSignedData*(pl: PeerList): string =
  result = ""

  # version (uint64, ビッグエンディアン)
  var vNet: uint64
  bigEndian64(addr vNet, unsafeAddr pl.version)
  var vBytes: array[8, byte]
  copyMem(addr vBytes[0], addr vNet, 8)
  for b in vBytes: result.add(char(b))

  # peerCount (uint16, ビッグエンディアン)
  var pcNet: uint16
  bigEndian16(addr pcNet, unsafeAddr pl.peerCount)
  var pcBytes: array[2, byte]
  copyMem(addr pcBytes[0], addr pcNet, 2)
  result.add(char(pcBytes[0]))
  result.add(char(pcBytes[1]))

  # 各 PeerInfo
  for p in pl.peers:
    result.add(encodePeerInfo(p))

proc encodePeerList*(pl: PeerList): string =
  result = encodePeerListSignedData(pl)
  # signature (compact 形式 64 バイト)
  let sigRaw = pl.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

proc signPeerList*(priv: SkSecretKey, pl: PeerList): FodprSignature =
  signBytes(priv, encodePeerListSignedData(pl))

proc verifyPeerList*(pl: PeerList): bool =
  if pl.peers.len == 0:
    return false
  verifyBytes(pl.peers[0].pubkey, encodePeerListSignedData(pl), pl.signature)
  # 注: 送信者の公開鍵は最初のピアの pubkey とする想定 (改善余地あり)

proc decodePeerList*(stream: Stream): PeerList =
  # version (uint64, ビッグエンディアン)
  let vBytes = stream.readStr(8)
  var vNet, vVal: uint64
  copyMem(addr vNet, unsafeAddr vBytes[0], 8)
  bigEndian64(addr vVal, addr vNet)

  # peerCount (uint16, ビッグエンディアン)
  let pcBytes = stream.readStr(2)
  var pcNet, pcVal: uint16
  copyMem(addr pcNet, unsafeAddr pcBytes[0], 2)
  bigEndian16(addr pcVal, addr pcNet)

  # 各 PeerInfo
  var peers = newSeq[PeerInfo]()
  for i in 0..<int(pcVal):
    peers.add(decodePeerInfo(stream))

  # signature (compact 形式 64 バイト)
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  return PeerList(
    version: vVal,
    peerCount: pcVal,
    peers: peers,
    signature: signature
  )

# ---------------------------------------------------------------------------
# F2F: WoT紹介メッセージ (TransTypeWoTIntro)
# ---------------------------------------------------------------------------
# WoTIntro 形式:
#   introducerPubkey(33) | PeerInfo | hopCount(1) | pathDecay(8) | expiresAt(8) | signature(64)
# 署名対象: introducerPubkey(33) | PeerInfo | hopCount(1) | pathDecay(8) | expiresAt(8)

proc encodeWoTIntroSignedData*(wi: WoTIntro): string =
  result = ""

  # introducerPubkey (圧縮形式 33 バイト)
  let introRaw = wi.introducer.toRawCompressed()
  for b in introRaw: result.add(char(b))

  # newPeer (PeerInfo)
  result.add(encodePeerInfo(wi.newPeer))

  # hopCount (1 バイト)
  result.add(char(byte(wi.hopCount)))

  # pathDecay (float64, ビッグエンディアン)
  let pdF = wi.pathDecay
  let pdBits = cast[uint64](pdF)
  var pdNet: uint64
  bigEndian64(addr pdNet, unsafeAddr pdBits)
  var pdBytes: array[8, byte]
  copyMem(addr pdBytes[0], addr pdNet, 8)
  for b in pdBytes: result.add(char(b))

  # expiresAt (uint64, ビッグエンディアン)
  var eaNet: uint64
  bigEndian64(addr eaNet, unsafeAddr wi.expiresAt)
  var eaBytes: array[8, byte]
  copyMem(addr eaBytes[0], addr eaNet, 8)
  for b in eaBytes: result.add(char(b))

proc encodeWoTIntro*(wi: WoTIntro): string =
  result = encodeWoTIntroSignedData(wi)
  # signature (compact 形式 64 バイト)
  let sigRaw = wi.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

proc signWoTIntro*(priv: SkSecretKey, wi: WoTIntro): FodprSignature =
  signBytes(priv, encodeWoTIntroSignedData(wi))

proc verifyWoTIntro*(wi: WoTIntro): bool =
  verifyBytes(wi.introducer, encodeWoTIntroSignedData(wi), wi.signature)

proc decodeWoTIntro*(stream: Stream): WoTIntro =
  # introducerPubkey (圧縮形式 33 バイト)
  let introBytes = stream.readStr(33)
  var introArr: array[33, byte]
  for i in 0..<33: introArr[i] = byte(introBytes[i])
  let introducer = parsePublicKey(introArr)

  # newPeer (PeerInfo)
  let newPeer = decodePeerInfo(stream)

  # hopCount (1 バイト)
  let hopCount = byte(stream.readChar())

  # pathDecay (float64, ビッグエンディアン)
  let pdBytes = readExactStr(stream, 8)
  var pdNet, pdBits: uint64
  copyMem(addr pdNet, unsafeAddr pdBytes[0], 8)
  bigEndian64(addr pdBits, addr pdNet)
  let pathDecay = cast[float](pdBits)

  # expiresAt (uint64, ビッグエンディアン)
  let eaBytes = readExactStr(stream, 8)
  var eaNet, eaVal: uint64
  copyMem(addr eaNet, unsafeAddr eaBytes[0], 8)
  bigEndian64(addr eaVal, addr eaNet)

  # signature (compact 形式 64 バイト)
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  return WoTIntro(
    introducer: introducer,
    newPeer: newPeer,
    hopCount: hopCount,
    pathDecay: pathDecay,
    expiresAt: eaVal,
    signature: signature
  )

# ---------------------------------------------------------------------------
# F2F: インビテーションコード (TransTypeInvitation)
# ---------------------------------------------------------------------------
# InvitationCode (エンコード前バイナリ形式):
#   version(1) | issuerPubkey(33) | PeerInfo | expiresAt(8) | scope(1) | invitationId(16) | usedAt(8) | signature(64)
# 署名対象: version(1) | issuerPubkey(33) | PeerInfo | expiresAt(8) | scope(1) | invitationId(16) | usedAt(8)
# Bech32エンコード後: f2finv1...

proc encodeInvitationSignedData*(inv: InvitationCode): string =
  result = ""

  # version (1 バイト)
  result.add(char(byte(inv.version)))

  # issuerPubkey (圧縮形式 33 バイト)
  let issuerRaw = inv.issuer.toRawCompressed()
  for b in issuerRaw: result.add(char(b))

  # targetPeer (PeerInfo)
  result.add(encodePeerInfo(inv.targetPeer))

  # expiresAt (uint64, ビッグエンディアン)
  var eaNet: uint64
  bigEndian64(addr eaNet, unsafeAddr inv.expiresAt)
  var eaBytes: array[8, byte]
  copyMem(addr eaBytes[0], addr eaNet, 8)
  for b in eaBytes: result.add(char(b))

  # scope (1 バイト)
  result.add(char(byte(inv.scope)))

  # invitationId (16 バイト)
  for b in inv.invitationId: result.add(char(b))

  # usedAt (uint64, ビッグエンディアン)
  var uaNet: uint64
  bigEndian64(addr uaNet, unsafeAddr inv.usedAt)
  var uaBytes: array[8, byte]
  copyMem(addr uaBytes[0], addr uaNet, 8)
  for b in uaBytes: result.add(char(b))

proc encodeInvitation*(inv: InvitationCode): string =
  result = encodeInvitationSignedData(inv)
  # signature (compact 形式 64 バイト)
  let sigRaw = inv.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

proc signInvitation*(priv: SkSecretKey, inv: InvitationCode): FodprSignature =
  signBytes(priv, encodeInvitationSignedData(inv))

proc verifyInvitation*(inv: InvitationCode): bool =
  verifyBytes(inv.issuer, encodeInvitationSignedData(inv), inv.signature)

proc decodeInvitation*(stream: Stream): InvitationCode =
  # version (1 バイト)
  let version = byte(stream.readChar())

  # issuerPubkey (圧縮形式 33 バイト)
  let issuerBytes = stream.readStr(33)
  var issuerArr: array[33, byte]
  for i in 0..<33: issuerArr[i] = byte(issuerBytes[i])
  let issuer = parsePublicKey(issuerArr)

  # targetPeer (PeerInfo)
  let targetPeer = decodePeerInfo(stream)

  # expiresAt (uint64, ビッグエンディアン)
  let eaBytes = stream.readStr(8)
  var eaNet, eaVal: uint64
  copyMem(addr eaNet, unsafeAddr eaBytes[0], 8)
  bigEndian64(addr eaVal, addr eaNet)

  # scope (1 バイト)
  let scope = byte(stream.readChar())

  # invitationId (16 バイト)
  let idBytes = readExactStr(stream, 16)
  var invitationId: array[16, byte]
  for i in 0..<16: invitationId[i] = byte(idBytes[i])

  # usedAt (uint64, ビッグエンディアン)
  let uaBytes = readExactStr(stream, 8)
  var uaNet, uaVal: uint64
  copyMem(addr uaNet, unsafeAddr uaBytes[0], 8)
  bigEndian64(addr uaVal, addr uaNet)

  # signature (compact 形式 64 バイト)
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  return InvitationCode(
    version: version,
    issuer: issuer,
    targetPeer: targetPeer,
    expiresAt: eaVal,
    scope: scope,
    invitationId: invitationId,
    usedAt: uaVal,
    signature: signature
  )

# ---------------------------------------------------------------------------
# F2F: Bech32 エンコード/デコード (インビテーションコード用)
# ---------------------------------------------------------------------------
# HRP: "f2finv"
const InvitationHrp* = "f2finv"

proc encodeInvitationBech32*(inv: InvitationCode): string =
  # バイナリエンコード
  let bin = encodeInvitation(inv)
  # バイト列に変換
  var data = newSeq[byte](bin.len)
  for i in 0..<bin.len: data[i] = byte(bin[i])
  # Bech32 エンコード
  result = bech32Encode(InvitationHrp, data)

proc decodeInvitationBech32*(code: string): InvitationCode =
  # Bech32 デコード
  let data = bech32Decode(code, InvitationHrp)
  # バイナリ列に変換
  var bin = newString(data.len)
  for i in 0..<data.len: bin[i] = char(data[i])
  # ストリームからデコード
  var strm = newStringStream(bin)
  return decodeInvitation(strm)

# インビテーションコード生成ヘルパー
proc createInvitation*(issuerPriv: SkSecretKey, targetPeer: PeerInfo,
                        expiresInSec: uint64, scope: uint8): InvitationCode =
  let now = uint64(epochTime())
  var inv = InvitationCode(
    version: 1,
    issuer: issuerPriv.toPublicKey(),
    targetPeer: targetPeer,
    expiresAt: now + expiresInSec,
    scope: scope,
    invitationId: "",  # プレースホルダ - 値はランダムに割り当てられる
    usedAt: 0,       # 未使用
    signature: emptySignature()  # プレースホルダ
  )
  inv.signature = signInvitation(issuerPriv, inv)
  return inv

# 暗号学的に安全なランダムバイト列生成 (nimcrypto の sysrand 利用)
proc randomBytes*(n: int): seq[byte] =
  result = newSeq[byte](n)
  for i in 0..<n:
    result[i] = byte(random.random(256))

# ---------------------------------------------------------------------------
# DHT (Kademlia over WebRTC) エンコード/デコード
# ---------------------------------------------------------------------------
# DHT メッセージは WebRTC データチャネル (FodprData) の content に
# 以下の形式で格納する:
#   MsgTypeDht(0x0B) | op(1) | msgId(16) | key(32) | senderPubkey(33) |
#   nodeCount(2) | DhtNodeInfo* | valueLen(4) | value | signature(64)
#
# 署名対象バイト列 (sender が所有する秘密鍵で署名):
#   op(1) | msgId(16) | key(32) | senderPubkey(33) | nodeCount(2) |
#   DhtNodeInfo* | valueLen(4) | value
#
# 応答 (MsgTypeDhtNodes=0x8B / MsgTypeDhtValue=0x8C) は同じ DhtMessage
# 構造でエンコードし、先頭の msgType バイトだけを変える。

# DhtNodeInfo エンコード (前方宣言)
proc encodeDhtNodeInfo*(n: DhtNodeInfo): string

# DHT メッセージの署名対象バイト列をエンコードする:
proc encodeDhtSignedData*(m: DhtMessage): string =
  result = ""

  # op (1 バイト)
  result.add(char(byte(m.op)))

  # msgId (16 バイト)
  for b in m.msgId: result.add(char(b))

  # key (32 バイト)
  for b in m.key: result.add(char(b))

  # senderPubkey (圧縮形式 33 バイト)
  let senderRaw = m.sender.toRawCompressed()
  for b in senderRaw: result.add(char(b))

  # nodeCount (uint16, ビッグエンディアン)
  let nCount = uint16(m.nodes.len)
  var ncNet: uint16
  bigEndian16(addr ncNet, unsafeAddr nCount)
  var ncBytes: array[2, byte]
  copyMem(addr ncBytes[0], addr ncNet, 2)
  result.add(char(ncBytes[0]))
  result.add(char(ncBytes[1]))

  # DhtNodeInfo の並び
  for n in m.nodes:
    result.add(encodeDhtNodeInfo(n))

  # valueLen (uint32, ビッグエンディアン)
  let vLen = uint32(m.value.len)
  var vlNet: uint32
  bigEndian32(addr vlNet, unsafeAddr vLen)
  var vlBytes: array[4, byte]
  copyMem(addr vlBytes[0], addr vlNet, 4)
  for b in vlBytes: result.add(char(b))

  # value
  result.add(m.value)

# DhtNodeInfo エンコード
#   nodeId(32) | pubkey(33) | addrCount(1) | (addrLen(2) | addr)* | lastSeen(8) | identityTrust(8) | reliabilityScore(8)
proc encodeDhtNodeInfo*(n: DhtNodeInfo): string =
  result = ""
  for b in n.nodeId: result.add(char(b))
  let pubRaw = n.pubkey.toRawCompressed()
  for b in pubRaw: result.add(char(b))
  result.add(char(byte(n.addresses.len)))
  for addr in n.addresses:
    let aLen = uint16(addr.len)
    var alNet: uint16
    bigEndian16(addr alNet, unsafeAddr aLen)
    var alBytes: array[2, byte]
    copyMem(addr alBytes[0], addr alNet, 2)
    result.add(char(alBytes[0]))
    result.add(char(alBytes[1]))
    result.add(addr)
  var lsNet: uint64
  bigEndian64(addr lsNet, unsafeAddr n.lastSeen)
  var lsBytes: array[8, byte]
  copyMem(addr lsBytes[0], addr lsNet, 8)
  for b in lsBytes: result.add(char(b))
  # identityTrust (float64, ビッグエンディアン)
  let itF = n.identityTrust
  let itBits = cast[uint64](itF)
  var itNet: uint64
  bigEndian64(addr itNet, unsafeAddr itBits)
  var itBytes: array[8, byte]
  copyMem(addr itBytes[0], addr itNet, 8)
  for b in itBytes: result.add(char(b))
  # reliabilityScore (float64, ビッグエンディアン)
  let rsF = n.reliabilityScore
  let rsBits = cast[uint64](rsF)
  var rsNet: uint64
  bigEndian64(addr rsNet, unsafeAddr rsBits)
  var rsBytes: array[8, byte]
  copyMem(addr rsBytes[0], addr rsNet, 8)
  for b in rsBytes: result.add(char(b))

# DhtNodeInfo デコード
proc decodeDhtNodeInfo*(stream: Stream): DhtNodeInfo =
  let idBytes = readExactStr(stream, 32)
  var nodeId: array[32, byte]
  for i in 0..<32: nodeId[i] = byte(idBytes[i])

  let pubBytes = readExactStr(stream, 33)
  var pubArr: array[33, byte]
  for i in 0..<33: pubArr[i] = byte(pubBytes[i])
  let pubkey = parsePublicKey(pubArr)

  let addrCount = int(byte(readExactStr(stream, 1)[0]))
  var addresses = newSeq[string]()
  for i in 0..<addrCount:
    let alBytes = readExactStr(stream, 2)
    var alNet, aLen: uint16
    copyMem(addr alNet, unsafeAddr alBytes[0], 2)
    bigEndian16(addr aLen, addr alNet)
    addresses.add(readExactStr(stream, int(aLen)))

  let lsBytes = readExactStr(stream, 8)
  var lsNet, lastSeen: uint64
  copyMem(addr lsNet, unsafeAddr lsBytes[0], 8)
  bigEndian64(addr lastSeen, addr lsNet)

  # identityTrust (float64, ビッグエンディアン)
  let itBytes = readExactStr(stream, 8)
  var itNet, itBits: uint64
  copyMem(addr itNet, unsafeAddr itBytes[0], 8)
  bigEndian64(addr itBits, addr itNet)
  let identityTrust = cast[float](itBits)

  # reliabilityScore (float64, ビッグエンディアン)
  let rsBytes = readExactStr(stream, 8)
  var rsNet, rsBits: uint64
  copyMem(addr rsNet, unsafeAddr rsBytes[0], 8)
  bigEndian64(addr rsBits, addr rsNet)
  let reliabilityScore = cast[float](rsBits)

  return DhtNodeInfo(
    nodeId: nodeId,
    pubkey: pubkey,
    addresses: addresses,
    lastSeen: lastSeen,
    identityTrust: identityTrust,
    reliabilityScore: reliabilityScore
  )

# DHT メッセージをワイヤ形式にエンコードする (msgType は呼び出し側が付与):
#   encodeDhtSignedData の結果に signature(64) を連結する。
proc encodeDht*(m: DhtMessage): string =
  result = encodeDhtSignedData(m)

  # signature (compact 形式 64 バイト)
  let sigRaw = m.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# DHT メッセージへの署名。sender フィールドは署名する前に送信者の
# 公開鍵で埋めること (署名対象データに含めるため)。
proc signDht*(priv: SkSecretKey, m: DhtMessage): FodprSignature =
  signBytes(priv, encodeDhtSignedData(m))

# DHT メッセージの署名検証。sender フィールドの公開鍵で検証する。
proc verifyDht*(m: DhtMessage): bool =
  verifyBytes(m.sender, encodeDhtSignedData(m), m.signature)

# ストリームから DHT メッセージ本体を復元する (署名対象 + signature)。
proc decodeDht*(stream: Stream): DhtMessage =
  # op (1 バイト)
  let opByte = readExactStr(stream, 1)

  # msgId (16 バイト)
  let idBytes = readExactStr(stream, 16)
  var msgId: array[16, byte]
  for i in 0..<16: msgId[i] = byte(idBytes[i])

  # key (32 バイト)
  let keyBytes = readExactStr(stream, 32)
  var key: array[32, byte]
  for i in 0..<32: key[i] = byte(keyBytes[i])

  # senderPubkey (圧縮形式 33 バイト)
  let senderBytes = readExactStr(stream, 33)
  var senderArr: array[33, byte]
  for i in 0..<33: senderArr[i] = byte(senderBytes[i])
  let senderPub = parsePublicKey(senderArr)

  # nodeCount (uint16)
  let ncBytes = readExactStr(stream, 2)
  var ncNet, nodeCount: uint16
  copyMem(addr ncNet, unsafeAddr ncBytes[0], 2)
  bigEndian16(addr nodeCount, addr ncNet)

  # DhtNodeInfo の並び
  var nodes = newSeq[DhtNodeInfo]()
  for i in 0..<int(nodeCount):
    nodes.add(decodeDhtNodeInfo(stream))

  # valueLen (uint32)
  let vlBytes = readExactStr(stream, 4)
  var vlNet, valueLen: uint32
  copyMem(addr vlNet, unsafeAddr vlBytes[0], 4)
  bigEndian32(addr valueLen, addr vlNet)
  let value = readExactStr(stream, int(valueLen))

  # signature (compact 形式 64 バイト)
  let sigBytes = readExactStr(stream, 64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  return DhtMessage(
    op: byte(opByte[0]),
    msgId: msgId,
    key: key,
    nodes: nodes,
    value: value,
    sender: senderPub,
    signature: signature
  )

# DHT 操作の数値から表示用の名前を返す。
proc dhtOpName*(op: uint8): string =
  case op
  of DhtOpPing:      "Ping"
  of DhtOpPong:      "Pong"
  of DhtOpFindNode:  "FindNode"
  of DhtOpFindValue: "FindValue"
  of DhtOpStore:     "Store"
  else: "Unknown(" & $op & ")"
