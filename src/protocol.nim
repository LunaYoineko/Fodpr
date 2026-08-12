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
  ##   - TransTypeAll    (0): イベント側では使用しない。REQ でのみ「すべての送信方法を
  ##                          購読する」ことを表す。
##   - TransTypeSigned (4): 全体署名イベント。createdAt / pubkey / tags を含む
##                          全フィールドを署名対象とし、署名対象バイト列の SHA-256 を
##                          イベントID として使う（メール用途の拡張）。
##   - TransTypeEncrypted (5): 暗号化イベント。content は envelope.nim の
##                          エンベロープ (宛先別暗号化, gift-wrap 相当)。
##                          全体署名 (TransTypeSigned と同じ検証) を使い、
##                          to:<fpub> タグがエンベロープ内の受信者と一致する必要がある。
##                          サーバーは構造のみ検証し、内容は復号しない。
##   - TransTypeWebRTC (6): WebRTC シグナリング専用。
##                          クライアントがこのタイプでシグナリング要求 (REQ) を送ると、
##                          リレーはイベントの保存・永続化を行わず、純粋なシグナリング
##                          サーバーとして動作する (シグナリングメッセージは破棄される)。
##                          P2P 確立後、双方は WebRTC データチャネルで直接通信し、
##                          リレーはその後関与しない。
##                          シグナリングには MsgTypeSignal (0x05) / MsgTypeSignalPush (0x83)
##                          を使用し、content には SDP offer/answer や ICE candidate
##                          (IPv6 一時アドレスを含む) を JSON 等で格納する。

import streams, endians, strutils, times
import crypto, secp256k1
import nimSHA2

# メッセージ種別を表す定数。
# 0x01〜0x04 はクライアント → サーバー、
# 0x81〜0x82 はサーバー → クライアントの配信を表す。
const
  MsgTypeEvent* = char(0x01)   # イベント投稿
  MsgTypeReq*   = char(0x02)   # 購読要求
  MsgTypeDel*   = char(0x03)   # イベント削除要求 (クライアント → サーバー)
  MsgTypeAuth*  = char(0x04)   # 認証応答 (クライアント → サーバー, NIP-42 相当)
  MsgTypeSignal*     = char(0x05)   # シグナリングメッセージ (クライアント → サーバー, WebRTC 専用)
  MsgTypePush*  = char(0x81)   # イベント配信
  MsgTypeChallenge* = char(0x82) # 認証チャレンジ (サーバー → クライアント)
  MsgTypeSignalPush* = char(0x83) # シグナリング配信 (サーバー → クライアント, WebRTC 専用)
  MsgTypeData*       = char(0x06)   # WebRTCデータチャネルメッセージ (P2P直接, 署名付き)
  MsgTypeDataPush*   = char(0x84)   # WebRTCデータ配信 (リレー経由の場合)
  MsgTypePeerListReq*  = char(0x07) # F2F: ピアリスト要求 (クライアント → ピア)
  MsgTypePeerListPush* = char(0x87) # F2F: ピアリスト配信 (ピア → クライアント)
  MsgTypeWoTIntro*     = char(0x08) # F2F: WoT紹介 (クライアント → ピア)
  MsgTypeWoTIntroPush* = char(0x88) # F2F: WoT紹介配信 (ピア → クライアント)
  MsgTypeInvitationReq* = char(0x09) # F2F: インビテーション要求 (クライアント → ピア)
  MsgTypeInvitationPush* = char(0x89) # F2F: インビテーション配信 (ピア → クライアント)
  MsgTypeGroupReq*      = char(0x0A) # F2F: グループ管理要求 (クライアント → ピア/ホスト)
  MsgTypeGroupPush*     = char(0x8A) # F2F: グループ管理配信 (ホスト/ピア → クライアント)
  
  # 送信タイプ (TransType)。
  # イベントの content を「どのように送るか」を表す。各ユーザーが自由に選べる。
  TransTypeAll*    = 0.uint16   # すべての送信方法（REQ でのみ使用）
  TransTypeJSON*   = 1.uint16   # JSON として送信（content は UTF-8 の JSON）
  TransTypeString* = 2.uint16   # 文字列として送信（content は UTF-8）
  TransTypeBinary* = 3.uint16   # バイナリとして送信（content は任意のバイト列）
  TransTypeSigned* = 4.uint16   # 拡張イベント（全体署名）。
                                # createdAt / pubkey / tags を含む全フィールドに署名する。
                                # 署名対象は encodeEventSignedData() のバイト列で、
                                # その SHA-256 がイベントID (eventId) になる。
                                # メール用途のメタデータ完全性やスレッド参照 (reply-to) の土台。
                                # (既存 1〜3 は content のみ署名のため後方互換で維持)
  TransTypeEncrypted* = 5.uint16 # 暗号化イベント。content は envelope.nim の
                                 # エンベロープ (宛先別暗号化, gift-wrap 相当)。
                                 # 全体署名 (TransTypeSigned と同じ検証) を使い、
                                 # to:<fpub> タグがエンベロープ内の受信者と一致する必要がある。
                                 # サーバーは構造のみ検証し、内容は復号しない。
  TransTypeWebRTC*  = 6.uint16   # WebRTC シグナリング専用。リレーはシグナリングサーバーに徹し、
                                 # イベントは保存せず MsgTypeSignal で即時中継する。
                                 # content には SDP offer/answer や ICE candidate
                                 # (IPv6 一時アドレスを含む) を格納する。
                                 # 全体署名 (TransTypeSigned と同じ検証) を必須とする。
# 双方の P2P 接続確立後、リレーは関与しない。
  TransTypeData*      = 7.uint16   # WebRTCデータチャネル専用。P2P直接通信で使用。
                                   # 各メッセージに署名を付与し、送信者の身元を保証する。
                                   # IPv6 一時アドレスなどのメタデータを含める。
  TransTypeF2FSignal*  = 8.uint16   # F2F: P2P直接シグナリング専用。
                                   # リレーを介さず、確立済みP2Pデータチャネル経由でシグナリングを行う。
                                   # content には SDP offer/answer JSON や ICE candidate
                                   # (IPv6 一時アドレスを含む) を格納する。
                                   # 全体署名 (TransTypeSigned と同じ検証) を必須とする。
  TransTypePeerList*   = 9.uint16   # F2F: ピアリスト交換 (WoTキャッシュ同期) 専用。
                                    # 最大50件のピア情報 (公開鍵、アドレス、lastSeen、trustScore) を
                                    # 署名付きで交換する。リレー非依存、P2P直接。
  TransTypeWoTIntro*  = 10.uint16  # F2F: WoT紹介メッセージ専用。
                                    # 新しいピアを信頼チェーン付きで紹介する。
                                    # 紹介者の署名を含み、シビル耐性を提供する。
  TransTypeInvitation* = 11.uint16 # F2F: インビテーションコード専用。
                                    # 第1救済手段。知人からの招待データを署名付きで交換。
  TransTypeGroup*      = 12.uint16 # F2F: グループ管理専用。
                                    # ホスト-ゲスト星形トポロジの管理、ホスト昇格等。

  # シグナリングメッセージの種別 (SignalType)。
  # WebRTC ハンドシェイクでやり取りするメッセージの種類を表す。
  SignalOffer*      = 1.uint8   # SDP Offer (IPv6 一時アドレスを含む候補)
  SignalAnswer*     = 2.uint8   # SDP Answer
  SignalCandidate*  = 3.uint8   # ICE Candidate (IPv6 一時アドレスを含む)
  SignalHostChange* = 4.uint8   # ホスト変更通知
                                  # content は JSON: {"newHost":"<fpub>", "groupId":"<groupId>"}
  SignalGroupJoin*  = 5.uint8   # グループ参加要求
                                  # content は JSON: {"groupId":"<groupId>"}
  SignalGroupLeave* = 6.uint8   # グループ脱退通知
                                  # content は JSON: {"groupId":"<groupId>"}

  # 削除要求 (DEL) の削除対象タイプ。
  DelTargetPubkey* = 0.uint8   # 公開鍵単位で削除 (その送信者のイベントを全削除)
  DelTargetEvent*  = 1.uint8   # 特定イベントを削除 (createdAt + contentハッシュで特定)
  DelTargetEventId* = 2.uint8  # 特定イベントを削除 (eventId で特定。全体署名イベント推奨)

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

  # 購読 (REQ) 要求。
  # transType が TransTypeAll(0) の場合はすべての送信方法を購読する。
  # tagKey/tagVal でタグの絞り込みも可能
  # (例: tagKey="pubkey" で公開鍵を指定)。
  FodprReq* = object
    subId*     : string   # 購読を識別するための ID
    transType* : uint16   # 購読したい送信方法
    tagKey*    : string   # 絞り込み対象のタグキー
    tagVal*    : string   # 絞り込み対象のタグ値

  # 削除 (DEL) 要求。
  # 送信者本人だけが自分のイベントを削除できるよう、要求全体に署名を付ける。
  # サーバーは署名を検証し、削除対象イベントの公開鍵が要求の公開鍵と
  # 一致するものだけを削除する。
  FodprDelReq* = object
    transType*  : uint16            # 削除対象の送信タイプ (TransTypeAll=0 は全タイプ)
    targetType* : uint8             # DelTargetPubkey / DelTargetEvent / DelTargetEventId
    pubkey*     : SkPublicKey       # 削除対象イベントの公開鍵 (要求の署名鍵でもある)
    createdAt*  : uint64            # DelTargetEvent のときのみ有効
    contentHash*: array[32, byte]   # DelTargetEvent のときのみ有効 (content の SHA-256)
    eventId*    : array[32, byte]   # DelTargetEventId のときのみ有効 (イベントID)
    signature*  : FodprSignature    # 上記フィールド全体に対する署名

  # 認証応答 (AUTH)。NIP-42 相当の読取認証。
  # サーバーから送られたチャレンジ nonce に署名して返す。
  # 署名対象バイト列: nonce(32) | pubkey(33)
  FodprAuth* = object
    nonce*     : array[32, byte]    # サーバーから受け取ったチャレンジ nonce
    pubkey*    : SkPublicKey        # 認証する公開鍵
    signature* : FodprSignature     # nonce(32) | pubkey(33) に対する署名

  # WebRTC シグナリングメッセージ (TransTypeWebRTC 用)。
  # リレーは content を解釈せず、署名検証後に宛先 (target) の認証済み購読者へ
  # 即座に中継する (保存はしない)。
  # 双方はシグナリングメッセージの secp256k1 署名を検証し、
  # P2P 接続確立後は直接 WebRTC データチャネルで通信する。
  # content には SDP offer/answer JSON や ICE candidate JSON
  # (IPv6 一時アドレスを含む) を格納する。
  FodprSignal* = object
    signalType*  : uint8       # SignalOffer / SignalAnswer / SignalCandidate
    sender*      : SkPublicKey # 送信者の公開鍵 (圧縮形式 33 バイト)
    target*      : SkPublicKey # 宛先の公開鍵 (認証済み subscriber の fpub と一致)
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

  # F2F: P2P直接シグナリングメッセージ (TransTypeF2FSignal 用)。
  # リレーを介さず、確立済みP2Pデータチャネル経由で直接シグナリングを行う。
  # 既存の FodprSignal (TransTypeWebRTC) はシード/リレー経由用として残す。
  # 双方はシグナリングメッセージの secp256k1 署名を検証する。
  F2FSignal* = object
    signalType*  : uint8       # SignalOffer / SignalAnswer / SignalCandidate
    sender*      : SkPublicKey # 送信者の公開鍵 (圧縮形式 33 バイト)
    target*      : SkPublicKey # 宛先の公開鍵
    content*     : string      # SDP JSON / ICE candidate JSON (IPv6 一時アドレス含む)
    signature*   : FodprSignature # 上記フィールド全体の ECDSA 署名
    viaRelay*    : bool        # false = 直接P2P, true = リレー経由 (互換用)

  # F2F: ピア情報 (ピアキャッシュ・WoT用)
  PeerInfo* = object
    pubkey*      : SkPublicKey  # 公開鍵 (圧縮形式 33 バイト)
    addresses*   : seq[string]  # 接続アドレス (IPv6一時アドレス, WebSocket URL等)
    lastSeen*    : uint64       # 最後に見た時刻 (Unix秒)
    trustScore*  : float        # 信頼スコア (0.0-1.0)

  # F2F: ピアリスト交換 (TransTypePeerList 用)
  # 最大50件のピア情報を署名付きで交換 (WoTキャッシュ同期)
  PeerList* = object
    version*     : uint64       # キャッシュバージョン
    peerCount*   : uint16       # ピア数 (最大50)
    peers*       : seq[PeerInfo] # ピア情報リスト
    signature*   : FodprSignature # 全体の署名 (送信者の秘密鍵)

  # F2F: WoT紹介メッセージ (TransTypeWoTIntro 用)
  # 新しいピアを信頼チェーン付きで紹介 (シビル耐性)
  WoTIntro* = object
    introducer*  : SkPublicKey  # 紹介者の公開鍵
    newPeer*     : PeerInfo     # 紹介する新しいピアの情報
    signature*   : FodprSignature # 紹介者の署名 (紹介者の秘密鍵で署名)

  # F2F: インビテーションコード (TransTypeInvitation 用)
  # 第1救済手段。知人から共有される招待データ（QR/URI/テキスト）
  # Bech32エンコード形式: f2finv1...
  InvitationCode* = object
    version*     : uint8        # バージョン (0x01)
    issuer*      : SkPublicKey  # 発行者の公開鍵 (圧縮形式 33 バイト)
    targetPeer*  : PeerInfo     # 接続対象のピア情報
    expiresAt*   : uint64       # 有効期限 (Unix秒)
    scope*       : uint8        # 0=単発接続, 1=WoT招待(キャッシュ共有含む)
    signature*   : FodprSignature # 発行者の署名 (秘密鍵で署名)

  # F2F: グループメンバー情報
  GroupMember* = object
    pubkey*      : SkPublicKey  # メンバーの公開鍵
    addresses*   : seq[string]  # 接続アドレス
    joinedAt*    : uint64       # 参加時刻 (Unix秒)
    isHost*      : bool         # ホストかどうか
    isConnected* : bool         # 現在接続中かどうか

  # F2F: グループ情報 (ホスト-ゲスト星形トポロジ)
  # TransTypeGroup (12) で使用
  F2FGroup* = object
    groupId*      : string       # グループID (ホストのfpubを使用)
    hostPubkey*   : SkPublicKey  # 現在のホストの公開鍵
    members*      : seq[GroupMember] # メンバーリスト
    version*      : uint64       # グループバージョン
    createdAt*    : uint64       # 作成時刻
    signature*    : FodprSignature # ホストの署名

  # F2F: グループ参加要求 (SignalGroupJoin 用)
  GroupJoinReq* = object
    groupId*     : string       # 参加したいグループID
    member*      : GroupMember  # 参加するメンバー情報
    signature*   : FodprSignature # 参加者の署名

  # F2F: グループ脱退通知 (SignalGroupLeave 用)
  GroupLeaveReq* = object
    groupId*     : string       # 脱退するグループID
    memberPubkey*: SkPublicKey  # 脱退するメンバーの公開鍵
    signature*   : FodprSignature # 脱退者の署名

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

# 購読要求を以下のバイナリ形式にエンコードする:
#   MsgTypeReq(1) | subIdLen(2) | subId | transType(2) |
#   tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
proc encodeReq*(r: FodprReq): string =
  result = ""
  result.add(MsgTypeReq)  # 先頭にメッセージ種別を付与

  # subId（長さは uint16）
  let idLen = uint16(r.subId.len)
  var idNet: uint16
  bigEndian16(addr idNet, unsafeAddr idLen)
  var idBytes: array[2, byte]
  copyMem(addr idBytes[0], addr idNet, 2)
  result.add(char(idBytes[0]))
  result.add(char(idBytes[1]))
  result.add(r.subId)

  # transType (uint16, ビッグエンディアン)
  var ttNet: uint16
  bigEndian16(addr ttNet, unsafeAddr r.transType)
  var ttBytes: array[2, byte]
  copyMem(addr ttBytes[0], addr ttNet, 2)
  result.add(char(ttBytes[0]))
  result.add(char(ttBytes[1]))

  # tagKey（長さは uint16）
  let tkLen = uint16(r.tagKey.len)
  var tkNet: uint16
  bigEndian16(addr tkNet, unsafeAddr tkLen)
  var tkBytes: array[2, byte]
  copyMem(addr tkBytes[0], addr tkNet, 2)
  result.add(char(tkBytes[0]))
  result.add(char(tkBytes[1]))
  result.add(r.tagKey)

  # tagVal（長さは uint16）
  let tvLen = uint16(r.tagVal.len)
  var tvNet: uint16
  bigEndian16(addr tvNet, unsafeAddr tvLen)
  var tvBytes: array[2, byte]
  copyMem(addr tvBytes[0], addr tvNet, 2)
  result.add(char(tvBytes[0]))
  result.add(char(tvBytes[1]))
  result.add(r.tagVal)

# encodeReq とは逆に、ストリームから購読要求を復元する。
proc decodeReq*(stream: Stream): FodprReq =
  # subId（長さは uint16）
  let idLenBytes = stream.readStr(2)
  var idNet, idLen: uint16
  copyMem(addr idNet, unsafeAddr idLenBytes[0], 2)
  bigEndian16(addr idLen, addr idNet)
  let subId = stream.readStr(int(idLen))

  # transType (uint16)
  let ttBytes = stream.readStr(2)
  var ttNet, ttVal: uint16
  copyMem(addr ttNet, unsafeAddr ttBytes[0], 2)
  bigEndian16(addr ttVal, addr ttNet)

  # tagKey（長さは uint16）
  let tkLenBytes = stream.readStr(2)
  var tkNet, tkLen: uint16
  copyMem(addr tkNet, unsafeAddr tkLenBytes[0], 2)
  bigEndian16(addr tkLen, addr tkNet)
  let tagKey = stream.readStr(int(tkLen))

  # tagVal（長さは uint16）
  let tvLenBytes = stream.readStr(2)
  var tvNet, tvLen: uint16
  copyMem(addr tvNet, unsafeAddr tvLenBytes[0], 2)
  bigEndian16(addr tvLen, addr tvNet)
  let tagVal = stream.readStr(int(tvLen))

  return FodprReq(subId: subId, transType: ttVal, tagKey: tagKey, tagVal: tagVal)

# ---------------------------------------------------------------------------
# DEL (イベント削除) のエンコード・デコード
# ---------------------------------------------------------------------------
# パケット形式 (クライアント → サーバー):
#   msgType(1) | transType(2) | targetType(1) | pubkey(33) |
#   [createdAt(8) | contentHash(32)]  ← DelTargetEvent の場合
#   [eventId(32)]                     ← DelTargetEventId の場合
#   | signature(64)
#
# 署名対象 (transType 以降、signature を除いたバイト列):
#   transType(2) | targetType(1) | pubkey(33) | 上記の識別子部分
# 署名は送信者本人の秘密鍵で行い、サーバーは要求内の pubkey で検証する。
# これにより「自分の投稿だけを自分が消せる」ことを保証する。
#
# targetType による削除対象の違い:
#   DelTargetPubkey(0)  : その pubkey のイベントを transType 単位で全削除
#   DelTargetEvent(1)   : createdAt と contentHash が一致する特定イベントを削除
#   DelTargetEventId(2) : eventId が一致する特定イベントを削除。
#                         (eventId は署名対象バイト列全体の SHA-256 なので、
#                          TransTypeSigned のメタデータ改ざん耐性に適合する)

# 署名対象のバイト列を作成する。クライアント側とサーバー側で
# バイト列を完全に一致させる必要がある。
proc encodeDelSignedData*(req: FodprDelReq): string =
  # transType(2) | targetType(1) | pubkey(33) | [識別子部分]
  var ttNet: uint16
  bigEndian16(addr ttNet, unsafeAddr req.transType)
  var ttBytes: array[2, byte]
  copyMem(addr ttBytes[0], addr ttNet, 2)
  result.add(char(ttBytes[0]))
  result.add(char(ttBytes[1]))
  result.add(char(req.targetType))
  let pubRaw = req.pubkey.toRawCompressed()
  for b in pubRaw: result.add(char(b))
  if req.targetType == DelTargetEvent:
    var caNet: uint64
    bigEndian64(addr caNet, unsafeAddr req.createdAt)
    var caBytes: array[8, byte]
    copyMem(addr caBytes[0], addr caNet, 8)
    for b in caBytes: result.add(char(b))
    for b in req.contentHash: result.add(char(b))
  elif req.targetType == DelTargetEventId:
    for b in req.eventId: result.add(char(b))

# 削除要求全体をワイヤ形式にエンコードする (クライアント用)。
# 署名済みの FodprDelReq を渡すと、先頭に msgType(0x03) を付与し、
# 末尾に署名を付けて完全なパケットを生成する。
proc encodeDel*(req: FodprDelReq): string =
  result = $MsgTypeDel
  result.add(encodeDelSignedData(req))
  let sigRaw = req.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# encodeDel とは逆に、ストリームから削除要求を復元する (サーバー用)。
proc decodeDelReq*(stream: Stream): FodprDelReq =
  # transType (uint16, ビッグエンディアン)
  let ttBytes = stream.readStr(2)
  var ttNet, ttVal: uint16
  copyMem(addr ttNet, unsafeAddr ttBytes[0], 2)
  bigEndian16(addr ttVal, addr ttNet)

  # targetType (1 バイト)
  let tgtByte = stream.readChar()

  # pubkey (圧縮形式 33 バイト)
  let pubBytes = stream.readStr(33)
  var pubArr: array[33, byte]
  for i in 0..<33: pubArr[i] = byte(pubBytes[i])
  let pubkey = parsePublicKey(pubArr)

  # targetType に応じた識別子部分を読む
  var createdAt: uint64
  var contentHash: array[32, byte]
  var eventId: array[32, byte]
  case byte(tgtByte)
  of DelTargetEvent:
    let caBytes = stream.readStr(8)
    var caNet, caVal: uint64
    copyMem(addr caNet, unsafeAddr caBytes[0], 8)
    bigEndian64(addr caVal, addr caNet)
    createdAt = caVal
    let hashBytes = stream.readStr(32)
    for i in 0..<32: contentHash[i] = byte(hashBytes[i])
  of DelTargetEventId:
    let idBytes = stream.readStr(32)
    for i in 0..<32: eventId[i] = byte(idBytes[i])
  else:
    discard  # DelTargetPubkey は識別子部分なし

  # signature (compact 形式 64 バイト)
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  result = FodprDelReq(
    transType: ttVal,
    targetType: byte(tgtByte),
    pubkey: pubkey,
    createdAt: createdAt,
    contentHash: contentHash,
    eventId: eventId,
    signature: signature
  )

# ---------------------------------------------------------------------------
# AUTH (認証) のエンコード・デコード (NIP-42 相当)
# ---------------------------------------------------------------------------
# パケット形式 (サーバー → クライアント):
#   MsgTypeChallenge(1) | nonce(32)
#
# パケット形式 (クライアント → サーバー):
#   MsgTypeAuth(1) | nonce(32) | pubkey(33) | signature(64)
#
# 署名対象バイト列 (クライアント側とサーバー側で完全一致させる):
#   nonce(32) | pubkey(33)
# 署名は signContent(秘密鍵, 署名対象バイト列) で生成し、
# サーバーは verifyContent(pubkey, 署名対象バイト列, signature) で検証する。
# nonce はサーバーが発行したものと一致し、かつ期限内である必要がある。
# これにより「その鍵の持ち主であること」の証明になる。

# チャレンジパケットを生成する (サーバー用)。
# 引数の nonce は 32 バイトの暗号学的乱数。
proc encodeChallenge*(nonce: array[32, byte]): string =
  result = $MsgTypeChallenge
  for b in nonce: result.add(char(b))

# AUTH の署名対象バイト列 (nonce | pubkey) を作成する。
# クライアントはこのバイト列を signContent で署名し、サーバーは検証する。
proc encodeAuthSignedData*(auth: FodprAuth): string =
  for b in auth.nonce: result.add(char(b))
  let pubRaw = auth.pubkey.toRawCompressed()
  for b in pubRaw: result.add(char(b))

# 認証応答パケットをワイヤ形式にエンコードする (クライアント用)。
# あらかじめ auth.signature に encodeAuthSignedData の署名を入れておくこと。
proc encodeAuth*(auth: FodprAuth): string =
  result = $MsgTypeAuth
  result.add(encodeAuthSignedData(auth))
  let sigRaw = auth.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# encodeAuth とは逆に、ストリームから認証応答を復元する (サーバー用)。
proc decodeAuth*(stream: Stream): FodprAuth =
  # nonce (32 バイト)
  let nonceBytes = stream.readStr(32)
  var nonce: array[32, byte]
  for i in 0..<32: nonce[i] = byte(nonceBytes[i])

  # pubkey (圧縮形式 33 バイト)
  let pubBytes = stream.readStr(33)
  var pubArr: array[33, byte]
  for i in 0..<33: pubArr[i] = byte(pubBytes[i])
  let pubkey = parsePublicKey(pubArr)

  # signature (compact 形式 64 バイト)
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  result = FodprAuth(nonce: nonce, pubkey: pubkey, signature: signature)

# DEL 要求の署名検証
proc verifyDel*(req: FodprDelReq): bool =
  verifyBytes(req.pubkey, encodeDelSignedData(req), req.signature)

# AUTH 応答の署名検証
proc verifyAuth*(auth: FodprAuth): bool =
  verifyBytes(auth.pubkey, encodeAuthSignedData(auth), auth.signature)

# 送信タイプの数値から表示用の名前を返す。
# ログ出力やクライアントでの配信方法の判別表示に使う。
proc transTypeName*(transType: uint16): string =
  case transType
  of TransTypeAll:    "All"
  of TransTypeJSON:   "JSON"
  of TransTypeString: "String"
  of TransTypeBinary: "Binary"
  of TransTypeSigned: "Signed"
  of TransTypeEncrypted: "Encrypted"
  of TransTypeWebRTC: "WebRTC"
  of TransTypeF2FSignal: "F2FSignal"
  of TransTypePeerList: "PeerList"
  of TransTypeWoTIntro: "WoTIntro"
  of TransTypeInvitation: "Invitation"
  else: "Unknown(" & $transType & ")"

# シグナリングメッセージの種別の数値から表示用の名前を返す。
proc signalTypeName*(signalType: uint8): string =
  case signalType
  of SignalOffer:    "Offer"
  of SignalAnswer:   "Answer"
  of SignalCandidate: "Candidate"
  of SignalHostChange: "HostChange"
  else: "Unknown(" & $signalType & ")"

# ---------------------------------------------------------------------------
# WebRTC シグナリングメッセージ (MsgTypeSignal / MsgTypeSignalPush)
# ---------------------------------------------------------------------------
# パケット形式 (クライアント → サーバー, MsgTypeSignal = 0x05):
#   MsgTypeSignal(1) | signalType(1) | senderPubkey(33) | targetPubkey(33) |
#   contentLen(4) | content | signature(64)
#
# パケット形式 (サーバー → クライアント, MsgTypeSignalPush = 0x83):
#   MsgTypeSignalPush(1) | subIdLen(2) | subId |
#   signalType(1) | senderPubkey(33) | targetPubkey(33) |
#   contentLen(4) | content | signature(64)
#
# 署名対象バイト列 (senderPubkey が所有する秘密鍵で署名):
#   signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content
#
# セキュリティモデル:
#   - 送信者は signalType / sender / target / content に対して secp256k1 (ECDSA)
#     で署名する。リレーは署名を検証後、宛先に中継する。
#   - 受信者は受信したシグナリングメッセージの署名を検証し、送信者の身元を確かめる。
#   - リレーは content を解釈・復号せず、署名検証 + 宛先照合のみを行う。
#   - シグナリングメッセージは保存されず (TransTypeWebRTC 専用)、
#     P2P 接続確立後はリレーを通らない。
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
# (MsgTypeSignal / MsgTypeSignalPush の msgType バイトは含めない。
#  呼び出し側が付与する。)
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

# ストリームからシグナリングメッセージ本体を復元する (署名対象 + signature)。
# msgType バイトは呼び出し側が読み飛ばしてから渡すこと。
proc decodeSignal*(stream: Stream): FodprSignal =
  # signalType (1 バイト)
  let sigTypeByte = stream.readChar()

  # senderPubkey (圧縮形式 33 バイト)
  let senderBytes = stream.readStr(33)
  var senderArr: array[33, byte]
  for i in 0..<33: senderArr[i] = byte(senderBytes[i])
  let senderPub = parsePublicKey(senderArr)

  # targetPubkey (圧縮形式 33 バイト)
  let targetBytes = stream.readStr(33)
  var targetArr: array[33, byte]
  for i in 0..<33: targetArr[i] = byte(targetBytes[i])
  let targetPub = parsePublicKey(targetArr)

  # content (長さは uint32)
  let clBytes = stream.readStr(4)
  var clNet, cLen: uint32
  copyMem(addr clNet, unsafeAddr clBytes[0], 4)
  bigEndian32(addr cLen, addr clNet)
  let content = stream.readStr(int(cLen))

  # signature (compact 形式 64 バイト)
  let sigBytes = stream.readStr(64)
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

# ---------------------------------------------------------------------------
# WebRTC データチャネルメッセージ (MsgTypeData / MsgTypeDataPush)
# ---------------------------------------------------------------------------
# パケット形式 (P2P直接, MsgTypeData = 0x06):
#   MsgTypeData(1) | senderPubkey(33) | targetPubkey(33) | seq(8) | timestamp(8) |
#   tagCount(2) | (tagLen(2) | tag)* | contentLen(4) | content | signature(64)
#
# パケット形式 (リレー経由, MsgTypeDataPush = 0x84):
#   MsgTypeDataPush(1) | subIdLen(2) | subId |
#   senderPubkey(33) | targetPubkey(33) | seq(8) | timestamp(8) |
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
#   - リレー経由の場合も内容は解釈せず、署名検証 + 宛先照合のみ

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
  let senderBytes = stream.readStr(33)
  var senderArr: array[33, byte]
  for i in 0..<33: senderArr[i] = byte(senderBytes[i])
  let senderPub = parsePublicKey(senderArr)

  # targetPubkey (圧縮形式 33 バイト)
  let targetBytes = stream.readStr(33)
  var targetArr: array[33, byte]
  for i in 0..<33: targetArr[i] = byte(targetBytes[i])
  let targetPub = parsePublicKey(targetArr)

  # seq (8 バイト)
  let seqBytes = stream.readStr(8)
  var seqNet, seqVal: uint64
  copyMem(addr seqNet, unsafeAddr seqBytes[0], 8)
  bigEndian64(addr seqVal, addr seqNet)

  # timestamp (8 バイト)
  let tsBytes = stream.readStr(8)
  var tsNet, tsVal: uint64
  copyMem(addr tsNet, unsafeAddr tsBytes[0], 8)
  bigEndian64(addr tsVal, addr tsNet)

  # タグの個数 (2 バイト)
  let tcBytes = stream.readStr(2)
  var tcNet, tagCount: uint16
  copyMem(addr tcNet, unsafeAddr tcBytes[0], 2)
  bigEndian16(addr tagCount, addr tcNet)

  # タグ本体を個数分読み込む
  var tags = newSeq[string]()
  for i in 0..<int(tagCount):
    let tlBytes = stream.readStr(2)
    var tlNet, tLen: uint16
    copyMem(addr tlNet, unsafeAddr tlBytes[0], 2)
    bigEndian16(addr tLen, addr tlNet)
    tags.add(stream.readStr(int(tLen)))

  # content (長さは uint32)
  let clBytes = stream.readStr(4)
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
# F2F: P2P直接シグナリング (TransTypeF2FSignal)
# ---------------------------------------------------------------------------
# パケット形式 (P2P直接, F2Fデータチャネル経由):
#   signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content | signature(64) | viaRelay(1)
#
# 署名対象バイト列 (sender が所有する秘密鍵で署名):
#   signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content | viaRelay(1)

# シグナリングメッセージの署名対象バイト列をエンコードする:
proc encodeF2FSignalSignedData*(s: F2FSignal): string =
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

  # viaRelay (1 バイト)
  result.add(char(byte(if s.viaRelay: 1 else: 0)))

# F2Fシグナリングメッセージをワイヤ形式にエンコードする:
proc encodeF2FSignal*(s: F2FSignal): string =
  result = encodeF2FSignalSignedData(s)

  # signature（compact 形式 64 バイト）
  let sigRaw = s.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# F2Fシグナリングメッセージへの署名。sender フィールドは署名する前に
# 送信者の公開鍵で埋めること (署名対象データに含めるため)。
proc signF2FSignal*(priv: SkSecretKey, s: F2FSignal): FodprSignature =
  signBytes(priv, encodeF2FSignalSignedData(s))

# F2Fシグナリングメッセージの署名検証。sender フィールドの公開鍵で検証する。
proc verifyF2FSignal*(s: F2FSignal): bool =
  verifyBytes(s.sender, encodeF2FSignalSignedData(s), s.signature)

# ストリームからF2Fシグナリングメッセージ本体を復元する (署名対象 + signature)。
proc decodeF2FSignal*(stream: Stream): F2FSignal =
  # signalType (1 バイト)
  let sigTypeByte = stream.readChar()

  # senderPubkey (圧縮形式 33 バイト)
  let senderBytes = stream.readStr(33)
  var senderArr: array[33, byte]
  for i in 0..<33: senderArr[i] = byte(senderBytes[i])
  let senderPub = parsePublicKey(senderArr)

  # targetPubkey (圧縮形式 33 バイト)
  let targetBytes = stream.readStr(33)
  var targetArr: array[33, byte]
  for i in 0..<33: targetArr[i] = byte(targetBytes[i])
  let targetPub = parsePublicKey(targetArr)

  # content (長さは uint32)
  let clBytes = stream.readStr(4)
  var clNet, cLen: uint32
  copyMem(addr clNet, unsafeAddr clBytes[0], 4)
  bigEndian32(addr cLen, addr clNet)
  let content = stream.readStr(int(cLen))

  # viaRelay (1 バイト)
  let viaRelayByte = stream.readChar()
  let viaRelay = byte(viaRelayByte) != 0

  # signature (compact 形式 64 バイト)
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  return F2FSignal(
    signalType: byte(sigTypeByte),
    sender: senderPub,
    target: targetPub,
    content: content,
    signature: signature,
    viaRelay: viaRelay
  )

# ---------------------------------------------------------------------------
# F2F: ピア情報 (PeerInfo) のエンコード/デコード
# ---------------------------------------------------------------------------
# PeerInfo 形式:
#   pubkey(33) | addrCount(1) | (addrLen(2) | addr)* | lastSeen(8) | trustScore(4)

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

  # trustScore (float32, ビッグエンディアン)
  var tsNet: uint32
  var tsVal: uint32 = cast[uint32](p.trustScore)
  bigEndian32(addr tsNet, addr tsVal)
  var tsBytes: array[4, byte]
  copyMem(addr tsBytes[0], addr tsNet, 4)
  for b in tsBytes: result.add(char(b))

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

  # trustScore (float32, ビッグエンディアン)
  let tsBytes = stream.readStr(4)
  var tsNet: uint32
  copyMem(addr tsNet, unsafeAddr tsBytes[0], 4)
  bigEndian32(addr tsNet, addr tsNet)
  let trustScore = cast[float32](tsNet)

  return PeerInfo(
    pubkey: pubkey,
    addresses: addresses,
    lastSeen: lsVal,
    trustScore: trustScore
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
#   introducerPubkey(33) | PeerInfo | signature(64)
# 署名対象: introducerPubkey(33) | PeerInfo

proc encodeWoTIntroSignedData*(wi: WoTIntro): string =
  result = ""

  # introducerPubkey (圧縮形式 33 バイト)
  let introRaw = wi.introducer.toRawCompressed()
  for b in introRaw: result.add(char(b))

  # newPeer (PeerInfo)
  result.add(encodePeerInfo(wi.newPeer))

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

  # signature (compact 形式 64 バイト)
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))

  return WoTIntro(
    introducer: introducer,
    newPeer: newPeer,
    signature: signature
  )

# ---------------------------------------------------------------------------
# F2F: インビテーションコード (TransTypeInvitation)
# ---------------------------------------------------------------------------
# InvitationCode (エンコード前バイナリ形式):
#   version(1) | issuerPubkey(33) | PeerInfo | expiresAt(8) | scope(1) | signature(64)
# 署名対象: version(1) | issuerPubkey(33) | PeerInfo | expiresAt(8) | scope(1)
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
    signature: emptySignature()  # プレースホルダ
  )
  inv.signature = signInvitation(issuerPriv, inv)
  return inv

# ---------------------------------------------------------------------------
# F2F: グループ管理 (GroupMember, F2FGroup, GroupJoinReq, GroupLeaveReq) エンコード/デコード
# ---------------------------------------------------------------------------

# GroupMember エンコード
#   pubkey(33) | addrCount(1) | (addrLen(2) | addr)* | joinedAt(8) | isHost(1) | isConnected(1)
proc encodeGroupMember*(m: GroupMember): string =
  result = ""
  let pubRaw = m.pubkey.toRawCompressed()
  for b in pubRaw: result.add(char(b))
  result.add(char(byte(m.addresses.len)))
  for addr in m.addresses:
    let aLen = uint16(addr.len)
    var alNet: uint16
    bigEndian16(addr alNet, unsafeAddr aLen)
    var alBytes: array[2, byte]
    copyMem(addr alBytes[0], addr alNet, 2)
    result.add(char(alBytes[0]))
    result.add(char(alBytes[1]))
    result.add(addr)
  var jaNet: uint64
  bigEndian64(addr jaNet, unsafeAddr m.joinedAt)
  var jaBytes: array[8, byte]
  copyMem(addr jaBytes[0], addr jaNet, 8)
  for b in jaBytes: result.add(char(b))
  result.add(char(if m.isHost: 1 else: 0))
  result.add(char(if m.isConnected: 1 else: 0))

# GroupMember デコード
proc decodeGroupMember*(stream: Stream): GroupMember =
  let pubBytes = stream.readStr(33)
  var pubArr: array[33, byte]
  for i in 0..<33: pubArr[i] = byte(pubBytes[i])
  let pubkey = parsePublicKey(pubArr)
  
  let addrCount = int(byte(stream.readChar()))
  var addresses = newSeq[string]()
  for i in 0..<addrCount:
    let alBytes = stream.readStr(2)
    var alNet, aLen: uint16
    copyMem(addr alNet, unsafeAddr alBytes[0], 2)
    bigEndian16(addr aLen, addr alNet)
    addresses.add(stream.readStr(int(aLen)))
  
  let jaBytes = stream.readStr(8)
  var jaNet, jaVal: uint64
  copyMem(addr jaNet, unsafeAddr jaBytes[0], 8)
  bigEndian64(addr jaVal, addr jaNet)
  
  let isHost = byte(stream.readChar()) != 0
  let isConnected = byte(stream.readChar()) != 0
  
  return GroupMember(
    pubkey: pubkey,
    addresses: addresses,
    joinedAt: jaVal,
    isHost: isHost,
    isConnected: isConnected
  )

# F2FGroup エンコード (署名対象)
#   groupIdLen(2) | groupId | hostPubkey(33) | memberCount(2) | GroupMember* | version(8) | createdAt(8)
proc encodeGroupSignedData*(g: F2FGroup): string =
  result = ""
  
  let gidLen = uint16(g.groupId.len)
  var gidNet: uint16
  bigEndian16(addr gidNet, unsafeAddr gidLen)
  var gidBytes: array[2, byte]
  copyMem(addr gidBytes[0], addr gidNet, 2)
  result.add(char(gidBytes[0]))
  result.add(char(gidBytes[1]))
  result.add(g.groupId)
  
  let hostRaw = g.hostPubkey.toRawCompressed()
  for b in hostRaw: result.add(char(b))
  
  let mcNet: uint16 = uint16(g.members.len)
  var mcBytes: array[2, byte]
  copyMem(addr mcBytes[0], addr mcNet, 2)
  result.add(char(mcBytes[0]))
  result.add(char(mcBytes[1]))
  
  for m in g.members:
    result.add(encodeGroupMember(m))
  
  var vNet: uint64
  bigEndian64(addr vNet, unsafeAddr g.version)
  var vBytes: array[8, byte]
  copyMem(addr vBytes[0], addr vNet, 8)
  for b in vBytes: result.add(char(b))
  
  var cNet: uint64
  bigEndian64(addr cNet, unsafeAddr g.createdAt)
  var cBytes: array[8, byte]
  copyMem(addr cBytes[0], addr cNet, 8)
  for b in cBytes: result.add(char(b))

# F2FGroup エンコード (署名付き)
proc encodeGroup*(g: F2FGroup): string =
  result = encodeGroupSignedData(g)
  let sigRaw = g.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# F2FGroup 署名
proc signGroup*(priv: SkSecretKey, g: F2FGroup): FodprSignature =
  signBytes(priv, encodeGroupSignedData(g))

# F2FGroup 署名検証
proc verifyGroup*(g: F2FGroup): bool =
  verifyBytes(g.hostPubkey, encodeGroupSignedData(g), g.signature)

# F2FGroup デコード
proc decodeGroup*(stream: Stream): F2FGroup =
  let gidLenBytes = stream.readStr(2)
  var gidNet, gidLen: uint16
  copyMem(addr gidNet, unsafeAddr gidLenBytes[0], 2)
  bigEndian16(addr gidLen, addr gidNet)
  let groupId = stream.readStr(int(gidLen))
  
  let hostBytes = stream.readStr(33)
  var hostArr: array[33, byte]
  for i in 0..<33: hostArr[i] = byte(hostBytes[i])
  let hostPubkey = parsePublicKey(hostArr)
  
  let mcBytes = stream.readStr(2)
  var mcNet, memberCount: uint16
  copyMem(addr mcNet, unsafeAddr mcBytes[0], 2)
  bigEndian16(addr memberCount, addr mcNet)
  
  var members = newSeq[GroupMember]()
  for i in 0..<int(memberCount):
    members.add(decodeGroupMember(stream))
  
  let vBytes = stream.readStr(8)
  var vNet, vVal: uint64
  copyMem(addr vNet, unsafeAddr vBytes[0], 8)
  bigEndian64(addr vVal, addr vNet)
  
  let cBytes = stream.readStr(8)
  var cNet, cVal: uint64
  copyMem(addr cNet, unsafeAddr cBytes[0], 8)
  bigEndian64(addr cVal, addr cNet)
  
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))
  
  return F2FGroup(
    groupId: groupId,
    hostPubkey: hostPubkey,
    members: members,
    version: vVal,
    createdAt: cVal,
    signature: signature
  )

# GroupJoinReq エンコード (署名対象)
#   groupIdLen(2) | groupId | GroupMember | signature(64)
proc encodeGroupJoinReqSignedData*(req: GroupJoinReq): string =
  result = ""
  let gidLen = uint16(req.groupId.len)
  var gidNet: uint16
  bigEndian16(addr gidNet, unsafeAddr gidLen)
  var gidBytes: array[2, byte]
  copyMem(addr gidBytes[0], addr gidNet, 2)
  result.add(char(gidBytes[0]))
  result.add(char(gidBytes[1]))
  result.add(req.groupId)
  result.add(encodeGroupMember(req.member))

# GroupJoinReq エンコード (署名付き)
proc encodeGroupJoinReq*(req: GroupJoinReq): string =
  result = encodeGroupJoinReqSignedData(req)
  let sigRaw = req.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# GroupJoinReq 署名
proc signGroupJoinReq*(priv: SkSecretKey, req: GroupJoinReq): FodprSignature =
  signBytes(priv, encodeGroupJoinReqSignedData(req))

# GroupJoinReq 署名検証
proc verifyGroupJoinReq*(req: GroupJoinReq): bool =
  verifyBytes(req.member.pubkey, encodeGroupJoinReqSignedData(req), req.signature)

# GroupJoinReq デコード
proc decodeGroupJoinReq*(stream: Stream): GroupJoinReq =
  let gidLenBytes = stream.readStr(2)
  var gidNet, gidLen: uint16
  copyMem(addr gidNet, unsafeAddr gidLenBytes[0], 2)
  bigEndian16(addr gidLen, addr gidNet)
  let groupId = stream.readStr(int(gidLen))
  
  let member = decodeGroupMember(stream)
  
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))
  
  return GroupJoinReq(
    groupId: groupId,
    member: member,
    signature: signature
  )

# GroupLeaveReq エンコード (署名対象)
#   groupIdLen(2) | groupId | memberPubkey(33)
proc encodeGroupLeaveReqSignedData*(req: GroupLeaveReq): string =
  result = ""
  let gidLen = uint16(req.groupId.len)
  var gidNet: uint16
  bigEndian16(addr gidNet, unsafeAddr gidLen)
  var gidBytes: array[2, byte]
  copyMem(addr gidBytes[0], addr gidNet, 2)
  result.add(char(gidBytes[0]))
  result.add(char(gidBytes[1]))
  result.add(req.groupId)
  let pubRaw = req.memberPubkey.toRawCompressed()
  for b in pubRaw: result.add(char(b))

# GroupLeaveReq エンコード (署名付き)
proc encodeGroupLeaveReq*(req: GroupLeaveReq): string =
  result = encodeGroupLeaveReqSignedData(req)
  let sigRaw = req.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# GroupLeaveReq 署名
proc signGroupLeaveReq*(priv: SkSecretKey, req: GroupLeaveReq): FodprSignature =
  signBytes(priv, encodeGroupLeaveReqSignedData(req))

# GroupLeaveReq 署名検証
proc verifyGroupLeaveReq*(req: GroupLeaveReq): bool =
  verifyBytes(req.memberPubkey, encodeGroupLeaveReqSignedData(req), req.signature)

# GroupLeaveReq デコード
proc decodeGroupLeaveReq*(stream: Stream): GroupLeaveReq =
  let gidLenBytes = stream.readStr(2)
  var gidNet, gidLen: uint16
  copyMem(addr gidNet, unsafeAddr gidLenBytes[0], 2)
  bigEndian16(addr gidLen, addr gidNet)
  let groupId = stream.readStr(int(gidLen))
  
  let pubBytes = stream.readStr(33)
  var pubArr: array[33, byte]
  for i in 0..<33: pubArr[i] = byte(pubBytes[i])
  let memberPubkey = parsePublicKey(pubArr)
  
  let sigBytes = stream.readStr(64)
  var sigArr: array[64, byte]
  for i in 0..<64: sigArr[i] = byte(sigBytes[i])
  let signature = FodprSignature(sig: parseSignature(sigArr))
  
  return GroupLeaveReq(
    groupId: groupId,
    memberPubkey: memberPubkey,
    signature: signature
  )
