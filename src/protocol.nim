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

import streams, endians, strutils
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
  MsgTypePush*  = char(0x81)   # イベント配信
  MsgTypeChallenge* = char(0x82) # 認証チャレンジ (サーバー → クライアント)
  
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
  else: "Unknown(" & $transType & ")"
