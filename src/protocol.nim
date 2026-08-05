## protocol.nim
## Fodpr のワイヤプロトコルを定義するモジュール。
##
## クライアント ⇄ サーバー間でやり取りされるバイナリパケットの
## エンコード / デコード処理を提供する。
##
## パケット構造（先頭 1 バイトがメッセージ種別）:
##   - 0x01 (EVENT): イベント投稿（署名付き）
##   - 0x02 (REQ)  : サブスクリプション要求
##   - 0x81 (PUSH) : サーバー → クライアントのイベント配信
##
## 数値はすべてビッグエンディアン（ネットワークバイトオーダー）で
## エンコードされ、プラットフォーム差を吸収している。

import streams, endians
import crypto, secp256k1

# メッセージ種別を表す定数。
# 0x01 / 0x02 はクライアント → サーバー、
# 0x81 はサーバー → クライアントの配信を表す。
const
  MsgTypeEvent* = char(0x01)   # イベント投稿
  MsgTypeReq*   = char(0x02)   # 購読要求
  MsgTypePush*  = char(0x81)   # イベント配信
  
  KindMetaData* = 0.uint16
  KindTextNote* = 1.uint16
  KindMedia*    = 2.uint16

type
  # 投稿されるイベント本体。
  # pubkey と signature は crypto.nim の secp256k1 型を使用する。
  FodprEvent* = object
    kind*      : uint16       # イベント種別 (0 = すべて)
    createdAt* : uint64       # Unix タイムスタンプ（秒）
    pubkey*    : SkPublicKey  # 送信者の公開鍵（圧縮形式 33 バイトで送信）
    tags*      : seq[string]  # タグ文字列のリスト
    content*   : string       # 本文
    signature* : FodprSignature # 本文に対する ECDSA 署名

  # 購読 (REQ) 要求。
  # kind が 0 の場合はすべての種別、tagKey/tagVal でタグの絞り込みも可能。
  FodprReq* = object
    subId*  : string   # 購読を識別するための ID
    kind*   : uint16   # 購読したいイベント種別
    tagKey* : string   # 絞り込み対象のタグキー
    tagVal* : string   # 絞り込み対象のタグ値

# ---------------------------------------------------------------------------
# EVENT のエンコード
# ---------------------------------------------------------------------------

# イベントを以下のバイナリ形式にエンコードする:
#   kind(2) | createdAt(8) | pubkey(33) | tagCount(2) |
#   (tagLen(2) | tag) * tagCount | contentLen(4) | content | signature(64)
proc encodeEvent*(ev: FodprEvent): string =
  result = ""

  # kind (uint16, ビッグエンディアン)
  var kNet: uint16
  bigEndian16(addr kNet, unsafeAddr ev.kind)
  var kBytes: array[2, byte]
  copyMem(addr kBytes[0], addr kNet, 2)
  result.add(char(kBytes[0]))
  result.add(char(kBytes[1]))

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

  # signature（compact 形式 64 バイト）
  let sigRaw = ev.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# ---------------------------------------------------------------------------
# EVENT のデコード
# ---------------------------------------------------------------------------

# encodeEvent とは逆に、ストリームからバイナリデータを読み込んで
# FodprEvent オブジェクトへ復元する。
proc decodeEvent*(stream: Stream): FodprEvent =
  # kind (2 バイト)
  let kBytes = stream.readStr(2)
  var kNet, kindVal: uint16
  copyMem(addr kNet, unsafeAddr kBytes[0], 2)
  bigEndian16(addr kindVal, addr kNet)

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
    kind: kindVal,
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
#   MsgTypeReq(1) | subIdLen(2) | subId | kind(2) |
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

  # kind (uint16, ビッグエンディアン)
  var kNet: uint16
  bigEndian16(addr kNet, unsafeAddr r.kind)
  var kBytes: array[2, byte]
  copyMem(addr kBytes[0], addr kNet, 2)
  result.add(char(kBytes[0]))
  result.add(char(kBytes[1]))

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

  # kind (uint16)
  let kBytes = stream.readStr(2)
  var kNet, kindVal: uint16
  copyMem(addr kNet, unsafeAddr kBytes[0], 2)
  bigEndian16(addr kindVal, addr kNet)

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

  return FodprReq(subId: subId, kind: kindVal, tagKey: tagKey, tagVal: tagVal)
