## envelope.nim
## Fodpr の宛先別暗号化エンベロープ (seal / gift-wrap 相当) を定義するモジュール。
##
## TransTypeEncrypted (5) の content に格納するバイナリ形式:
##   version(1) | recipientCount(2, BE) | (recipient block × count) |
##   bodyNonce(12) | bodyTag(16) | bodyCiphertext
##
##   recipient block (固定長 93 バイト):
##     recipientPubkey(33) | wrapNonce(12) | wrappedKeyCiphertext(32) | wrappedKeyTag(16)
##
## 鍵スキーム:
##   - メッセージ鍵 K (32B ランダム) で本文 (body) を AES-256-GCM で暗号化
##   - K を各受信者向けに、ECDH 共有鍵から導出したラップ鍵 W でラップする
##   - W = SHA-256(ECDH(送信者秘密鍵, 受信者公開鍵) || "FodprEnvelopeV1" || 受信者公開鍵)
##   - 受信者は ECDH(自分の秘密鍵, 送信者公開鍵) で同じ W を復元し、K を取り出す
##
## リレーは内容を解釈せず、isValidEnvelope / envelopeRecipients による
## 構造検証と to:<fpub> タグとの突合のみを行う。

import streams, endians
import crypto, secp256k1
import nimcrypto, nimSHA2

const
  EnvelopeVersion* = byte(0x01)   # エンベロープ形式のバージョン
  EnvelopeNonceLen = 12           # GCM nonce 長
  EnvelopeTagLen   = 16           # GCM 認証タグ長
  EnvelopeKeyLen   = 32           # メッセージ鍵 / ラップ鍵の長さ
  EnvelopeRecipBlockLen = 33 + EnvelopeNonceLen + EnvelopeKeyLen + EnvelopeTagLen
  EnvelopeContext = "FodprEnvelopeV1"

type
  # 暗号化・復号の失敗を表す例外。
  EnvelopeError* = object of CatchableError

# ---------------------------------------------------------------------------
# 内部ヘルパー
# ---------------------------------------------------------------------------

proc toBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  if s.len > 0:
    copyMem(addr result[0], unsafeAddr s[0], s.len)

proc fromBytes(b: openArray[byte]): string =
  result = newString(b.len)
  if b.len > 0:
    copyMem(addr result[0], unsafeAddr b[0], b.len)

# ラップ鍵 W の導出。ECDH 共有鍵にドメイン分離と受信者公開鍵を混ぜることで、
# 同じ共有鍵でも受信者ごとに異なる W になる (鍵の分離)。
proc wrapKey(shared: SkEcdhSecret, recipPub: openArray[byte]): array[EnvelopeKeyLen, byte] =
  var ctx: SHA256
  ctx.initSHA()
  ctx.update(shared.data)
  ctx.update(EnvelopeContext)
  ctx.update(recipPub)
  result = array[EnvelopeKeyLen, byte](ctx.final())

# AES-256-GCM 暗号化 (平文 → 暗号文 + タグ)。
proc gcmEncrypt(key: array[EnvelopeKeyLen, byte], nonce: array[EnvelopeNonceLen, byte],
                plain: seq[byte]): tuple[ct: seq[byte], tag: array[EnvelopeTagLen, byte]] =
  var noAad: array[0, byte]
  var gcm: GCM[rijndael256]
  gcm.init(key, nonce, noAad)
  result.ct = newSeq[byte](plain.len)
  gcm.encrypt(plain, result.ct, result.tag)

# AES-256-GCM 復号 (認証失敗は EnvelopeError)。
proc gcmDecrypt(key: array[EnvelopeKeyLen, byte], nonce: array[EnvelopeNonceLen, byte],
                ct: seq[byte], tag: array[EnvelopeTagLen, byte]): seq[byte] =
  var noAad: array[0, byte]
  var gcm: GCM[rijndael256]
  gcm.init(key, nonce, noAad)
  result = newSeq[byte](ct.len)
  if not gcm.decrypt(ct, result, tag):
    raise newException(EnvelopeError, "envelope decryption failed (authentication tag mismatch)")

# ---------------------------------------------------------------------------
# エンベロープの組み立て / 解析
# ---------------------------------------------------------------------------

proc isValidEnvelope*(envelope: string): bool  # 前方宣言

# 本文を複数の受信者向けに暗号化したエンベロープを生成する。
# senderPriv は送信者 (イベントの pubkey の秘密鍵)。
proc encryptEnvelope*(body: string, senderPriv: SkSecretKey, recipients: seq[SkPublicKey]): string =
  if body.len == 0:
    raise newException(EnvelopeError, "body must not be empty")
  if recipients.len == 0:
    raise newException(EnvelopeError, "at least one recipient required")
  if recipients.len > 65535:
    raise newException(EnvelopeError, "too many recipients")

  # メッセージ鍵 K と本文の暗号化
  var k: array[EnvelopeKeyLen, byte]
  discard randomBytes(k)
  var bodyNonce: array[EnvelopeNonceLen, byte]
  discard randomBytes(bodyNonce)
  let (bodyCt, bodyTag) = gcmEncrypt(k, bodyNonce, toBytes(body))

  # ヘッダ (version | recipientCount)
  result.add(char(EnvelopeVersion))
  let rc = uint16(recipients.len)
  result.add(char(byte((rc shr 8) and 0xff)))
  result.add(char(byte(rc and 0xff)))

  # 受信者ごとの鍵ブロック
  for r in recipients:
    let pubRaw = r.toRawCompressed()
    for b in pubRaw: result.add(char(b))
    let shared = ecdh(senderPriv, r)
    let w = wrapKey(shared, pubRaw)
    var wrapNonce: array[EnvelopeNonceLen, byte]
    discard randomBytes(wrapNonce)
    let (wct, wtag) = gcmEncrypt(w, wrapNonce, @k)
    for b in wrapNonce: result.add(char(b))
    for b in wct: result.add(char(b))
    for b in wtag: result.add(char(b))

  # 本文の暗号文
  for b in bodyNonce: result.add(char(b))
  for b in bodyTag: result.add(char(b))
  for b in bodyCt: result.add(char(b))

# エンベロープを復号する。受信者が宛先に含まれていれば本文を返す。
# senderPub はイベントの pubkey (送信者) で、ECDH の相手鍵として使う。
# 宛先に含まれていない場合や認証タグ不一致は EnvelopeError。
proc decryptEnvelope*(envelope: string, recipientPriv: SkSecretKey, senderPub: SkPublicKey): string =
  if not isValidEnvelope(envelope):
    raise newException(EnvelopeError, "invalid envelope")

  var strm = newStringStream(envelope)
  discard strm.readChar()  # version
  let rcBytes = strm.readStr(2)
  var rcNet, rc: uint16
  copyMem(addr rcNet, unsafeAddr rcBytes[0], 2)
  bigEndian16(addr rc, addr rcNet)

  let myRawBytes = recipientPriv.toPublicKey().toRawCompressed()
  var myRaw = newString(33)
  for i in 0..<33: myRaw[i] = char(myRawBytes[i])

  # 自分の受信者ブロックを探す (本文は全ブロックの後にあるため、
  # ブロックは先に読み切ってから本文を読む)
  var matched: tuple[found: bool, nonce: string, ct: string, tag: string]
  for i in 0..<int(rc):
    let pubBytes = strm.readStr(33)
    let wrapNonceBytes = strm.readStr(EnvelopeNonceLen)
    let wctBytes = strm.readStr(EnvelopeKeyLen)
    let wtagBytes = strm.readStr(EnvelopeTagLen)
    if pubBytes == myRaw:
      matched = (true, wrapNonceBytes, wctBytes, wtagBytes)
      break
  if not matched.found:
    raise newException(EnvelopeError, "recipient is not addressed in this envelope")

  # 本文は全受信者ブロックの後にあるため、先頭から
  # (version 1 + recipientCount 2 + ブロック数 × ブロック長) へ移動する
  strm.setPosition(3 + int(rc) * EnvelopeRecipBlockLen)

  # 自分のブロックのラップ鍵 W を復元して K を取り出す
  let shared = ecdh(recipientPriv, senderPub)
  let w = wrapKey(shared, myRaw.toOpenArrayByte(0, myRaw.len - 1))
  var wrapNonce: array[EnvelopeNonceLen, byte]
  for j in 0..<EnvelopeNonceLen: wrapNonce[j] = byte(matched.nonce[j])
  var wtag: array[EnvelopeTagLen, byte]
  for j in 0..<EnvelopeTagLen: wtag[j] = byte(matched.tag[j])
  let k = gcmDecrypt(w, wrapNonce, toBytes(matched.ct), wtag)
  var kArr: array[EnvelopeKeyLen, byte]
  if k.len != EnvelopeKeyLen:
    raise newException(EnvelopeError, "invalid wrapped key length")
  copyMem(addr kArr[0], unsafeAddr k[0], EnvelopeKeyLen)

  # 本文を復号 (現在位置は全受信者ブロックの直後)
  let bodyNonceBytes = strm.readStr(EnvelopeNonceLen)
  let bodyTagBytes = strm.readStr(EnvelopeTagLen)
  let bodyCtBytes = strm.readStr(envelope.len - strm.getPosition)
  var bodyNonce: array[EnvelopeNonceLen, byte]
  for j in 0..<EnvelopeNonceLen: bodyNonce[j] = byte(bodyNonceBytes[j])
  var bodyTag: array[EnvelopeTagLen, byte]
  for j in 0..<EnvelopeTagLen: bodyTag[j] = byte(bodyTagBytes[j])
  return fromBytes(gcmDecrypt(kArr, bodyNonce, toBytes(bodyCtBytes), bodyTag))

# エンベロープの構造を検証する (リレー用。内容は解釈しない)。
# バージョン・受信者数・長さの整合性のみを確認する。
proc isValidEnvelope*(envelope: string): bool =
  if envelope.len < 3 + EnvelopeRecipBlockLen + EnvelopeNonceLen + EnvelopeTagLen:
    return false
  if byte(envelope[0]) != EnvelopeVersion:
    return false
  var rc = (uint16(byte(envelope[1])) shl 8) or uint16(byte(envelope[2]))
  let expected = 3 + int(rc) * EnvelopeRecipBlockLen + EnvelopeNonceLen + EnvelopeTagLen
  return envelope.len >= expected

# エンベロープに含まれる受信者の公開鍵一覧を返す (リレー用。
# to:<fpub> タグとの突合に使う。構造が不正なら EnvelopeError)。
proc envelopeRecipients*(envelope: string): seq[SkPublicKey] =
  if not isValidEnvelope(envelope):
    raise newException(EnvelopeError, "invalid envelope")
  var rc = (uint16(byte(envelope[1])) shl 8) or uint16(byte(envelope[2]))
  var strm = newStringStream(envelope)
  discard strm.readChar()   # version
  discard strm.readStr(2)   # recipientCount
  result = newSeq[SkPublicKey](int(rc))
  for i in 0..<int(rc):
    let pubBytes = strm.readStr(33)
    var pubArr: array[33, byte]
    for j in 0..<33: pubArr[j] = byte(pubBytes[j])
    result[i] = parsePublicKey(pubArr)
    # 受信者ブロックの残り (wrapNonce | wrappedKey | wrappedTag) を読み飛ばす
    discard strm.readStr(EnvelopeNonceLen + EnvelopeKeyLen + EnvelopeTagLen)
