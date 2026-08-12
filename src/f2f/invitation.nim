## invitation.nim
## F2F: インビテーションコード生成・検証モジュール (第1救済)
##
## 知人から共有される招待データ（QRコード、URIスキーム、テキスト）を
## 生成・検証・エンコード/デコードする。
## Bech32形式: f2finv1...

import times, streams, strutils
import protocol, crypto

const
  INVITATION_VERSION* = byte(1)
  INVITATION_SCOPE_SINGLE* = byte(0)  # 単発接続のみ
  INVITATION_SCOPE_WOT* = byte(1)     # WoT招待 (キャッシュ共有含む)
  DEFAULT_EXPIRY_HOURS* = 168         # 7日間 (7*24)
  URI_SCHEME* = "fodpr://invite/"

# インビテーションコード生成
# issuerPriv: 発行者の秘密鍵
# targetPeer: 接続対象のピア情報
# expiresInSec: 有効期限 (秒)
# scope: 0=単発接続, 1=WoT招待
proc createInvitation*(issuerPriv: SkSecretKey, targetPeer: PeerInfo,
                       expiresInSec: uint64 = DEFAULT_EXPIRY_HOURS * 3600,
                       scope: uint8 = INVITATION_SCOPE_WOT): InvitationCode =
  let now = uint64(epochTime())
  var inv = InvitationCode(
    version: INVITATION_VERSION,
    issuer: issuerPriv.toPublicKey(),
    targetPeer: targetPeer,
    expiresAt: now + expiresInSec,
    scope: scope,
    signature: emptySignature()  # プレースホルダ
  )
  inv.signature = signInvitation(issuerPriv, inv)
  return inv

# Bech32エンコード (f2finv1...)
proc encodeInvitation*(inv: InvitationCode): string =
  let bin = protocol.encodeInvitation(inv)
  var data = newSeq[byte](bin.len)
  for i in 0..<bin.len: data[i] = byte(bin[i])
  result = bech32Encode(InvitationHrp, data)

# Bech32デコード
proc decodeInvitation*(code: string): InvitationCode =
  let data = bech32Decode(code, InvitationHrp)
  var bin = newString(data.len)
  for i in 0..<data.len: bin[i] = char(data[i])
  var strm = newStringStream(bin)
  return decodeInvitation(strm)

# インビテーションコード検証
# - 署名検証
# - 有効期限チェック
# - バージョンチェック
proc verifyInvitation*(inv: InvitationCode): bool =
  if inv.version != INVITATION_VERSION:
    return false
  let now = uint64(epochTime())
  if now > inv.expiresAt:
    return false
  if inv.scope > INVITATION_SCOPE_WOT:
    return false
  return protocol.verifyInvitation(inv)

# URIスキーム形式で出力 (fodpr://invite/f2finv1...)
proc encodeInvitationUri*(inv: InvitationCode): string =
  let code = encodeInvitation(inv)
  return URI_SCHEME & code

# URIからインビテーションコードを抽出・デコード
proc decodeInvitationUri*(uri: string): InvitationCode =
  if not uri.startsWith(URI_SCHEME):
    raise newException(ValueError, "Invalid URI scheme")
  let code = uri[URI_SCHEME.len..^1]
  return decodeInvitation(code)

# QRコード用のテキスト表現 (Bech32そのまま)
proc encodeInvitationQr*(inv: InvitationCode): string =
  return encodeInvitation(inv)

# インビテーションコードからピア情報を抽出
proc getTargetPeer*(inv: InvitationCode): PeerInfo =
  return inv.targetPeer

# インビテーションの発行者公開鍵を取得
proc getIssuerPubkey*(inv: InvitationCode): SkPublicKey =
  return inv.issuer

# 有効期限の人間可読形式
proc getExpiryString*(inv: InvitationCode): string =
  let t = inv.expiresAt.int64
  return format(t.fromUnix(), "yyyy-MM-dd HH:mm:ss")

# スコープの人間可読形式
proc getScopeString*(inv: InvitationCode): string =
  case inv.scope
  of INVITATION_SCOPE_SINGLE: "単発接続のみ"
  of INVITATION_SCOPE_WOT: "WoT招待 (キャッシュ共有含む)"
  else: "Unknown"

# インビテーションコードの詳細表示用
proc invitationToString*(inv: InvitationCode): string =
  let valid = verifyInvitation(inv)
  result = "=== インビテーションコード ===\n"
  result &= "バージョン: " & $inv.version & "\n"
  result &= "発行者: " & fpubEncode(inv.issuer) & "\n"
  result &= "接続先: " & fpubEncode(inv.targetPeer.pubkey) & "\n"
  result &= "接続先アドレス: " & inv.targetPeer.addresses.join(", ") & "\n"
  result &= "有効期限: " & getExpiryString(inv) & "\n"
  result &= "スコープ: " & getScopeString(inv) & "\n"
  result &= "有効性: " & (if valid: "有効" else: "無効/期限切れ") & "\n"
  result &= "================================"

# テスト用: サンプルインビテーション生成
proc createTestInvitation*(priv: SkSecretKey, targetPubkey: SkPublicKey,
                           addresses: seq[string] = @["[::1]:8000"]): InvitationCode =
  let peer = PeerInfo(
    pubkey: targetPubkey,
    addresses: addresses,
    lastSeen: uint64(epochTime()),
    trustScore: 1.0
  )
  return createInvitation(priv, peer)