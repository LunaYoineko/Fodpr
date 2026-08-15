## gen_host_invite.nim
## 接続テスト用: ホスト自身の IPv6:8000 を示す招待コードを生成して stdout に出力する。
## 引数: IPv6 アドレス (省略時 ::1)

import os, strutils, times
import Fodpr

let ipv6 = if paramCount() >= 1: paramStr(1) else: "::1"
let key = generateFodprKey()
let peer = PeerInfo(
  pubkey: key.publicKey,
  addresses: @["[" & ipv6 & "]:8000"],
  lastSeen: uint64(epochTime()),
  identityTrust: 1.0,
  reliabilityScore: 1.0,
  country: ""
)
let inv = invitation.createInvitation(key.privateKey, peer, 3600, INVITATION_SCOPE_WOT)
echo invitation.encodeInvitation(inv)
