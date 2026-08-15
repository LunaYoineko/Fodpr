## holepunch_host.nim
## ホスト側 UDP ホールパンチピア (ファイアウォール越えテスト用 CLI)
## ============================================================================
## ファイアウォール (UFW) の内側にいるホスト側から、相手 (モバイル等) へ
## UDP パンチを送り続け、相手からのパンチに応答する。自ら先に送ることで
## conntrack にフローを作り、相手のパケットが「応答」として通るようにする。
##
## 使い方:
##   nim c -d:release examples/holepunch_host.nim
##   ./examples/holepunch_host <相手IPv6> [localPort] [remotePort] [durationSec]
##
## 例 (相手 240b:c020:... が UDP 8000 で待機している場合):
##   ./examples/holepunch_host 240b:c020:4e0:5929:b0be:7d18:bb9d:64d7 8000 8000 20
##
## ポート開放は不要。firewall が「外→内」を遮断していても、こちらが先に
## パケットを送れば往復が成立することを実証できる。

import std/[os, strutils, times, net]
from std/posix import TPollfd, POLLIN, poll
import Fodpr

proc usage() =
  echo "usage: holepunch_host <remoteIPv6> [localPort] [remotePort] [durationSec]"
  quit(1)

proc main() =
  if paramCount() < 1:
    usage()
  let remoteHost = paramStr(1)
  let localPort = (if paramCount() >= 2: parseInt(paramStr(2)) else: 8000)
  let remotePort = (if paramCount() >= 3: parseInt(paramStr(3)) else: localPort)
  let durationSec = (if paramCount() >= 4: parseInt(paramStr(4)) else: 15)

  if remoteHost.len == 0:
    usage()

  let key = generateFodprKey()
  let myPub = key.publicKey
  echo "holepunch_host 開始"
  echo "  相手      : " & remoteHost & ":" & $remotePort
  echo "  バインド  : UDP [::]:" & $localPort
  echo "  公開鍵    : " & fpubEncode(myPub)[0 ..< 24] & "..."
  echo "  ファイアウォールはこちらが先に送ることで穴を開ける (ポート開放不要)"

  var sock: Socket
  try:
    sock = newSocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindAddr(Port(localPort), "::")
  except CatchableError as e:
    echo "ERROR: bind 失敗: " & e.msg
    quit(1)

  var
    punchesSent = 0
    punchesRecv = 0
    roundTrips = 0
    msgRecv = 0
    lastRtt = 0.0
    seqCounter = 0'u64
    sentSeqToTime: seq[tuple[seq: uint64, t0: float]]
  let deadline = epochTime() + durationSec.float

  echo "パンチ開始 (" & $durationSec & " 秒) ..."
  while epochTime() < deadline:
    # --- 送信: 相手へパンチを打つ ---
    var pkt = createPunchPacket(PT_PUNCH, myPub, seqCounter)
    signPunchPacket(key.privateKey, pkt)
    try:
      sock.sendTo(parseIpAddress(remoteHost), Port(remotePort),
                  encodePunchPacket(pkt))
      inc punchesSent
      sentSeqToTime.add((seq: seqCounter, t0: epochTime()))
      inc seqCounter
    except CatchableError as e:
      echo "send error: " & e.msg
    # --- 受信: 相手からのパンチ / 応答を処理 ---
    var pfd: TPollfd
    pfd.fd = cint(getFd(sock))
    pfd.events = POLLIN
    pfd.revents = 0
    while poll(addr pfd, 1, 100) > 0:
      var buf = ""
      var src: string
      var srcPort: Port
      var n = 0
      try:
        n = sock.recvFrom(buf, PUNCH_MSG_BUFFER, src, srcPort)
      except CatchableError:
        break
      if n < PUNCH_PACKET_SIZE:
        continue
      var rp = createPunchPacket(PT_PUNCH, myPub, 0)
      try:
        rp = decodePunchPacket(buf[0 ..< n])
      except CatchableError:
        continue
      if not verifyPunchPacket(rp):
        echo "  (署名検証失敗のパケットを無視)"
        continue
      inc punchesRecv
      if rp.ptype == PT_PUNCH:
        var reply = createPunchPacket(PT_REPLY, myPub, rp.seq)
        signPunchPacket(key.privateKey, reply)
        try:
          sock.sendTo(parseIpAddress(src), srcPort, encodePunchPacket(reply))
        except CatchableError:
          discard
        echo "  受信: PUNCH from [" & src & "]:" & $srcPort &
             " -> REPLY 送信"
      elif rp.ptype == PT_REPLY:
        for sent in sentSeqToTime:
          if sent.seq == rp.seq:
            lastRtt = (epochTime() - sent.t0) * 1000.0
            inc roundTrips
            echo "  受信: REPLY seq=" & $rp.seq &
                 " RTT=" & lastRtt.formatFloat(ffDecimal, 1) & " ms (往復成功 x" &
                 $roundTrips & ")"
            break
      elif rp.ptype == PT_MSG:
        inc msgRecv
        echo "  受信: MSG from [" & src & "]:" & $srcPort & " = " & rp.payload
        var reply = createPunchPacket(PT_MSG, myPub, seqCounter)
        reply.payload = "Host->Android: Reply OK! 受信しました:「" & rp.payload & "」 (Fodpr v0.7)"
        signPunchPacket(key.privateKey, reply)
        try:
          sock.sendTo(parseIpAddress(src), srcPort, encodePunchPacket(reply))
          inc seqCounter
        except CatchableError:
          discard
        echo "  送信: MSG REPLY = " & reply.payload
      pfd.revents = 0
    sleep(120)

  sock.close()
  echo "----------------------------------------"
  echo "パンチ終了"
  echo "  送信パンチ : " & $punchesSent
  echo "  受信パケット: " & $punchesRecv
  echo "  往復成功   : " & $roundTrips & (if roundTrips > 0:
    " (最終RTT " & lastRtt.formatFloat(ffDecimal, 1) & " ms)" else: "")
  echo "  メッセージ受信: " & $msgRecv
  echo "  => " & (if roundTrips > 0: "ホールパンチ成功 (双方向通信確立)"
                  else: "往復不成立 (相手が起動しているか確認)")
  if roundTrips > 0:
    quit(0)
  else:
    quit(1)

when isMainModule:
  main()
