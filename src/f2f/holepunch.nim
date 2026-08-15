## holepunch.nim
## UDP ホールパンチング (NAT / ステートフルファイアウォール トラバーサル)
## ============================================================================
## ステートフルファイアウォール (例: Linux UFW) は「自ら送信したフローの応答」
## しか通過させない。そこで両ピアが同時に UDP パケットを送り合うことで、
## conntrack に双方向のフローエントリを作らせ、以降の双方向通信を成立させる。
##
## パケット書式 (最小 121 バイト):
##   "FPUN"(4) | version(1) | ptype(1) | seq(8, BE)
##   | sender(33, 圧縮公開鍵) | timestamp(8, BE, Unix ミリ秒)
##   | payloadLen(2, BE) | payload(0..65535) | signature(64, ECDSA)
## 署名対象 = "FPUN" 〜 payload までの全フィールド (signature を除く)。

import std/[net, times, endians, strutils, os, options]
from std/posix import TPollfd, POLLIN, poll

import ../crypto

const
  PUNCH_MAGIC* = "FPUN"
  PUNCH_VERSION* = 1'u8
  PUNCH_PACKET_SIZE* = 121   # payload なしの最小パケットサイズ

  # パンチ種別
  PT_PUNCH*     = 1'u8   # 双方向で送り合うパンチ
  PT_REPLY*     = 2'u8   # 受信したパンチへの応答 (相手の seq をエコー)
  PT_KEEPALIVE* = 3'u8   # 確立後のキープアライブ
  PT_MSG*       = 4'u8   # データメッセージ (payload に UTF-8 文字列)

  PUNCH_INTERVAL_MS* = 200      # パンチ送信間隔
  PUNCH_RECV_TIMEOUT_MS* = 600  # 1 ラウンドの受信待機時間
  PUNCH_MAX_ROUNDS* = 30        # 最大ラウンド数
  PUNCH_MSG_TIMEOUT_MS* = 3000  # メッセージ応答の待機時間
  PUNCH_MSG_BUFFER* = PUNCH_PACKET_SIZE + 4096  # メッセージ受信用バッファ

type
  PunchPacket* = object
    ptype*: uint8
    seq*: uint64
    sender*: SkPublicKey
    timestamp*: uint64      # Unix ミリ秒 (送信時点)
    payload*: string        # PT_MSG で使う UTF-8 メッセージ
    signature*: FodprSignature

  HolePunchResult* = object
    ok*: bool               # 往復 (RTT) が 1 回以上成立したか
    roundTrips*: int        # 成立した往復の回数
    punchesSent*: int       # 送信したパンチ数
    punchesRecv*: int       # 受信・検証成功したパケット数
    rttMs*: float           # 最後に成立した往復の RTT
    replyMsg*: string       # 相手から受信したメッセージ (PT_MSG 応答)
    err*: string

# ---------------------------------------------------------------------------
# パケットのエンコード / デコード / 署名
# ---------------------------------------------------------------------------

proc encodePunchSignedData(p: PunchPacket): string =
  ## magic | version | ptype | seq(8) | sender(33) | timestamp(8) | payloadLen(2) | payload
  result = PUNCH_MAGIC
  result.add(char(PUNCH_VERSION))
  result.add(char(p.ptype))
  var seqNet: uint64
  bigEndian64(addr seqNet, unsafeAddr p.seq)
  var seqBytes: array[8, byte]
  copyMem(addr seqBytes[0], addr seqNet, 8)
  for b in seqBytes: result.add(char(b))
  let pubRaw = p.sender.toRawCompressed()
  for b in pubRaw: result.add(char(b))
  var tsNet: uint64
  bigEndian64(addr tsNet, unsafeAddr p.timestamp)
  var tsBytes: array[8, byte]
  copyMem(addr tsBytes[0], addr tsNet, 8)
  for b in tsBytes: result.add(char(b))
  var pl = uint16(p.payload.len)
  var plNet: uint16
  bigEndian16(addr plNet, addr pl)
  var plBytes: array[2, byte]
  copyMem(addr plBytes[0], addr plNet, 2)
  result.add(char(plBytes[0]))
  result.add(char(plBytes[1]))
  result.add(p.payload)

proc createPunchPacket*(ptype: uint8, sender: SkPublicKey, seq: uint64): PunchPacket =
  PunchPacket(ptype: ptype, seq: seq, sender: sender,
              timestamp: uint64(epochTime() * 1000.0),
              payload: "",
              signature: emptySignature())

proc signPunchPacket*(priv: SkSecretKey, p: var PunchPacket) =
  ## 送信者秘密鍵でパケットに署名する。
  p.signature = signBytes(priv, encodePunchSignedData(p))

proc encodePunchPacket*(p: PunchPacket): string =
  ## 署名済みパケットを 119 バイトに直列化する。
  result = encodePunchSignedData(p)
  let sigRaw = p.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

proc verifyPunchPacket*(p: PunchPacket): bool =
  ## パケットの署名が sender 公開鍵で検証できるかを確認する。
  verifyBytes(p.sender, encodePunchSignedData(p), p.signature)

proc decodePunchPacket*(data: string): PunchPacket =
  ## 生バイト列を PunchPacket に復号する。形式不正は ValueError。
  if data.len < PUNCH_PACKET_SIZE:
    raise newException(ValueError, "short punch packet: " & $data.len)
  if data[0 ..< 4] != PUNCH_MAGIC:
    raise newException(ValueError, "bad punch magic")
  if byte(data[4]) != PUNCH_VERSION:
    raise newException(ValueError, "bad punch version: " & $byte(data[4]))
  var pubArr: array[33, byte]
  for i in 0 ..< 33: pubArr[i] = byte(data[14 + i])
  var p: PunchPacket = PunchPacket(ptype: byte(data[5]), seq: 0'u64,
                                   sender: parsePublicKey(pubArr),
                                   timestamp: 0'u64,
                                   payload: "",
                                   signature: emptySignature())
  var seqNet, seqVal: uint64
  copyMem(addr seqNet, unsafeAddr data[6], 8)
  bigEndian64(addr seqVal, addr seqNet)
  p.seq = seqVal
  var tsNet, tsVal: uint64
  copyMem(addr tsNet, unsafeAddr data[47], 8)
  bigEndian64(addr tsVal, addr tsNet)
  p.timestamp = tsVal
  var plNet, plLen: uint16
  copyMem(addr plNet, unsafeAddr data[55], 2)
  bigEndian16(addr plLen, addr plNet)
  let payloadStart = 57
  let sigStart = payloadStart + int(plLen)
  if sigStart + 64 != data.len:
    raise newException(ValueError,
      "bad punch packet size: header says " & $sigStart & " sig, got " & $data.len)
  if int(plLen) > 0:
    p.payload = data[payloadStart ..< sigStart]
  var sigArr: array[64, byte]
  for i in 0 ..< 64: sigArr[i] = byte(data[sigStart + i])
  p.signature = FodprSignature(sig: parseSignature(sigArr))
  result = p

# ---------------------------------------------------------------------------
# クライアント側ホールパンチ実行
# ---------------------------------------------------------------------------

proc tryParseIp(s: string): Option[IpAddress] =
  try:
    return some(parseIpAddress(s))
  except CatchableError:
    return none(IpAddress)

proc sendPunchPacket(sock: Socket, remoteHost: string, remotePort: int,
                     data: string) =
  let ip = tryParseIp(remoteHost)
  if ip.isSome:
    discard sock.sendTo(ip.get, Port(remotePort), data)
  else:
    sock.sendTo(remoteHost, Port(remotePort), data)

proc runHolePunch*(localPort: int, remoteHost: string, remotePort: int,
                   priv: SkSecretKey,
                   maxRounds: int = PUNCH_MAX_ROUNDS,
                   intervalMs: int = PUNCH_INTERVAL_MS,
                   recvTimeoutMs: int = PUNCH_RECV_TIMEOUT_MS,
                   sendMsg: string = "",
                   waitReplyMs: int = PUNCH_MSG_TIMEOUT_MS): HolePunchResult =
  ## UDP ソケットを localPort にバインドし、remote へパンチを送り続けて
  ## 相手からの「応答 (seq 一致)」が届くまで往復を試みる。
  ##
  ## 相手も同時にパンチを送ってくる想定 (相互ホールパンチ)。相手のファイア
  ## ウォールがステートフルでも、相手が先にこちらへ送ってきていれば、
  ## こちらの送信パケットは「応答」として通過し、往復が成立する。
  ##
  ## sendMsg が空でなければ、ホールが開いた後に PT_MSG を送信し、
  ## 相手の PT_MSG 応答を waitReplyMs ミリ秒まで待って replyMsg に格納する。
  var res: HolePunchResult
  var sock: Socket
  try:
    sock = newSocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    sock.setSockOpt(OptReuseAddr, true)
    sock.bindAddr(Port(localPort), "::")
  except CatchableError as e:
    res.err = "socket bind [" & $localPort & "] failed: " & e.msg
    return res

  let myPub = priv.toPublicKey()
  var sentSeqToTime: seq[tuple[seq: uint64, t0: float]]
  var round = 0'u64

  while res.roundTrips < 1 and round < uint64(maxRounds):
    # 1) パンチを送信
    var pkt = createPunchPacket(PT_PUNCH, myPub, round)
    signPunchPacket(priv, pkt)
    let outData = encodePunchPacket(pkt)
    try:
      sendPunchPacket(sock, remoteHost, remotePort, outData)
      inc res.punchesSent
      sentSeqToTime.add((seq: round, t0: epochTime()))
    except CatchableError as e:
      if res.err.len == 0: res.err = "send failed: " & e.msg
    inc round

    # 2) 受信待機 (recvTimeoutMs まで。poll を小刻みに)
    let deadline = epochTime() + recvTimeoutMs.float / 1000.0
    while epochTime() < deadline and res.roundTrips < 1:
      var pfd: TPollfd
      pfd.fd = cint(getFd(sock))
      pfd.events = POLLIN
      pfd.revents = 0
      if poll(addr pfd, 1, 100) <= 0:
        continue
      var buf = ""
      var src: string
      var srcPort: Port
      var n = 0
      try:
        n = sock.recvFrom(buf, PUNCH_MSG_BUFFER, src, srcPort)
      except CatchableError:
        continue
      if n < PUNCH_PACKET_SIZE:
        continue
      var rp = createPunchPacket(PT_PUNCH, myPub, 0)
      try:
        rp = decodePunchPacket(buf[0 ..< n])
      except CatchableError:
        continue
      if not verifyPunchPacket(rp):
        continue
      inc res.punchesRecv
      if rp.ptype == PT_PUNCH:
        # 相手からのパンチ → seq をエコーして応答を返す
        var reply = createPunchPacket(PT_REPLY, myPub, rp.seq)
        signPunchPacket(priv, reply)
        try:
          sendPunchPacket(sock, src, int(srcPort), encodePunchPacket(reply))
        except CatchableError:
          discard
      elif rp.ptype == PT_REPLY:
        # 応答の seq が自分の送信 seq に一致すれば往復成功
        for sent in sentSeqToTime:
          if sent.seq == rp.seq:
            res.rttMs = (epochTime() - sent.t0) * 1000.0
            inc res.roundTrips
            break
      elif rp.ptype == PT_MSG:
        res.replyMsg = rp.payload

    sleep(intervalMs)

  # 3) ホールが開いた後、メッセージを送信して応答を待つ
  if res.roundTrips >= 1 and sendMsg.len > 0 and res.replyMsg.len == 0:
    var m = createPunchPacket(PT_MSG, myPub, round)
    m.payload = sendMsg
    signPunchPacket(priv, m)
    try:
      sendPunchPacket(sock, remoteHost, remotePort, encodePunchPacket(m))
    except CatchableError as e:
      if res.err.len == 0: res.err = "msg send failed: " & e.msg
    let deadline = epochTime() + waitReplyMs.float / 1000.0
    while epochTime() < deadline and res.replyMsg.len == 0:
      var pfd: TPollfd
      pfd.fd = cint(getFd(sock))
      pfd.events = POLLIN
      pfd.revents = 0
      if poll(addr pfd, 1, 200) <= 0:
        continue
      var buf = ""
      var src: string
      var srcPort: Port
      var n = 0
      try:
        n = sock.recvFrom(buf, PUNCH_MSG_BUFFER, src, srcPort)
      except CatchableError:
        continue
      if n < PUNCH_PACKET_SIZE:
        continue
      var rp = createPunchPacket(PT_PUNCH, myPub, 0)
      try:
        rp = decodePunchPacket(buf[0 ..< n])
      except CatchableError:
        continue
      if not verifyPunchPacket(rp):
        continue
      if rp.ptype == PT_MSG:
        res.replyMsg = rp.payload
      elif rp.ptype == PT_PUNCH:
        # 穴の維持中に届いた相手からのパンチ → 応答を返す
        var reply = createPunchPacket(PT_REPLY, myPub, rp.seq)
        signPunchPacket(priv, reply)
        try:
          sendPunchPacket(sock, src, int(srcPort), encodePunchPacket(reply))
        except CatchableError:
          discard
    if res.replyMsg.len == 0 and res.err.len == 0:
      res.err = "no message reply within " & $waitReplyMs & " ms"

  sock.close()
  if res.roundTrips < 1 and res.err.len == 0:
    res.err = "no round trip within " & $maxRounds & " rounds"
  res.ok = res.roundTrips >= 1
  return res
