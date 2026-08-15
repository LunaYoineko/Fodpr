## mesh.nim
## F2F メッシュネットワークライブラリ
## ==================================================================
## 単一の UDP ソケットで複数のピアと同時に接続 (メッシュ) を維持し、
## 署名付きメッセージ (PT_MSG) をブロードキャスト / 中継する。
##
## - 全メッセージは Fodpr 署名付き (なりすまし・改ざん防止)
## - 中継は受信した生パケットをそのまま転送するため、発信元の署名が
##   エンドツーエンドで検証できる (中継ノードは中身を変えられない)
## - 重複抑制は (発信者公開鍵, seq) の既知セットで行う (ループ防止)
## - ピアへの生存確認は UDP パンチ (PT_PUNCH/PT_REPLY) を定期的に送る
## - イベント駆動: stepMesh() が受信イベント (メッセージ/ピア追加/喪失) を返す
##
## 使い方:
##   var node = newMeshNode(priv, pub, 8000)
##   discard addPeer(node, "::1", 8001)
##   sendBroadcast(node, "hello")
##   while true:
##     for ev in stepMesh(node, 100):
##       case ev.kind ...

import std/[net, times, strutils, options]
from std/posix import TPollfd, POLLIN, poll
import Fodpr

const
  DEFAULT_PORT* = 8000        # 既定のチャット/メッシュポート
  PUNCH_INTERVAL_MS* = 2000   # ピアへのパンチ間隔 (穴の維持)
  PEER_TIMEOUT_S* = 30.0      # この秒数応答が無ければ不達とみなす
  MAX_PEERS* = 20             # 自動学習を含むピア数の上限
  SEEN_MAX* = 1024            # 既知メッセージセットの上限

type
  Endpoint* = tuple[host: string, port: int, ok: bool]

  MeshPeer* = object
    host*: string
    port*: int
    pubkey*: Option[SkPublicKey]
    alive*: bool
    lastSeen*: float
    lastPunch*: float
    recvCount*: int
    viaAutoLearn*: bool

  MeshEventKind* = enum
    mePeerAdded   # ピアが登録された (自動学習含む)
    mePeerLost    # ピアが不達になった
    meMsg         # メッセージ受信 (中継含む)
    meMsgSelf     # 自分が送ったメッセージの反射 (通常は表示不要)

  MeshEvent* = object
    kind*: MeshEventKind
    peerIdx*: int                 # 送信元ピアのインデックス (-1 あり)
    srcHost*: string
    srcPort*: int
    sender*: Option[SkPublicKey]  # 発信者 (E2E 署名、メッセージ時のみ some)
    payload*: string
    autoLearned*: bool            # mePeerAdded: 自動学習による追加か

  MeshNode* = object
    sock*: Socket
    priv*: SkSecretKey
    myPub*: SkPublicKey
    myPort*: int
    peers*: seq[MeshPeer]
    msgSeq*: uint64
    seen*: seq[tuple[key: string, ts: float]]
    events*: seq[MeshEvent]

# ---------------------------------------------------------------------------
# ユーティリティ
# ---------------------------------------------------------------------------

proc parseEndpoint*(s: string): Endpoint =
  ## "[ipv6]:port" / "[ipv6]" / "ipv6" / "host:port" / "host" 形式をパースする。
  var str = s.strip()
  if str.len == 0 or str.contains("://"):
    return ("", 0, false)
  if str.startsWith("["):
    let close = str.find(']')
    if close < 0: return ("", 0, false)
    let host = str[1 ..< close]
    if close + 1 < str.len:
      if str[close + 1] != ':': return ("", 0, false)
      try:
        return (host, parseInt(str[close + 2 .. ^1]), true)
      except CatchableError:
        return ("", 0, false)
    return (host, DEFAULT_PORT, true)
  if str.count(':') >= 2:
    return (str, DEFAULT_PORT, true)
  let sep = str.find(':')
  if sep > 0:
    try:
      return (str[0 ..< sep], parseInt(str[sep + 1 .. ^1]), true)
    except CatchableError:
      return ("", 0, false)
  return (str, DEFAULT_PORT, true)

proc sameIp(a, b: string): bool =
  try:
    return $parseIpAddress(a) == $parseIpAddress(b)
  except CatchableError:
    return a == b

proc sendData(sock: Socket, host: string, port: int, data: string) =
  try:
    sock.sendTo(parseIpAddress(host), Port(port), data)
  except CatchableError:
    try:
      sock.sendTo(host, Port(port), data)
    except CatchableError:
      discard

proc sendDataTo(sock: Socket, host: string, port: Port, data: string) =
  try:
    sock.sendTo(parseIpAddress(host), port, data)
  except CatchableError:
    discard

# ---------------------------------------------------------------------------
# ノード生成
# ---------------------------------------------------------------------------

proc newMeshNode*(priv: SkSecretKey, myPub: SkPublicKey,
                  localPort: int = DEFAULT_PORT): MeshNode =
  ## UDP ソケットを生成・バインドする。失敗時は例外を送出する。
  result = MeshNode(priv: priv, myPub: myPub, myPort: localPort,
                    msgSeq: 1, peers: @[], seen: @[], events: @[])
  result.sock = newSocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
  result.sock.setSockOpt(OptReuseAddr, true)
  result.sock.bindAddr(Port(localPort), "::")

proc closeMesh*(node: var MeshNode) =
  try:
    node.sock.close()
  except CatchableError:
    discard

proc isPeerAlive*(peer: MeshPeer, nowT: float = epochTime()): bool =
  peer.alive and nowT - peer.lastSeen <= PEER_TIMEOUT_S

proc countAlive*(node: MeshNode): int =
  for p in node.peers:
    if isPeerAlive(p):
      inc result

# ---------------------------------------------------------------------------
# ピア管理
# ---------------------------------------------------------------------------

proc findPeerIdx*(node: MeshNode, host: string, port: int): int =
  for i in 0 ..< node.peers.len:
    if node.peers[i].port == port and sameIp(node.peers[i].host, host):
      return i
  return -1

proc findPeerByPub(node: MeshNode, pub: SkPublicKey): int =
  for i in 0 ..< node.peers.len:
    if node.peers[i].pubkey.isSome and
       node.peers[i].pubkey.get.toRawCompressed() == pub.toRawCompressed():
      return i
  return -1

proc addPeer*(node: var MeshNode, host: string, port: int,
              viaAutoLearn: bool = false): int =
  ## ピアを追加する。成功時はインデックス、失敗時は -1 を返す。
  if node.peers.len >= MAX_PEERS:
    return -1
  if findPeerIdx(node, host, port) >= 0:
    return -1
  node.peers.add(MeshPeer(host: host, port: port,
                          alive: false, lastSeen: 0.0, lastPunch: 0.0,
                          recvCount: 0, viaAutoLearn: viaAutoLearn))
  let idx = node.peers.len - 1
  node.events.add(MeshEvent(kind: mePeerAdded, peerIdx: idx,
                            srcHost: host, srcPort: port,
                            autoLearned: viaAutoLearn))
  return idx

proc markSeen(node: var MeshNode, p: PunchPacket): bool =
  ## (発信者, seq) が未見なら追加して true。既知なら false。
  var key = newStringOfCap(41)
  for b in p.sender.toRawCompressed():
    key.add(char(b))
  for shift in countdown(56, 0, 8):
    key.add(char(byte((p.seq shr shift) and 0xff)))
  for e in node.seen:
    if e.key == key:
      return false
  node.seen.add((key: key, ts: epochTime()))
  if node.seen.len > SEEN_MAX:
    node.seen.delete(0)
  return true

# ---------------------------------------------------------------------------
# パケット送信
# ---------------------------------------------------------------------------

proc sendPunch(node: var MeshNode, idx: int) =
  var pkt = createPunchPacket(PT_PUNCH, node.myPub, node.msgSeq)
  signPunchPacket(node.priv, pkt)
  inc node.msgSeq
  sendData(node.sock, node.peers[idx].host, node.peers[idx].port,
           encodePunchPacket(pkt))
  node.peers[idx].lastPunch = epochTime()

proc sendBroadcast*(node: var MeshNode, text: string) =
  ## 全ピアへ署名付きメッセージをブロードキャストする。
  var m = createPunchPacket(PT_MSG, node.myPub, node.msgSeq)
  inc node.msgSeq
  m.payload = text
  signPunchPacket(node.priv, m)
  let raw = encodePunchPacket(m)
  for i in 0 ..< node.peers.len:
    sendData(node.sock, node.peers[i].host, node.peers[i].port, raw)

proc sendMsgTo*(node: var MeshNode, idx: int, text: string) =
  ## 指定ピアへ署名付きメッセージを送信する。
  if idx < 0 or idx >= node.peers.len:
    return
  var m = createPunchPacket(PT_MSG, node.myPub, node.msgSeq)
  inc node.msgSeq
  m.payload = text
  signPunchPacket(node.priv, m)
  let raw = encodePunchPacket(m)
  sendData(node.sock, node.peers[idx].host, node.peers[idx].port, raw)

# ---------------------------------------------------------------------------
# 受信パケット処理
# ---------------------------------------------------------------------------

proc handlePacket(node: var MeshNode, buf: string, n: int,
                  srcHost: string, srcPort: Port) =
  if n < PUNCH_PACKET_SIZE:
    return
  var rp = createPunchPacket(PT_PUNCH, node.myPub, 0)
  try:
    rp = decodePunchPacket(buf[0 ..< n])
  except CatchableError:
    return
  if not verifyPunchPacket(rp):
    return

  # --- ピアの生存記録 (エンドポイント一致 or 公開鍵一致) ---
  var idx = findPeerIdx(node, srcHost, int(srcPort))
  if idx < 0:
    idx = findPeerByPub(node, rp.sender)
  if idx < 0:
    # 直接受信した未登録ピア → 自動学習
    if rp.ptype != PT_MSG and rp.sender.toRawCompressed() != node.myPub.toRawCompressed():
      idx = addPeer(node, srcHost, int(srcPort), viaAutoLearn = true)
  if idx >= 0:
    node.peers[idx].alive = true
    node.peers[idx].lastSeen = epochTime()
    inc node.peers[idx].recvCount
    if node.peers[idx].pubkey.isNone:
      node.peers[idx].pubkey = some(rp.sender)
    let fromMe = rp.sender.toRawCompressed() == node.myPub.toRawCompressed()

    case rp.ptype
    of PT_PUNCH:
      var reply = createPunchPacket(PT_REPLY, node.myPub, rp.seq)
      signPunchPacket(node.priv, reply)
      sendDataTo(node.sock, srcHost, srcPort, encodePunchPacket(reply))
    of PT_REPLY, PT_KEEPALIVE:
      discard
    of PT_MSG:
      if fromMe:
        node.events.add(MeshEvent(kind: meMsgSelf, peerIdx: idx,
                                  srcHost: srcHost, srcPort: int(srcPort),
                                  sender: some(rp.sender), payload: rp.payload))
      else:
        node.events.add(MeshEvent(kind: meMsg, peerIdx: idx,
                                  srcHost: srcHost, srcPort: int(srcPort),
                                  sender: some(rp.sender), payload: rp.payload))
        if markSeen(node, rp):
          # 未見 → 他の全ピアへ中継 (元パケットをそのまま転送)
          for j in 0 ..< node.peers.len:
            if j == idx: continue
            sendData(node.sock, node.peers[j].host, node.peers[j].port,
                     buf[0 ..< n])
    else:
      discard

# ---------------------------------------------------------------------------
# メインループの1ステップ
# ---------------------------------------------------------------------------

proc stepMesh*(node: var MeshNode, timeoutMs: int = 100): seq[MeshEvent] =
  ## ピアの生存管理・定期パンチ・受信処理を実行し、発生したイベントを返す。
  ## 呼び出し後に node.events はクリアされる。
  result = node.events
  node.events = @[]

  let nowT = epochTime()
  for i in 0 ..< node.peers.len:
    # タイムアウト判定
    if node.peers[i].alive and nowT - node.peers[i].lastSeen > PEER_TIMEOUT_S:
      node.peers[i].alive = false
      result.add(MeshEvent(kind: mePeerLost, peerIdx: i,
                           srcHost: node.peers[i].host,
                           srcPort: node.peers[i].port))
    # 定期的なパンチ送信 (穴の維持)
    if nowT - node.peers[i].lastPunch > PUNCH_INTERVAL_MS.float / 1000.0:
      sendPunch(node, i)

  # 受信処理
  var pfd: TPollfd
  pfd.fd = cint(getFd(node.sock))
  pfd.events = POLLIN
  pfd.revents = 0
  if poll(addr pfd, 1, cint(timeoutMs)) > 0:
    var buf = ""
    var srcHost: string
    var srcPort: Port
    var n = 0
    try:
      n = node.sock.recvFrom(buf, PUNCH_MSG_BUFFER, srcHost, srcPort)
    except CatchableError:
      n = 0
    if n > 0:
      handlePacket(node, buf, n, srcHost, srcPort)
