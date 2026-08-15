## mesh_client.nim
## F2F メッシュネットワーククライアント (複数ピア同時接続・メッセージ中継)
## ============================================================================
## 単一の UDP ソケットで複数のピアと同時に接続 (メッシュ) を維持し、
## 署名付きメッセージ (PT_MSG) をブロードキャスト / 中継する。
##
## - 全メッセージは Fodpr 署名付き (なりすまし・改ざん防止)
## - 中継は受信した生パケットをそのまま転送するため、発信元の署名が
##   エンドツーエンドで検証できる (中継ノードは中身を変えられない)
## - 重複抑制は (発信者公開鍵, seq) の既知セットで行う (ループ防止)
## - ピアへの生存確認は UDP パンチ (PT_PUNCH/PT_REPLY) を定期的に送る
##
## 使い方:
##   ./mesh_client [localPort] [peer1] [peer2] ...
##   ./mesh_client 8000 [240b:...:d4c0]:8000 [::1]:8001
##   ./mesh_client 8000 @peers.txt        # ピア一覧をファイルから読込
##
## ピア形式: "[ipv6]:port" / "ipv6" / "host:port" / "host"
##
## コマンド (標準入力):
##   msg <text>        全ピアへブロードキャスト
##   msgp <idx> <text> 指定ピアへ送信
##   add <host:port>   ピアを追加
##   list              ピア一覧・生存状態を表示
##   exit / quit       終了

import std/[net, times, strutils, os, options]
from std/posix import TPollfd, POLLIN, poll
import Fodpr

const
  DEFAULT_PORT* = 8000
  PUNCH_INTERVAL_MS = 2000    # ピアへのパンチ間隔 (穴の維持)
  PEER_TIMEOUT_S = 30.0       # この秒数応答が無ければ不達とみなす
  MAX_PEERS = 20              # 自動学習を含むピア数の上限
  SEEN_MAX = 1024             # 既知メッセージセットの上限

type
  Endpoint = tuple[host: string, port: int, ok: bool]

  MeshPeer = object
    host: string
    port: int
    pubkey: Option[SkPublicKey]
    alive: bool
    lastSeen: float
    lastPunch: float
    recvCount: int
    viaAutoLearn: bool

  MeshNode = object
    sock: Socket
    priv: SkSecretKey
    myPub: SkPublicKey
    peers: seq[MeshPeer]
    msgSeq: uint64
    seen: seq[tuple[key: string, ts: float]]

proc newMeshNode(priv: SkSecretKey, myPub: SkPublicKey): MeshNode =
  result = MeshNode(priv: priv, myPub: myPub, msgSeq: 1, peers: @[])

var gCmdChannel: Channel[string]

# ---------------------------------------------------------------------------
# ユーティリティ
# ---------------------------------------------------------------------------

proc parseEndpoint(s: string): Endpoint =
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

proc nowStr(): string =
  now().format("HH:mm:ss")

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
# ピア管理
# ---------------------------------------------------------------------------

proc findPeer(node: MeshNode, host: string, port: int): int =
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

proc addPeer(node: var MeshNode, host: string, port: int,
             viaAutoLearn: bool = false): bool =
  if node.peers.len >= MAX_PEERS:
    return false
  if findPeer(node, host, port) >= 0:
    return false
  node.peers.add(MeshPeer(host: host, port: port,
                          alive: false, lastSeen: 0.0, lastPunch: 0.0,
                          recvCount: 0, viaAutoLearn: viaAutoLearn))
  echo "[" & nowStr() & "] ピア追加: [" & host & "]:" & $port &
       (if viaAutoLearn: " (自動学習)" else: "")
  return true

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

proc broadcastMsg(node: var MeshNode, text: string) =
  var m = createPunchPacket(PT_MSG, node.myPub, node.msgSeq)
  inc node.msgSeq
  m.payload = text
  signPunchPacket(node.priv, m)
  let raw = encodePunchPacket(m)
  var sent = 0
  for i in 0 ..< node.peers.len:
    sendData(node.sock, node.peers[i].host, node.peers[i].port, raw)
    inc sent
  echo "[" & nowStr() & "] ブロードキャスト (送信 " & $sent & " ピア): " & text

proc sendMsgTo(node: var MeshNode, idx: int, text: string) =
  if idx < 0 or idx >= node.peers.len:
    echo "エラー: ピアインデックスが範囲外 (list で確認)"
    return
  var m = createPunchPacket(PT_MSG, node.myPub, node.msgSeq)
  inc node.msgSeq
  m.payload = text
  signPunchPacket(node.priv, m)
  let raw = encodePunchPacket(m)
  sendData(node.sock, node.peers[idx].host, node.peers[idx].port, raw)
  echo "[" & nowStr() & "] 送信 -> [" & node.peers[idx].host & "]:" &
       $node.peers[idx].port & ": " & text

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
    echo "[" & nowStr() & "] (署名検証失敗のパケットを無視)"
    return

  # --- ピアの生存記録 (エンドポイント一致 or 公開鍵一致) ---
  var idx = findPeer(node, srcHost, int(srcPort))
  if idx < 0:
    idx = findPeerByPub(node, rp.sender)
  if idx < 0:
    # 直接受信した未登録ピア → 自動学習
    if rp.ptype != PT_MSG and rp.sender.toRawCompressed() != node.myPub.toRawCompressed():
      if addPeer(node, srcHost, int(srcPort), viaAutoLearn = true):
        idx = node.peers.len - 1
  if idx >= 0:
    node.peers[idx].alive = true
    node.peers[idx].lastSeen = epochTime()
    inc node.peers[idx].recvCount
    if node.peers[idx].pubkey.isNone:
      node.peers[idx].pubkey = some(rp.sender)
    # 発信者が自分自身の公開鍵ならエコー (自分宛の反射) を無視対象にしない
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
        discard
      else:
        echo "[" & nowStr() & "] 受信 from [" & srcHost & "]:" & $srcPort &
             " : " & rp.payload
        if markSeen(node, rp):
          # 未見 → 他の全ピアへ中継 (元パケットをそのまま転送)
          var relayed = 0
          for j in 0 ..< node.peers.len:
            if j == idx: continue
            sendData(node.sock, node.peers[j].host, node.peers[j].port,
                     buf[0 ..< n])
            inc relayed
          if relayed > 0:
            echo "  -> 中継 (" & $relayed & " ピア)"
        else:
          echo "  -> 重複パケットのため中継をスキップ"
    else:
      discard
  else:
    # ピア未登録 (PT_MSG などで自動学習しないケース)
    if rp.ptype == PT_MSG and
       rp.sender.toRawCompressed() != node.myPub.toRawCompressed():
      echo "[" & nowStr() & "] 受信 (未登録ピア) : " & rp.payload

# ---------------------------------------------------------------------------
# コマンド処理 (標準入力)
# ---------------------------------------------------------------------------

proc handleCommand(node: var MeshNode, cmd: string) =
  let parts = cmd.splitWhitespace()
  if parts.len == 0: return
  case parts[0]
  of "msg":
    if parts.len < 2:
      echo "使い方: msg <テキスト>"
      return
    let text = cmd[parts[0].len .. ^1].strip()
    if node.peers.len == 0:
      echo "ピアが登録されていません (add <host:port> で追加)"
      return
    broadcastMsg(node, text)
  of "msgp":
    if parts.len < 3:
      echo "使い方: msgp <ピア番号> <テキスト>"
      return
    var idx = 0
    try:
      idx = parseInt(parts[1])
    except CatchableError:
      echo "ピア番号が不正です"
      return
    let text = cmd[len("msgp") + parts[1].len + 1 .. ^1].strip()
    sendMsgTo(node, idx, text)
  of "add":
    if parts.len < 2:
      echo "使い方: add <host:port>"
      return
    let ep = parseEndpoint(parts[1])
    if not ep.ok:
      echo "アドレス形式が不正です"
      return
    if not addPeer(node, ep.host, ep.port):
      echo "追加に失敗 (上限到達 or 重複)"
  of "list":
    echo "=== ピア一覧 (" & $node.peers.len & " 件) ==="
    for i, p in node.peers:
      let nowT = epochTime()
      let age = (if p.lastSeen > 0: nowT - p.lastSeen else: -1.0)
      let state = if p.alive and age >= 0 and age <= PEER_TIMEOUT_S: "生存"
                  else: "不達"
      let pub = (if p.pubkey.isSome: fpubEncode(p.pubkey.get)[0 ..< 12] & "..."
                 else: "(未取得)")
      echo "  [" & $i & "] " & state & " [" & p.host & "]:" & $p.port &
           " pub=" & pub & " 受信=" & $p.recvCount &
           " lastSeen=" & (if age >= 0: age.formatFloat(ffDecimal, 1) & "s前"
                           else: "-") &
           (if p.viaAutoLearn: " (自動学習)" else: "")
    echo "=============================="
  of "exit", "quit", "q":
    echo "終了します"
    gCmdChannel.send("__quit__")
  else:
    echo "不明なコマンド: " & parts[0]
    echo "コマンド: msg <text> / msgp <idx> <text> / add <host:port> / list / exit"

# ---------------------------------------------------------------------------
# 標準入力スレッド
# ---------------------------------------------------------------------------

proc stdinReader() {.thread.} =
  var line: string
  while true:
    if not readLine(stdin, line):
      break
    let s = line.strip()
    if s.len == 0: continue
    gCmdChannel.send(s)
  # EOF (Ctrl-D / パイプ終端) → 終了
  gCmdChannel.send("__quit__")

# ---------------------------------------------------------------------------
# メイン
# ---------------------------------------------------------------------------

proc main() =
  if paramCount() < 1:
    echo "usage: mesh_client [localPort] [peer1] [peer2] ..."
    echo "       mesh_client 8000 [240b:...]:8000 [::1]:8001"
    echo "       mesh_client 8000 @peers.txt"
    echo ""
    echo "コマンド: msg <text> / msgp <idx> <text> / add <host:port> / list / exit"
    quit(1)

  let key = generateFodprKey()
  var node = newMeshNode(key.privateKey, key.publicKey)

  var localPort = DEFAULT_PORT
  var argStart = 1
  try:
    localPort = parseInt(paramStr(1))
    argStart = 2
  except CatchableError:
    discard

  try:
    node.sock = newSocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    node.sock.setSockOpt(OptReuseAddr, true)
    node.sock.bindAddr(Port(localPort), "::")
  except CatchableError as e:
    echo "ERROR: bind [" & $localPort & "] 失敗: " & e.msg
    quit(1)

  # ピア登録 (引数 + @ファイル)
  for i in argStart .. paramCount():
    var entry = paramStr(i)
    if entry.startsWith("@"):
      let path = entry[1 .. ^1]
      try:
        for line in lines(path):
          let s = line.strip()
          if s.len == 0 or s.startsWith("#"): continue
          let ep = parseEndpoint(s)
          if ep.ok: discard addPeer(node, ep.host, ep.port)
      except CatchableError as e:
        echo "警告: ピアファイル読み込み失敗 (" & path & "): " & e.msg
      continue
    let ep = parseEndpoint(entry)
    if ep.ok:
      discard addPeer(node, ep.host, ep.port)
    else:
      echo "警告: 不正なピア形式: " & entry

  echo "=============================================="
  echo "F2F メッシュクライアント"
  echo "  ローカル: UDP [::]:" & $localPort
  echo "  公開鍵  : " & fpubEncode(node.myPub)
  echo "  ピア数  : " & $node.peers.len
  echo "  自分宛てに届いたメッセージは『反射』として表示されません"
  echo "=============================================="

  gCmdChannel.open(64)
  var reader: Thread[void]
  createThread(reader, stdinReader)

  var lastPunchTick = epochTime()
  while true:
    # --- 標準入力コマンド処理 ---
    while true:
      let r = gCmdChannel.tryRecv()
      if not r.dataAvailable: break
      if r.msg == "__quit__":
        echo "メッシュクライアントを終了します"
        node.sock.close()
        return
      handleCommand(node, r.msg)

    # --- ピア生存タイムアウト判定 ---
    let nowT = epochTime()
    for i in 0 ..< node.peers.len:
      if node.peers[i].alive and nowT - node.peers[i].lastSeen > PEER_TIMEOUT_S:
        node.peers[i].alive = false
        echo "[" & nowStr() & "] ピア [" & node.peers[i].host & "]:" &
             $node.peers[i].port & " が不達になりました"
      # --- 定期的なパンチ送信 (穴の維持) ---
      if nowT - node.peers[i].lastPunch > PUNCH_INTERVAL_MS.float / 1000.0:
        sendPunch(node, i)

    # --- 受信処理 ---
    var pfd: TPollfd
    pfd.fd = cint(getFd(node.sock))
    pfd.events = POLLIN
    pfd.revents = 0
    if poll(addr pfd, 1, 100) > 0:
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
    sleep(50)

when isMainModule:
  main()
