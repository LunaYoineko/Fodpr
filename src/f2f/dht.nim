## dht.nim
## F2F: Kademlia DHT (WebRTC データチャネル上)
##
## ピアの接続先 (IPv6 一時アドレス) を公開鍵から解決するための
## 分散ハッシュテーブル。ルーティングテーブルは 256-bit ノードID
## (nodeId = SHA-256(圧縮公開鍵)) の k-buckets で管理する。
##
## すべての RPC は確立済み WebRTC データチャネル (FodprData) 上で行う。
## DhtMessage は encodeDht でシリアライズし、先頭に MsgTypeDht (0x0B) /
## MsgTypeDhtNodes (0x8B) / MsgTypeDhtValue (0x8C) のいずれかを付与して
## FodprData.content に格納する。受信側は content の先頭バイトで判定して
## DHT ハンドラにルーティングする。

import asyncdispatch, times, tables, streams, strutils, sequtils, algorithm, options
import protocol, crypto, transport, nimSHA2

const
  K_BUCKET_SIZE = 20      # 各バケットの最大ノード数
  MIN_TRUST_DEFAULT = 0.0 # デフォルトの最小信頼スコア (WoT ゲート)
  DHT_RPC_TIMEOUT_MS = 5000
  # Adaptive keepalive settings
  MIN_PING_INTERVAL_MS* = 5000      # 最小PING間隔 (5秒)
  MAX_PING_INTERVAL_MS* = 60000     # 最大PING間隔 (1分)
  PING_SUCCESS_DECREASE* = 0.8      # 成功時の係数 (interval * この値)
  PING_FAILURE_INCREASE* = 1.5      # 失敗時の係数 (interval / この値の逆)
  PING_SUCCESS_THRESHOLD* = 3       # 連続成功でintervalを減衰
  PING_FAILURE_THRESHOLD* = 3       # 連続失敗でintervalを増大

type
  # Kademlia k-bucket
  KBucket* = object
    nodes*: seq[DhtNodeInfo]  # 最大 K_BUCKET_SIZE ノード (最新を末尾)
    lastUpdated*: uint64

  # ルーティングテーブル (256-bit ノードID 用)
  DhtRoutingTable* = object
    localNodeId*: array[32, byte]
    buckets*: seq[KBucket]    # 256 個 (localNodeId からの距離別)
    version*: uint64

  # DHT ノード本体
  DhtNode* = object
    localPriv*: SkSecretKey
    localPubkey*: SkPublicKey
    localNodeId*: array[32, byte]
    table*: DhtRoutingTable
    kvStore*: Table[string, string]   # keyHex -> value
    pendingMsgId*: array[16, byte]    # 乱数メッセージID カウンタ
    minTrust*: float                  # WoT ゲート用最小信頼スコア
    # Adaptive keepalive tracking
    pingSuccessCount*: int            # 連続PING成功回数
    pingFailureCount*: int            # 連続PING失敗回数
    currentPingInterval*: uint64     # 現在のPING間隔 (ms)
    lastPingTime*: uint64            # last PING送信時刻 (ms)

  # RPC 応答
  DhtResponse* = object
    msgId*: array[16, byte]
    ok*: bool
    nodes*: seq[DhtNodeInfo]
    value*: string

# カスタム例外
type
  DhtError* = object of CatchableError

# ---------------------------------------------------------------------------
# ノードID / 距離
# ---------------------------------------------------------------------------

# 公開鍵からノードIDを計算する: nodeId = SHA-256(圧縮公開鍵)
proc nodeId*(pub: SkPublicKey): array[32, byte] =
  let raw = pub.toRawCompressed()
  var buf = ""
  for b in raw: buf.add(char(b))
  result = array[32, byte](computeSHA256(buf))

# 32 バイトの ID を16進文字列に変換する (ストレージキー用)
proc idToHex*(id: array[32, byte]): string =
  result = ""
  for b in id:
    result.add(b.toHex(2).toLowerAscii)

# 2つのノードIDの XOR 距離の先頭ビット位置 (0..255) を返す。
# -1 は完全一致 (自分自身)。
proc bucketIndexFor*(a: array[32, byte], b: array[32, byte]): int =
  for i in 0..<32:
    let diff = byte(a[i] xor b[i])
    if diff != 0:
      # このバイト内の最上位セットビット
      var msb = 0
      var v = diff
      while v > 0:
        v = v shr 1
        msb += 1
      return (31 - i) * 8 + (8 - msb)
  return -1

# XOR 距離の辞書順比較用 (a と b の target からの距離を比較)
proc closerTo*(target, a, b: array[32, byte]): bool =
  for i in 0..<32:
    let da = byte(a[i] xor target[i])
    let db = byte(b[i] xor target[i])
    if da < db: return true
    if da > db: return false
  return false

# 空のルーティングテーブルを作成
proc newRoutingTable*(localNodeId: array[32, byte]): DhtRoutingTable =
  var buckets = newSeq[KBucket](256)
  for i in 0..<256:
    buckets[i] = KBucket(nodes: @[], lastUpdated: 0)
  result = DhtRoutingTable(
    localNodeId: localNodeId,
    buckets: buckets,
    version: 1
  )

# 新しい DHT ノードを作成
proc newDhtNode*(
  priv: SkSecretKey,
  minTrust: float = MIN_TRUST_DEFAULT
): DhtNode =
  let pub = priv.toPublicKey()
  let id = nodeId(pub)
  result = DhtNode(
    localPriv: priv,
    localPubkey: pub,
    localNodeId: id,
    table: newRoutingTable(id),
    kvStore: initTable[string, string](),
    pendingMsgId: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    minTrust: minTrust,
    pingSuccessCount: 0,
    pingFailureCount: 0,
    currentPingInterval: MIN_PING_INTERVAL_MS,
    lastPingTime: 0
  )

# ---------------------------------------------------------------------------
# ルーティングテーブル操作
# ---------------------------------------------------------------------------

# ノードをルーティングテーブルに追加する。WoT ゲートを適用し、
# minTrust 未満の新規ノードは拒否する (既知ノードは更新を許可)。
proc addNode*(
  node: var DhtNode,
  n: DhtNodeInfo,
  minTrust: float = MIN_TRUST_DEFAULT
): bool =
  if n.nodeId == node.localNodeId:
    return false

  let idx = bucketIndexFor(node.localNodeId, n.nodeId)
  if idx < 0:
    return false

  let now = uint64(epochTime())

  # 既知ノードなら lastSeen を更新して末尾へ移動
  var found = -1
  for i in 0..<node.table.buckets[idx].nodes.len:
    if node.table.buckets[idx].nodes[i].nodeId == n.nodeId:
      found = i
      break

  if found >= 0:
    node.table.buckets[idx].nodes[found].lastSeen = now
    let updated = node.table.buckets[idx].nodes[found]
    node.table.buckets[idx].nodes.delete(found)
    node.table.buckets[idx].nodes.add(updated)
    node.table.version += 1
    return true

  # 新規ノード: WoT ゲート
  if n.trustScore < minTrust:
    return false

  if node.table.buckets[idx].nodes.len >= K_BUCKET_SIZE:
    # 最古ノードを置き換える (LRU シンプル実装)
    node.table.buckets[idx].nodes.delete(0)
    node.table.buckets[idx].nodes.add(n)
  else:
    node.table.buckets[idx].nodes.add(n)
  node.table.buckets[idx].lastUpdated = now
  node.table.version += 1
  return true

# ターゲットから見て近い順に最大 count 個のノードを返す
proc findClosest*(
  node: DhtNode,
  targetId: array[32, byte],
  count: int = K_BUCKET_SIZE
): seq[DhtNodeInfo] =
  var all: seq[DhtNodeInfo] = @[]
  # 対象バケットを中心に両方向へ広げながら収集
  let center = bucketIndexFor(node.localNodeId, targetId)
  if center < 0:
    return @[]

  var checked = 0
  for dist in 0..255:
    var idx = center + dist
    if idx < 256:
      for n in node.table.buckets[idx].nodes:
        all.add(n)
        checked += 1
    idx = center - dist
    if idx >= 0:
      for n in node.table.buckets[idx].nodes:
        all.add(n)
        checked += 1
    if checked >= count:
      break

  # target からの距離でソート
  all.sort(proc(a, b: DhtNodeInfo): int =
    if closerTo(targetId, a.nodeId, b.nodeId): -1
    elif closerTo(targetId, b.nodeId, a.nodeId): 1
    else: 0
  )

  result = @[]
  for i in 0..<min(count, all.len):
    result.add(all[i])

# ルーティングテーブル内の全ノードを返す
proc allKnownNodes*(node: DhtNode): seq[DhtNodeInfo] =
  result = @[]
  for b in node.table.buckets:
    for n in b.nodes:
      result.add(n)

# ---------------------------------------------------------------------------
# RPC 送信
# ---------------------------------------------------------------------------

# 次に使う msgId を返し、内部カウンタを進める
proc nextMsgId*(node: var DhtNode): array[16, byte] =
  for i in countdown(15, 0):
    node.pendingMsgId[i] = node.pendingMsgId[i] + 1
    if node.pendingMsgId[i] != 0:
      break
  result = node.pendingMsgId

# DHT RPC をデータチャネル経由で送信する (FodprData.content に格納)。
# msgType は応答種別 (MsgTypeDht / MsgTypeDhtNodes / MsgTypeDhtValue) の
# いずれか。FodprData の署名は DhtMessage の署名とは独立。
proc sendDhtRpc*(
  node: DhtNode,
  conn: var F2FConnection,
  msg: DhtMessage,
  msgType: char
): Future[bool] {.async.} =
  var signed = msg
  signed.sender = node.localPubkey
  signed.signature = signDht(node.localPriv, signed)

  let body = encodeDht(signed)
  var content = ""
  content.add(msgType)
  content.add(body)

  return await sendF2FData(conn, node.localPriv, content, @["type:dht"])

# PING: ノードの生存確認
proc sendPing*(
  node: var DhtNode,
  conn: var F2FConnection
): Future[bool] {.async.} =
  var now = uint64(epochTime())
  # Adaptive interval: only send if enough time has passed
  if node.lastPingTime > 0 and (now - node.lastPingTime) < node.currentPingInterval:
    # not yet time for next PING - skip, return success (no-op)
    return Promise(true)
  
  var msg = DhtMessage(
    op: DhtOpPing,
    msgId: nextMsgId(node),
    key: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    sender: node.localPubkey,
    signature: emptySignature()
  )
  let result = await sendDhtRpc(node, conn, msg, MsgTypeDht)
  node.lastPingTime = now
  return result

# PING失敗時のフォールバック呼び出し (handleDhtMessage 内から呼ばれる)
proc onPingFailed*(node: var DhtNode) =
  updatePingInterval(node, false)

# PING間隔の適応的更新
proc updatePingInterval*(node: var DhtNode, success: bool) {.async.} =
  if success:
    node.pingSuccessCount += 1
    node.pingFailureCount = 0
    # 連続成功: インターバルをわずかに減衰 (最小値へ)
    if node.pingSuccessCount >= PING_SUCCESS_THRESHOLD:
      node.currentPingInterval = max(
        MIN_PING_INTERVAL_MS,
        cast[uint64](cast[float](node.currentPingInterval) * PING_SUCCESS_DECREASE)
      )
      node.pingSuccessCount = 0
  else:
    node.pingFailureCount += 1
    node.pingSuccessCount = 0
    # 連続失敗: インターバルを増大 (最大値まで)
    if node.pingFailureCount >= PING_FAILURE_THRESHOLD:
      node.currentPingInterval = min(
        MAX_PING_INTERVAL_MS,
        cast[uint64](cast[float](node.currentPingInterval) * PING_FAILURE_INCREASE)
      )
      node.pingFailureCount = 0

# FIND_NODE: ターゲットノードIDに近いノードを探索
proc sendFindNode*(
  node: var DhtNode,
  conn: var F2FConnection,
  targetId: array[32, byte]
): Future[bool] {.async.} =
  var msg = DhtMessage(
    op: DhtOpFindNode,
    msgId: nextMsgId(node),
    key: targetId,
    sender: node.localPubkey,
    signature: emptySignature()
  )
  return await sendDhtRpc(node, conn, msg, MsgTypeDht)

# FIND_VALUE: キーに対応する値 (接続先情報) を取得
proc sendFindValue*(
  node: var DhtNode,
  conn: var F2FConnection,
  key: array[32, byte]
): Future[bool] {.async.} =
  var msg = DhtMessage(
    op: DhtOpFindValue,
    msgId: nextMsgId(node),
    key: key,
    sender: node.localPubkey,
    signature: emptySignature()
  )
  return await sendDhtRpc(node, conn, msg, MsgTypeDht)

# STORE: キーに対応する値 (接続先情報) を保存
proc sendStore*(
  node: var DhtNode,
  conn: var F2FConnection,
  key: array[32, byte],
  value: string
): Future[bool] {.async.} =
  var msg = DhtMessage(
    op: DhtOpStore,
    msgId: nextMsgId(node),
    key: key,
    value: value,
    sender: node.localPubkey,
    signature: emptySignature()
  )
  return await sendDhtRpc(node, conn, msg, MsgTypeDht)

# ---------------------------------------------------------------------------
# RPC 受信・応答
# ---------------------------------------------------------------------------

# DhtMessage を検証し、FIND_NODE / FIND_VALUE / STORE の場合は
# 自ノードの情報と近傍ノードを使って応答を返す。
proc handleDhtMessage*(
  node: var DhtNode,
  msg: DhtMessage,
  conn: var F2FConnection
): Future[DhtResponse] {.async.} =
  # 署名検証
  if not verifyDht(msg):
    echo "DHT message signature verification failed"
    return DhtResponse(msgId: msg.msgId, ok: false)

  # 送信元ノードをルーティングテーブルに追加
  let peerNode = DhtNodeInfo(
    nodeId: nodeId(msg.sender),
    pubkey: msg.sender,
    addresses: @[],
    lastSeen: uint64(epochTime()),
    trustScore: node.minTrust
  )
  discard addNode(node, peerNode, node.minTrust)

  case msg.op
  of DhtOpPing:
    # PONG 応答 (自分のノード情報を添える)
    let selfInfo = DhtNodeInfo(
      nodeId: node.localNodeId,
      pubkey: node.localPubkey,
      addresses: @[],
      lastSeen: uint64(epochTime()),
      trustScore: 1.0
    )
    var pong = DhtMessage(
      op: DhtOpPong,
      msgId: msg.msgId,
      key: msg.key,
      nodes: @[selfInfo],
      sender: node.localPubkey,
      signature: emptySignature()
    )
    discard await sendDhtRpc(node, conn, pong, MsgTypeDhtNodes)
    return DhtResponse(msgId: msg.msgId, ok: true, nodes: @[selfInfo])

  of DhtOpFindNode:
    # 近傍ノードを応答
    let closest = findClosest(node, msg.key, K_BUCKET_SIZE)
    var resp = DhtMessage(
      op: DhtOpFindNode,
      msgId: msg.msgId,
      key: msg.key,
      nodes: closest,
      sender: node.localPubkey,
      signature: emptySignature()
    )
    discard await sendDhtRpc(node, conn, resp, MsgTypeDhtNodes)
    return DhtResponse(msgId: msg.msgId, ok: true, nodes: closest)

  of DhtOpFindValue:
    let keyHex = idToHex(msg.key)
    if node.kvStore.hasKey(keyHex):
      # 値ヒット → MsgTypeDhtValue
      var resp = DhtMessage(
        op: DhtOpFindValue,
        msgId: msg.msgId,
        key: msg.key,
        value: node.kvStore[keyHex],
        sender: node.localPubkey,
        signature: emptySignature()
      )
      discard await sendDhtRpc(node, conn, resp, MsgTypeDhtValue)
      return DhtResponse(msgId: msg.msgId, ok: true, value: node.kvStore[keyHex])
    else:
      # 非ヒット → 近傍ノードを応答
      let closest = findClosest(node, msg.key, K_BUCKET_SIZE)
      var resp = DhtMessage(
        op: DhtOpFindNode,
        msgId: msg.msgId,
        key: msg.key,
        nodes: closest,
        sender: node.localPubkey,
        signature: emptySignature()
      )
      discard await sendDhtRpc(node, conn, resp, MsgTypeDhtNodes)
      return DhtResponse(msgId: msg.msgId, ok: true, nodes: closest)

  of DhtOpStore:
    # キーに対応する値を保存 (max サイズ制限付き)
    if msg.value.len <= 4096:
      node.kvStore[idToHex(msg.key)] = msg.value
    var resp = DhtMessage(
      op: DhtOpStore,
      msgId: msg.msgId,
      key: msg.key,
      sender: node.localPubkey,
      signature: emptySignature()
    )
    discard await sendDhtRpc(node, conn, resp, MsgTypeDhtValue)
    return DhtResponse(msgId: msg.msgId, ok: true)

  else:
    echo "Unknown DHT op: ", msg.op
    return DhtResponse(msgId: msg.msgId, ok: false)

# データチャネル受信バイト列から DHT メッセージを抽出する。
# content の先頭バイトが DHT 種別なら DhtMessage を返す。
proc extractDhtMessage*(content: string): Option[DhtMessage] =
  if content.len < 2:
    return none(DhtMessage)
  let mt = byte(content[0])
  if mt != byte(MsgTypeDht) and mt != byte(MsgTypeDhtNodes) and
     mt != byte(MsgTypeDhtValue):
    return none(DhtMessage)
  var strm = newStringStream(content[1..^1])
  try:
    return some(decodeDht(strm))
  except CatchableError as e:
    echo "DHT decode failed: ", e.msg
    return none(DhtMessage)

# DHT ノードを別ノードのルーティングテーブルへシードする
# (ブートストラップ用: 接続先ノードを k-buckets に追加)
proc seedNodes*(
  node: var DhtNode,
  seeds: seq[DhtNodeInfo]
) =
  for s in seeds:
    discard addNode(node, s, node.minTrust)
