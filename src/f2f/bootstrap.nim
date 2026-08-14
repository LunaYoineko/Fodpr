## bootstrap.nim
## F2F: シードリレー・フォールバックモジュール (最終手段)
##
## インビテーションも失敗し、キャッシュ全滅時のみ発動する
## 「迷子を救うための非常口」としてのシードリレー機能。

import asyncdispatch, ws, json, strutils, sequtils, times
import protocol, crypto, peer_cache, transport

const
  DEFAULT_SEED_RELAYS* = @[
    "wss://seed1.fodpr.example.com/",
    "wss://seed2.fodpr.example.com/"
  ]

  SEED_TIMEOUT_MS = 10000  # 10秒でタイムアウト
  MAX_SEED_NODES* = 50

type
  SeedNode* = object
    pubkey*: SkPublicKey
    addresses*: seq[string]

  SeedList* = object
    version*: uint64
    nodes*: seq[SeedNode]
    signature*: FodprSignature  # シードサーバーの署名

# カスタム例外
type
  BootstrapError* = object of CatchableError

# ---------------------------------------------------------------------------
# 内部ヘルパー
# ---------------------------------------------------------------------------

proc parseSeedNode(node: JsonNode): SeedNode =
  let
    pubkey = fpubDecode(node["pubkey"].getStr())
    addresses = node["addresses"].mapIt(it.getStr())
  return SeedNode(pubkey: pubkey, addresses: addresses)

proc seedNodeToJson*(node: SeedNode): JsonNode =
  %*{
    "pubkey": fpubEncode(node.pubkey),
    "addresses": node.addresses.mapIt(%* it)
  }

# ---------------------------------------------------------------------------
# 公開 API
# ---------------------------------------------------------------------------

# 指定されたシードリレーからシードノードリストを取得
proc bootstrapFromSeed*(seedUrl: string): Future[seq[SeedNode]] {.async.} =
  var ws: WebSocket
  try:
    ws = await newWebSocket(seedUrl)
  except:
    raise newException(BootstrapError, "Failed to connect to seed relay: " & seedUrl)

  # シード要求送信 (カスタムメッセージ)
  let req = %*{
    "type": "seed_request",
    "max_nodes": MAX_SEED_NODES
  }
  await ws.send($req, Text)

  # レスポンス受信
  var response: string
  try:
    response = await ws.receiveStrPacket()
  except:
    raise newException(BootstrapError, "Timeout or error receiving seed response")

  ws.close()

  # JSONパース
  let doc = parseJson(response)
  if doc["type"].getStr() != "seed_response":
    raise newException(BootstrapError, "Invalid seed response type")

  result = newSeq[SeedNode]()
  for node in doc["nodes"]:
    result.add(parseSeedNode(node))

# 複数のシードリレーを順番に試行し、最初に成功したものを返す
proc tryBootstrapFromSeeds*(seedUrls: seq[string] = DEFAULT_SEED_RELAYS): Future[seq[SeedNode]] {.async.} =
  for url in seedUrls:
    try:
      let nodes = await bootstrapFromSeed(url)
      if nodes.len > 0:
        return nodes
    except Exception as e:
      echo "Seed relay ", url, " failed: ", e.msg
      continue

  raise newException(BootstrapError, "All seed relays failed")

# フォールバック用: キャッシュが全滅した時にシードから復旧を試みる
proc fallbackToSeed*(cache: PeerCache): Future[seq[SeedNode]] {.async.} =
  if not isCacheStaleOrEmpty(cache):
    # キャッシュがまだ有効ならフォールバックしない
    return @[]

  echo "Cache is empty or stale. Initiating seed fallback..."
  return await tryBootstrapFromSeeds()

# シードノードリストを PeerInfo リストに変換 (キャッシュ更新用)
proc seedNodesToPeerInfo*(nodes: seq[SeedNode]): seq[PeerInfo] =
  result = newSeq[PeerInfo](nodes.len)
  let now = uint64(epochTime())
  for i, node in nodes:
    result[i] = PeerInfo(
      pubkey: node.pubkey,
      addresses: node.addresses,
      lastSeen: now,
      reliabilityScore: 0.0  # 新規ピアは常にスコア0.0から開始
    )

# 空の PeerInfo を作成 (スタブ用)
proc emptyPeerInfo*(): PeerInfo =
  # ダミーの公開鍵 (実際には使われない)
  var zeroPub: array[33, byte]
  for i in 0..<33: zeroPub[i] = 0
  let dummyPub = parsePublicKey(zeroPub)
  return PeerInfo(
    pubkey: dummyPub,
    addresses: @[],
    lastSeen: 0,
    reliabilityScore: 0.0
  )

# 空の WebRTCDataChannel を作成 (スタブ用)
proc emptyDataChannel*(): WebRTCDataChannel =
  return WebRTCDataChannel(
    label: "",
    ordered: true,
    maxRetransmits: 0,
    onOpen: nil,
    onClose: nil,
    onMessage: nil,
    onError: nil
  )

# シードノードへの並列ダイアル試行
# 最初に成功した接続を返す
proc dialSeedNodes*(
  nodes: seq[SeedNode],
  localPriv: SkSecretKey,
  dialTimeoutMs: int = 5000
): Future[tuple[success: bool, peer: PeerInfo, conn: WebRTCDataChannel]] {.async.} =
  # 実際の実装では WebRTC 接続を行う
  # ここではスタブとして最初のノードを返す
  if nodes.len == 0:
    return (false, emptyPeerInfo(), emptyDataChannel())

  # 並列で接続試行 (簡易版: 順番に試行)
  for node in nodes:
    for addr in node.addresses:
      try:
        # ここで WebRTC 接続を確立
        # 成功したら PeerInfo と DataChannel を返す
        echo "Dialing seed node: ", addr
        # 実装は transport.nim で行う
      except:
        continue

  return (false, emptyPeerInfo(), emptyDataChannel())

# シードリスト取得・WoT参加の統合フロー
proc bootstrapAndJoin*(
  seedUrls: seq[string] = DEFAULT_SEED_RELAYS
): Future[tuple[success: bool, cache: PeerCache, seedNodes: seq[SeedNode]]] {.async.} =
  try:
    let seedNodes = await tryBootstrapFromSeeds(seedUrls)
    if seedNodes.len == 0:
      return (false, PeerCache(), @[])

    # シードノードを PeerInfo に変換
    let peerInfos = seedNodesToPeerInfo(seedNodes)

    # 新しいキャッシュ作成
    var cache = PeerCache(
      version: 1,
      peers: peerInfos,
      lastUpdated: uint64(epochTime())
    )

    # 最初の数ノードへ接続試行して WoT リスト取得
    # 実際の実装ではここで transport.nim を使って P2P 接続
    # 成功したら WoT から最新ピアリストを取得してキャッシュ更新

    return (true, cache, seedNodes)
  except Exception as e:
    echo "Bootstrap failed: ", e.msg
    return (false, PeerCache(), @[])