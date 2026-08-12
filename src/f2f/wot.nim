## wot.nim
## F2F: Web of Trust (WoT) 構築・管理モジュール
##
## 信頼の連鎖 (信頼スコア、紹介関係) を管理し、
## シビル耐性を提供する。

import protocol, crypto, peer_cache, discovery, tables, algorithm, times, options, sets, json

type
  TrustEdge* = object
    fromPub*: SkPublicKey    # 紹介者/信頼する側
    to*: SkPublicKey      # 紹介される/信頼される側
    score*: float         # 信頼度 (0.0-1.0)
    createdAt*: uint64    # 紹介時刻

  WoTGraph* = object
    nodes*: seq[SkPublicKey]           # 全ノード
    edges*: seq[TrustEdge]             # 信頼のエッジ
    trustScores*: Table[SkPublicKey, float]  # ノードごとの総合信頼スコア
    version*: uint64                   # グラフバージョン

  WoTPath* = object
    hops*: seq[SkPublicKey]  # 経路 (自分 -> ... -> 目標)
    score*: float            # 経路の信頼度 (最小エッジスコア)

# ---------------------------------------------------------------------------
# 公開 API
# ---------------------------------------------------------------------------

# 空の WoT グラフを作成
proc newWoTGraph*(): WoTGraph =
  result = WoTGraph(
    nodes: @[],
    edges: @[],
    trustScores: initTable[SkPublicKey, float](),
    version: 1
  )

# ピアキャッシュから WoT グラフを構築
proc buildWoTFromCache*(cache: PeerCache): WoTGraph =
  var graph = newWoTGraph()

  # 全ピアをノードとして追加
  for p in cache.peers:
    graph.nodes.add(p.pubkey)
    graph.trustScores[p.pubkey] = p.trustScore

  # 簡易的なエッジ構築: trustScore 上位同士を相互に信頼とみなす
  # より高度な実装では WoTIntro メッセージから構築
  var sortedPeers = cache.peers
  # 簡易バブルソート (trustScore 降順)
  for i in 0..<sortedPeers.len:
    for j in i+1..<sortedPeers.len:
      if sortedPeers[j].trustScore > sortedPeers[i].trustScore:
        swap(sortedPeers[i], sortedPeers[j])

  # 上位10件を相互接続 (クリーク形成)
  let topCount = min(10, sortedPeers.len)
  for i in 0..<topCount:
    for j in i+1..<topCount:
      let a = sortedPeers[i]
      let b = sortedPeers[j]
      # 相互エッジ追加
      graph.edges.add(TrustEdge(
        fromPub: a.pubkey, to: b.pubkey,
        score: min(a.trustScore, b.trustScore),
        createdAt: min(a.lastSeen, b.lastSeen)
      ))
      graph.edges.add(TrustEdge(
        fromPub: b.pubkey, to: a.pubkey,
        score: min(a.trustScore, b.trustScore),
        createdAt: min(a.lastSeen, b.lastSeen)
      ))

  return graph

# WoT 紹介を追加 (新しい信頼のエッジ)
proc addWoTIntroduction*(
  graph: WoTGraph,
  intro: WoTIntro
): WoTGraph =
  if not verifyWoTIntro(intro):
    return graph

  var updated = graph

  # ノード追加
  if intro.newPeer.pubkey notin updated.nodes:
    updated.nodes.add(intro.newPeer.pubkey)

  if intro.introducer notin updated.nodes:
    updated.nodes.add(intro.introducer)

  # エッジ追加 (紹介者 -> 新ピア)
  updated.edges.add(TrustEdge(
    fromPub: intro.introducer,
    to: intro.newPeer.pubkey,
    score: intro.newPeer.trustScore,
    createdAt: uint64(epochTime())
  ))

  # 信頼スコア更新 (紹介者のスコアを新ピアに伝播)
  let introducerScore = updated.trustScores.getOrDefault(intro.introducer, 0.5)
  let propagatedScore = introducerScore * 0.8  # 減衰
  let currentScore = updated.trustScores.getOrDefault(intro.newPeer.pubkey, 0.0)
  updated.trustScores[intro.newPeer.pubkey] = max(currentScore, propagatedScore)

  updated.version += 1
  return updated

# 自分から目標ピアへの信頼経路を探索 (BFS)
proc findTrustPath*(
  graph: WoTGraph,
  fromPub: SkPublicKey,
  to: SkPublicKey,
  minScore: float = 0.3
): Option[WoTPath] =
  if fromPub == to:
    return some(WoTPath(hops: @[fromPub], score: 1.0))

  var queue = newSeq[WoTPath]()
  var visited = initSet[SkPublicKey]()

  queue.add(WoTPath(hops: @[fromPub], score: 1.0))
  visited.incl(fromPub)

  while queue.len > 0:
    let current = queue.pop()

    if current.hops[^1] == to:
      return some(current)

    # 隣接ノードを探索
    for edge in graph.edges:
      if edge.fromPub == current.hops[^1] and edge.score >= minScore:
        if edge.to notin visited:
          let newScore = min(current.score, edge.score)
          var newPath = current
          newPath.hops.add(edge.to)
          newPath.score = newScore
          queue.add(newPath)
          visited.incl(edge.to)

  return none(WoTPath)

# 信頼経路に基づくピア推奨 (目標ピアへの経路があるピアを優先)
proc recommendPeersByTrust*(
  graph: WoTGraph,
  myPubkey: SkPublicKey,
  targetPubkey: SkPublicKey,
  cache: PeerCache,
  count: int = 5
): seq[PeerInfo] =
  let path = findTrustPath(graph, myPubkey, targetPubkey)

  var scored = newSeq[tuple[peer: PeerInfo, score: float]]()

  for p in cache.peers:
    var score = p.trustScore

    # 経路上のピアならボーナス
    if path.isSome:
      for hop in path.get().hops:
        if hop == p.pubkey:
          score += 0.3
          break

    scored.add((p, score))

  scored.sort(proc(a, b: tuple[peer: PeerInfo, score: float]): int =
    if a.score > b.score: -1
    elif a.score < b.score: 1
    else: 0
  )

  result = newSeq[PeerInfo]()
  for i in 0..<min(count, scored.len):
    result.add(scored[i].peer)

# グラフのシリアライズ (デバッグ/永続化用)
proc wotGraphToJson*(graph: WoTGraph): JsonNode =
  var nodeList = newSeq[JsonNode]()
  for n in graph.nodes:
    nodeList.add(%*{
      "pubkey": fpubEncode(n),
      "trustScore": graph.trustScores.getOrDefault(n, 0.0)
    })

  var edgeList = newSeq[JsonNode]()
  for e in graph.edges:
    edgeList.add(%*{
      "from": fpubEncode(e.fromPub),
      "to": fpubEncode(e.to),
      "score": e.score,
      "createdAt": e.createdAt
    })

  return %*{
    "version": graph.version,
    "nodes": nodeList,
    "edges": edgeList
  }

# グラフのデシリアライズ
proc jsonToWoTGraph*(doc: JsonNode): WoTGraph =
  var graph = newWoTGraph()
  graph.version = doc["version"].getBiggestInt().uint64

  for node in doc["nodes"]:
    let pubkey = fpubDecode(node["pubkey"].getStr())
    graph.nodes.add(pubkey)
    graph.trustScores[pubkey] = node["trustScore"].getFloat()

  for edge in doc["edges"]:
    graph.edges.add(TrustEdge(
      fromPub: fpubDecode(edge["from"].getStr()),
      to: fpubDecode(edge["to"].getStr()),
      score: edge["score"].getFloat(),
      createdAt: edge["createdAt"].getBiggestInt().uint64
    ))

  return graph

# 信頼スコアの減衰 (時間経過による自然減衰)
proc decayTrustScores*(graph: WoTGraph, now: uint64): WoTGraph =
  var updated = graph
  const DECAY_HALF_LIFE = 86400 * 30  # 30日で半減

  for node in updated.nodes:
    let trustScore = graph.trustScores.getOrDefault(node, 0.5)
    # 簡易実装: 信頼スコアを時間経過で徐々に減衰
    # 実際には最後の更新時刻を別途管理すべき
    let decayFactor = 0.95  # 固定減衰係数
    updated.trustScores[node] = max(trustScore * decayFactor, 0.1)

  return updated