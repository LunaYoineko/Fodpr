## discovery.nim
## F2F: WoTベースピア発見モジュール
##
## 接続済みピアから WoT (Web of Trust) ベースで新しいピアを発見し、
## ピアリスト交換 (TransTypePeerList) を行う。

import asyncdispatch, protocol, crypto, peer_cache, options, tables, sequtils, sets, transport

const
  MAX_TRUST_SCORE = 1.0

type
  WoTNode* = object
    pubkey*: SkPublicKey
    connections*: seq[SkPublicKey]  # 直接知っているピア
    introducedBy*: Option[SkPublicKey]  # 紹介者 (信頼の連鎖)

  PeerDiscoveryResult* = object
    peerList: PeerList
    introductions: seq[WoTIntro]

# ---------------------------------------------------------------------------
# 内部ヘルパー
# ---------------------------------------------------------------------------

# PeerList から WoT グラフを構築
proc buildWoTGraph*(peerList: PeerList): seq[WoTNode] =
  var nodes = newSeq[WoTNode]()
  var pubkeyToIndex = initTable[SkPublicKey, int]()

  # まず全ピアをノードとして登録
  for i, p in peerList.peers:
    pubkeyToIndex[p.pubkey] = i
    nodes.add(WoTNode(
      pubkey: p.pubkey,
      connections: @[],
      introducedBy: none(SkPublicKey)
    ))

  # アドレス情報から接続関係を推測 (同じアドレスを持つ = 知り合い)
  # より高度な実装では WoTIntro メッセージを使う
  for i, p in peerList.peers:
    # 簡易実装: trustScore が高い順に上位数件を「知り合い」とみなす
    var scored = newSeq[tuple[pubkey: SkPublicKey, score: float]]()
    for other in peerList.peers:
      if other.pubkey != p.pubkey:
        scored.add((other.pubkey, other.trustScore))

    # スコア降順でソート (簡易バブルソート)
    for i in 0..<scored.len:
      for j in i+1..<scored.len:
        if scored[j].score > scored[i].score:
          swap(scored[i], scored[j])

    # 上位3件を接続として登録
    for j in 0..<min(3, scored.len):
      nodes[i].connections.add(scored[j].pubkey)

  return nodes

# 自分の WoT から次の接続候補を選択
proc getNextCandidates*(
  wotGraph: seq[WoTNode],
  myPubkey: SkPublicKey,
  knownPeers: seq[SkPublicKey],
  maxCandidates: int = 10
): seq[SkPublicKey] =
  # 自分が直接知っているピアを取得
  var myIndex = -1
  for i, n in wotGraph:
    if n.pubkey == myPubkey:
      myIndex = i
      break

  if myIndex == -1:
    return @[]

  var candidates = newSeq[SkPublicKey]()
  var seen = initHashSet[SkPublicKey]()

  # 既知のピアを除外
  for k in knownPeers:
    seen.incl(k)

  # 直接の知り合い (1ホップ) を優先
  for conn in wotGraph[myIndex].connections:
    if conn notin seen and candidates.len < maxCandidates:
      candidates.add(conn)
      seen.incl(conn)

  # 知り合いの知り合い (2ホップ) を追加
  if candidates.len < maxCandidates:
    for conn in wotGraph[myIndex].connections:
      # conn の接続を探す
      for n in wotGraph:
        if n.pubkey == conn:
          for secondHop in n.connections:
            if secondHop notin seen and candidates.len < maxCandidates:
              candidates.add(secondHop)
              seen.incl(secondHop)
          break

  return candidates

# ピアからピアリストを要求・取得 (P2Pデータチャネル経由)
proc requestPeerList*(
  conn: WebRTCDataChannel,
  maxPeers: int = MAX_CACHE_SIZE
): PeerList =
  # TransTypePeerList / MsgTypePeerListReq で要求
  # 実装は signaling.nim / transport.nim 側で行う
  # ここではスタブ - 空の PeerList を返す
  return PeerList(
    version: 0,
    peerCount: 0,
    peers: @[],
    signature: emptySignature()
  )

# ピアリストを送信 (要求に応答)
proc sendPeerList*(
  conn: WebRTCDataChannel,
  cache: PeerCache
): Future[bool] {.async.} =
  # キャッシュから PeerList を作成して送信
  var pl = PeerList(
    version: cache.version,
    peerCount: uint16(min(cache.peers.len, MAX_CACHE_SIZE)),
    peers: cache.peers[0..<min(cache.peers.len, MAX_CACHE_SIZE)],
    signature: emptySignature()
  )
  # 署名は呼び出し側で行う
  # 実装は signaling.nim / transport.nim 側で行う
  raise newException(ValueError, "Not implemented - use transport.nim")

# WoT紹介メッセージを生成
proc createWoTIntroduction*(
  myPriv: SkSecretKey,
  newPeer: PeerInfo
): WoTIntro =
  var intro = WoTIntro(
    introducer: myPriv.toPublicKey(),
    newPeer: newPeer,
    signature: emptySignature()
  )
  intro.signature = signWoTIntro(myPriv, intro)
  return intro

# WoT紹介メッセージを検証・処理
proc processWoTIntroduction*(
  intro: WoTIntro,
  cache: PeerCache
): tuple[valid: bool, cache: PeerCache] =
  if not verifyWoTIntro(intro):
    return (false, cache)

  # 新しいピアをキャッシュに追加
  let updatedCache = addOrUpdatePeer(cache, intro.newPeer)

  # 紹介者の信頼スコアも少し上げる
  var finalCache = updatedCache
  for i, p in finalCache.peers:
    if p.pubkey == intro.introducer:
      finalCache.peers[i].trustScore =
        min(p.trustScore + 0.05, MAX_TRUST_SCORE)
      break

  return (true, finalCache)

# キャッシュから WoT ベースでピアを選択 (信頼の連鎖考慮)
proc selectPeersWoT*(
  cache: PeerCache,
  myPubkey: SkPublicKey,
  count: int = 5
): seq[PeerInfo] =
  # まず通常の選択ロジックを実行
  let basic = selectPeers(cache, count * 2)

  # WoT グラフを構築してスコアリングを調整
  # (簡易実装: そのまま返す)
  return basic[0..<min(count, basic.len)]