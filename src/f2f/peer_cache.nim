## peer_cache.nim
## F2F: ピアキャッシュ・ローテーション管理モジュール
##
## 最大50件のピア情報をローカルストレージに保存する。
## キャッシュは破棄せず、新しく取得したピアリストは既存キャッシュへマージする。
## reliabilityScore が閾値未満のまま長期間 (STALE_SCORE_SEC) 経過したピアのみ削除する。

import os, json, streams, times, sequtils, algorithm, sets, options
import protocol, crypto

# シンプルな乱数生成 (secp256k1 との競合回避)
var randomSeed = epochTime().int64
proc simpleRandom(max: int): int =
  randomSeed = (randomSeed * 1103515245 + 12345) and 0x7fffffff
  return int(randomSeed mod int64(max))

const
  MAX_CACHE_SIZE* = 50
  CACHE_VERSION* = 1
  CACHE_FILE_NAME = "peer_cache.json"
  DEFAULT_TRUST_SCORE = 0.0  # 新規ピアの初期スコア (信頼は接続実績で築く)
  TRUST_INCREMENT = 0.1
  TRUST_DECREMENT = 0.15
  MIN_TRUST_SCORE = 0.05
  MAX_TRUST_SCORE = 1.0
  # 削除判定: スコアがこの値以上に上がらなければ削除対象
  STALE_SCORE_THRESHOLD = 0.1
  # スコアが閾値未満のままこの秒数 (7日) 経過したピアはキャッシュから削除
  STALE_SCORE_SEC* = 86400 * 7
  STALE_THRESHOLD_SEC* = 86400 * 7  # 7日間見られていなければ古いとみなす
  # アクティブ接続の上限 (同時接続数のハードリミット)
  MAX_ACTIVE_PEERS* = 15  # 同時接続ピア数の上限 (15-20推奨)

type
  PeerCache* = object
    version*: uint64          # キャッシュバージョン
    peers*: seq[PeerInfo]     # ピア情報 (最大50件)
    lastUpdated*: uint64      # 最終更新時刻 (Unix秒)

  # ピア選択用の内部構造
  PeerSelection* = object
    peer: PeerInfo
    score: float  # 選択スコア (信頼度 + ランダム要素)

# ---------------------------------------------------------------------------
# 内部ヘルパー
# ---------------------------------------------------------------------------

proc getCachePath(): string =
  let
    homeDir = getEnv("HOME")
    cacheDir = homeDir / ".fodpr" / "cache"
  if not dirExists(cacheDir):
    createDir(cacheDir)
  result = cacheDir / CACHE_FILE_NAME

proc peerInfoToJson(p: PeerInfo): JsonNode =
  %*{
    "pubkey": fpubEncode(p.pubkey),
    "addresses": p.addresses.mapIt(%* it),
    "lastSeen": %* p.lastSeen,
    "identityTrust": %* p.identityTrust,
    "reliabilityScore": %* p.reliabilityScore,
    "zeroScoreSince": %* p.zeroScoreSince
  }

proc jsonToPeerInfo(node: JsonNode): PeerInfo =
  let
    pubkey = fpubDecode(node["pubkey"].getStr())
    addresses = node["addresses"].mapIt(it.getStr())
    lastSeen = node["lastSeen"].getBiggestInt()
    reliability = if node.hasKey("reliabilityScore"):
      node["reliabilityScore"].getFloat()
    elif node.hasKey("trustScore"):
      node["trustScore"].getFloat()
    else:
      DEFAULT_TRUST_SCORE
    identityTrust = if node.hasKey("identityTrust"):
      node["identityTrust"].getFloat()
    else:
      0.0
    zeroScoreSince = if node.hasKey("zeroScoreSince"):
      uint64(node["zeroScoreSince"].getBiggestInt())
    else:
      0'u64
  return PeerInfo(
    pubkey: pubkey,
    addresses: addresses,
    lastSeen: uint64(lastSeen),
    identityTrust: identityTrust,
    reliabilityScore: reliability,
    zeroScoreSince: zeroScoreSince
  )

# ---------------------------------------------------------------------------
# 公開 API
# ---------------------------------------------------------------------------

# addOrUpdatePeer の前方宣言 (updateCache から参照されるため)
proc addOrUpdatePeer*(cache: PeerCache, newPeer: PeerInfo): PeerCache

# 7日ルール: reliabilityScore が STALE_SCORE_THRESHOLD 未満のまま
# STALE_SCORE_SEC (7日) 以上経過したピアをキャッシュから削除する
proc pruneStalePeers*(cache: PeerCache): PeerCache =
  let now = uint64(epochTime())
  var updated = cache
  updated.peers = updated.peers.filterIt(
    it.reliabilityScore >= STALE_SCORE_THRESHOLD or
    it.zeroScoreSince == 0 or
    now - it.zeroScoreSince < STALE_SCORE_SEC
  )
  return updated

# キャッシュをファイルから読み込む
proc loadCache*(): PeerCache =
  let path = getCachePath()
  if not fileExists(path):
    return PeerCache(version: CACHE_VERSION, peers: @[], lastUpdated: 0)

  try:
    let content = path.readFile()
    let doc = parseJson(content)
    let version = doc["version"].getBiggestInt()
    let lastUpdated = doc["lastUpdated"].getBiggestInt()
    var peers = newSeq[PeerInfo]()
    for peerNode in doc["peers"]:
      peers.add(jsonToPeerInfo(peerNode))
    var loaded = PeerCache(
      version: uint64(version),
      peers: peers,
      lastUpdated: uint64(lastUpdated)
    )
    # 7日ルール: スコアが閾値未満のまま長期間経過したピアを削除
    loaded = pruneStalePeers(loaded)
    return loaded
  except:
    # 破損したファイルは無視して空キャッシュを返す
    return PeerCache(version: CACHE_VERSION, peers: @[], lastUpdated: 0)

# キャッシュをファイルに保存する
proc saveCache*(cache: PeerCache) =
  let path = getCachePath()
  var peerNodes = newSeq[JsonNode]()
  for p in cache.peers:
    peerNodes.add(peerInfoToJson(p))

  let doc = %*{
    "version": %* cache.version,
    "lastUpdated": %* cache.lastUpdated,
    "peers": %* peerNodes
  }
  path.writeFile(pretty(doc))

# ピアリストから接続を試みるピアを選択する (信頼スコア順 + ランダム化)
proc selectPeers*(cache: PeerCache, count: int = 5): seq[PeerInfo] =
  if cache.peers.len == 0:
    return @[]

  # 古いピアは削除せず維持する (7日ルールでのみ削除)。
  # ここではキャッシュ全体から選択する。
  let freshPeers = cache.peers

  # 選択スコアを計算 (信頼スコア * ランダム係数)
  var selections = newSeq[PeerSelection]()
  for p in freshPeers:
    let randFactor = 0.5 + (simpleRandom(1000).float / 1000.0) * 0.5  # 0.5-1.0
    selections.add(PeerSelection(peer: p, score: p.reliabilityScore * randFactor))

  # スコア降順でソート
  selections.sort(proc(a, b: PeerSelection): int =
    if a.score > b.score: -1
    elif a.score < b.score: 1
    else: 0
  )

  # 上位 count 件を返す
  result = newSeq[PeerInfo]()
  for i in 0..<min(count, selections.len):
    result.add(selections[i].peer)

# 取得したピアリストを既存キャッシュへマージする (キャッシュは破棄しない)
proc updateCache*(cache: PeerCache, newPeers: seq[PeerInfo]): PeerCache =
  var updated = cache

  for newPeer in newPeers:
    # 既存ピアは保持しつつ、情報を更新/追加
    updated = addOrUpdatePeer(updated, newPeer)

  # 7日ルール: スコアが閾値未満のまま長期間経過したピアを削除
  updated = pruneStalePeers(updated)

  updated.version = cache.version + 1
  updated.lastUpdated = uint64(epochTime())
  return updated

# 接続成功時の信頼スコア更新
proc onConnectionSuccess*(cache: PeerCache, peerPubkey: SkPublicKey): PeerCache =
  var updated = cache
  for i, p in updated.peers:
    if p.pubkey == peerPubkey:
      updated.peers[i].reliabilityScore = min(p.reliabilityScore + TRUST_INCREMENT, MAX_TRUST_SCORE)
      updated.peers[i].lastSeen = uint64(epochTime())
      # スコアが閾値以上になったので 7日ルール用タイマーをリセット
      if updated.peers[i].reliabilityScore >= STALE_SCORE_THRESHOLD:
        updated.peers[i].zeroScoreSince = 0
      break
  updated.lastUpdated = uint64(epochTime())
  return updated

# 接続失敗時の信頼スコア減衰
proc onConnectionFailure*(cache: PeerCache, peerPubkey: SkPublicKey): PeerCache =
  var updated = cache
  for i, p in updated.peers:
    if p.pubkey == peerPubkey:
      updated.peers[i].reliabilityScore = max(p.reliabilityScore - TRUST_DECREMENT, MIN_TRUST_SCORE)
      # スコアが閾値未満になった時刻を記録 (7日ルール用)
      if updated.peers[i].reliabilityScore < STALE_SCORE_THRESHOLD:
        if updated.peers[i].zeroScoreSince == 0:
          updated.peers[i].zeroScoreSince = uint64(epochTime())
      else:
        # 閾値以上ならタイマーをリセット
        updated.peers[i].zeroScoreSince = 0
      break
  # 即時削除は行わない。削除は 7日ルール (pruneStalePeers) のみ
  updated = pruneStalePeers(updated)
  updated.lastUpdated = uint64(epochTime())
  return updated

# ピア情報をキャッシュに追加・更新
proc addOrUpdatePeer*(cache: PeerCache, newPeer: PeerInfo): PeerCache =
  var updated = cache
  var found = false
  for i, p in updated.peers:
    if p.pubkey == newPeer.pubkey:
      # 既存ピア: アドレスと lastSeen は新しい情報へ統合するが、
      # スコア (reliabilityScore / zeroScoreSince) はローカル実績を維持する
      var mergedAddrs = p.addresses
      for a in newPeer.addresses:
        if a notin mergedAddrs:
          mergedAddrs.add(a)
      updated.peers[i].addresses = mergedAddrs
      if newPeer.lastSeen > p.lastSeen:
        updated.peers[i].lastSeen = newPeer.lastSeen
      if newPeer.country.len > 0:
        updated.peers[i].country = newPeer.country
      found = true
      break

  if not found:
    var peer = newPeer
    # 新規ピアはスコア 0.0 から開始。7日ルール用タイマーを開始
    peer.reliabilityScore = DEFAULT_TRUST_SCORE
    if peer.zeroScoreSince == 0:
      peer.zeroScoreSince = uint64(epochTime())
    updated.peers.add(peer)

  # 最大サイズ制限 (古い順で削除)
  if updated.peers.len > MAX_CACHE_SIZE:
    updated.peers.sort(proc(a, b: PeerInfo): int =
      if a.lastSeen < b.lastSeen: -1
      elif a.lastSeen > b.lastSeen: 1
      else: 0
    )
    updated.peers.setLen(MAX_CACHE_SIZE)

  updated = pruneStalePeers(updated)
  updated.lastUpdated = uint64(epochTime())
  return updated

# キャッシュが空か、全ピアが古いかどうかを判定
proc isCacheStaleOrEmpty*(cache: PeerCache): bool =
  if cache.peers.len == 0:
    return true
  let now = uint64(epochTime())
  for p in cache.peers:
    if now - p.lastSeen < STALE_THRESHOLD_SEC:
      return false
  return true

# キャッシュ内のアクティブなピア数を取得
proc getActivePeerCount*(cache: PeerCache): int =
  let now = uint64(epochTime())
  var count = 0
  for p in cache.peers:
    if now - p.lastSeen < STALE_THRESHOLD_SEC:
      inc(count)
  return count

# アクティブ接続上限チェック: 上限を超えていれば信頼の低いピアを切断候補とする
proc getLowestActivePeer*(cache: PeerCache): Option[PeerInfo] =
  let now = uint64(epochTime())
  var lowest: Option[PeerInfo] = none(PeerInfo)
  var lowestScore = 1.0
  for p in cache.peers:
    if now - p.lastSeen < STALE_THRESHOLD_SEC:
      if p.reliabilityScore < lowestScore:
        lowestScore = p.reliabilityScore
        lowest = some(p)
  return lowest

# アクティブ接続上限チェック: 上限を超えていれば古い/信頼の低いピアを切断
proc checkActivePeerLimit*(cache: PeerCache): PeerCache =
  if cache.peers.len <= MAX_ACTIVE_PEERS:
    return cache
  
  # アクティブピア数をカウント
  var activeCount = getActivePeerCount(cache)
  if activeCount <= MAX_ACTIVE_PEERS:
    # 古いピアでクリーンアップが十分なら何もしない
    return cache
  
  # 切断候補 (信頼スコアが最低のアクティブピア) を特定
  var disconnected = getLowestActivePeer(cache)
  if disconnected.isSome:
    var updated = cache
    # キャッシュから削除 (LRU的動作)
    updated.peers = updated.peers.filterIt(it.pubkey != disconnected.get().pubkey)
    updated.lastUpdated = uint64(epochTime())
    echo "Active peer limit (MAX_ACTIVE_PEERS=$MAX_ACTIVE_PEERS) exceeded, disconnected least-reliable peer"
    return updated
  
  return cache