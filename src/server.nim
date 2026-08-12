## server.nim
## Fodpr リレーサーバー & F2F シードサーバー
##
## 既存のリレー機能 (イベント保存・購読配信) に加え、
## F2F ネットワークのシードサーバー機能を提供する。
## - 通常リレー: EVENT/REQ/DEL/AUTH/WebRTCシグナリング
## - シード機能: seed_request/seed_response (アクティブピアリスト提供)
## - グループ管理: ホスト自動昇格 (SignalHostChange)

import std/atomics
import std/json
import asynchttpserver, asyncdispatch, streams, strutils, endians, os, times, random, math, locks, options, tables, algorithm, sequtils, base64
import ws
import secp256k1
import lmdb
import protocol, crypto
import f2f/group, f2f/bootstrap, f2f/peer_cache

# LMDB 環境とデータベースハンドル
var dbenv: LMDBEnv
var dbiJson: Dbi
var dbiString: Dbi
var dbiBinary: Dbi

# シードサーバー用: アクティブピア追跡
var activePeers: seq[PeerInfo] = @[]
var activePeersLock: Lock
var seedServerPriv: Option[SkSecretKey] = none(SkSecretKey)

# グループ管理用 (ホスト自動昇格)
var groupSessions: Table[string, GroupSession]
var groupSessionsLock: Lock

# シャットダウンフラグ
var stopFlag: Atomic[bool]

proc ctrlcHandler() {.noconv.} =
  stopFlag.store(true)

# LMDB 初期化
proc initDatabase() =
  if not dirExists("data"):
    createDir("data")

  dbenv = newLMDBEnv("data", maxdbs = 3)

  let txn = dbenv.newTxn()
  dbiJson = txn.dbiOpen("json", CREATE)
  dbiString = txn.dbiOpen("string", CREATE)
  dbiBinary = txn.dbiOpen("binary", CREATE)
  txn.commit()

  echo "[DB] LMDB ストレージ初期化完了 (./data)"

# シードサーバー鍵ペア生成・読み込み
proc initSeedServerKey(): SkSecretKey =
  let keyPath = "data/seed_server.key"
  if fileExists(keyPath):
    let content = keyPath.readFile()
    var keyBytes: array[32, byte]
    for i in 0..<32:
      keyBytes[i] = byte(content[i])
    let parsed = SkSecretKey.fromRaw(keyBytes)
    if parsed.isErr:
      raise newException(ValueError, "Invalid seed server key: " & $parsed.error)
    return parsed.get()
  else:
    let priv = generateFodprKey().privateKey
    let raw = priv.toRaw()
    var keyStr = newString(32)
    for i in 0..<32:
      keyStr[i] = char(raw[i])
    keyPath.writeFile(keyStr)
    echo "[Seed] 新しいシードサーバー鍵を生成: ", fpubEncode(priv.toPublicKey())
    return priv

# アクティブピアリストを更新 (接続成功時呼び出し)
proc updateActivePeer(peer: PeerInfo) {.gcsafe.} =
  {.gcsafe.}:
    acquire(activePeersLock)
    defer: release(activePeersLock)

    var found = false
    for i, p in activePeers:
      if p.pubkey == peer.pubkey:
        activePeers[i] = peer
        found = true
        break

    if not found:
      activePeers.add(peer)

    # 最大50件に制限
    if activePeers.len > MAX_CACHE_SIZE:
      activePeers.sort(proc(a, b: PeerInfo): int =
        if a.lastSeen < b.lastSeen: -1
        elif a.lastSeen > b.lastSeen: 1
        else: 0
      )
      activePeers.setLen(MAX_CACHE_SIZE)
      discard

# アクティブピアを削除 (切断時呼び出し)
proc removeActivePeer(pubkey: SkPublicKey) {.gcsafe.} =
  {.gcsafe.}:
    acquire(activePeersLock)
    defer: release(activePeersLock)

    activePeers = activePeers.filterIt(it.pubkey != pubkey)

# 現在のアクティブピアリストを取得 (シード応答用)
proc getActiveSeedNodes(maxNodes: int): seq[SeedNode] {.gcsafe.} =
  {.gcsafe.}:
    acquire(activePeersLock)
    defer: release(activePeersLock)

    var nodes = newSeq[SeedNode]()
    let now = uint64(epochTime())
    let staleThreshold = uint64(STALE_THRESHOLD_SEC)

    for p in activePeers:
      if nodes.len >= maxNodes:
        break
      if now - p.lastSeen < staleThreshold:
        nodes.add(SeedNode(pubkey: p.pubkey, addresses: p.addresses))

    return nodes

# イベント保存用ヘルパー
proc pushEventsFromDbi(txn: LMDBTxn, dbi: Dbi, subReq: FodprReq, ws: WebSocket) {.async, gcsafe.} =
  let cursor = txn.cursorOpen(dbi)
  var kVal, dVal: Val

  while cursorGet(cursor, addr kVal, addr dVal, NEXT) == 0:
    if subReq.tagKey == "pubkey" and subReq.tagVal != "":
      var enc = newString(int(dVal.mvSize))
      if dVal.mvSize > 0:
        copyMem(addr enc[0], dVal.mvData, int(dVal.mvSize))
      let evt = decodeEvent(newStringStream(enc))
      if $evt.pubkey.toRawCompressed() != subReq.tagVal:
        continue

    var encoded = newString(int(dVal.mvSize))
    if dVal.mvSize > 0:
      copyMem(addr encoded[0], dVal.mvData, int(dVal.mvSize))

    var pushData = ""
    pushData.add(MsgTypePush)
    let subIdLen = uint16(subReq.subId.len)
    var siNet: uint16
    bigEndian16(addr siNet, unsafeAddr subIdLen)
    var siBytes: array[2, byte]
    copyMem(addr siBytes[0], addr siNet, 2)
    pushData.add(char(siBytes[0]))
    pushData.add(char(siBytes[1]))
    pushData.add(subReq.subId)
    pushData.add(encoded)
    await ws.send(pushData, Binary)

  cursor.cursorClose()

# シードリクエスト処理
proc handleSeedRequest(ws: WebSocket, doc: JsonNode) {.async.} =
  let maxNodes = if doc.hasKey("max_nodes"): doc["max_nodes"].getInt() else: MAX_SEED_NODES
  let clampedMax = min(maxNodes, MAX_SEED_NODES)

  let seedNodes = getActiveSeedNodes(clampedMax)

  # シードリストに署名
  let version = uint64(epochTime())
  var signData = ""
  signData.add($version)
  for node in seedNodes:
    let pubRaw = node.pubkey.toRawCompressed()
    for b in pubRaw: signData.add(char(b))
    for addr in node.addresses:
      let addrLen = uint16(addr.len)
      var alNet: uint16
      bigEndian16(addr alNet, unsafeAddr addrLen)
      var alBytes: array[2, byte]
      copyMem(addr alBytes[0], addr alNet, 2)
      signData.add(char(alBytes[0]))
      signData.add(char(alBytes[1]))
      signData.add(addr)

  let signature = signBytes(seedServerPriv.get(), signData)

  # レスポンス作成
  var nodeJsons = newSeq[JsonNode]()
  for node in seedNodes:
    nodeJsons.add(seedNodeToJson(node))

  let response = %*{
    "type": "seed_response",
    "version": %* version,
    "nodes": %* nodeJsons,
    "signature": %* base64.encode(signature.sig.toRaw())
  }

  await ws.send($response, Text)
  echo "[Seed] シード応答送信: ", seedNodes.len, " ノード"

# グループ参加要求処理 (ホスト側)
proc handleGroupJoin(groupId: string, req: GroupJoinReq, ws: WebSocket, clientPubkey: SkPublicKey) {.async.} =
  {.gcsafe.}:
    acquire(groupSessionsLock)
    defer: release(groupSessionsLock)

    var session = if groupSessions.hasKey(groupId):
                    groupSessions[groupId]
                  else:
                    let hostPriv = generateFodprKey().privateKey
                    let s = createGroup(hostPriv, groupId)
                    groupSessions[groupId] = s
                    s

    if group.verifyGroupJoinReq(req):
      if addMember(session, req.member):
        session.group.signature = signGroupData(session.group, session.hostPriv)
        groupSessions[groupId] = session

        # 参加成功応答
        let resp = %*{
          "type": "group_join_response",
          "success": true,
          "group": groupToJson(session.group)
        }
        await ws.send($resp, Text)

        # 他のメンバーに通知 (SignalGroupJoin)
        for member in session.group.members:
          if member.pubkey != req.member.pubkey and member.isConnected:
            # 実際には P2P またはリレー経由で送信
            discard
      else:
        let resp = %*{"type": "group_join_response", "success": false, "error": "group_full_or_duplicate"}
        await ws.send($resp, Text)
    else:
      let resp = %*{"type": "group_join_response", "success": false, "error": "invalid_signature"}
      await ws.send($resp, Text)

# ホスト昇格処理 (ホスト切断時の自動昇格)
proc promoteGroupHost(groupId: string): Option[SkPublicKey] {.gcsafe.} =
  {.gcsafe.}:
    acquire(groupSessionsLock)
    defer: release(groupSessionsLock)

    if not groupSessions.hasKey(groupId):
      return none(SkPublicKey)

    var session = groupSessions[groupId]
    let newHost = promoteNewHost(session)
    if newHost.isSome:
      session.group.signature = emptySignature()  # 新ホストで再署名必要
      groupSessions[groupId] = session

      # SignalHostChange を全メンバーにブロードキャスト
      let signalContent = createHostChangeSignal(newHost.get(), groupId)
      echo "[Group] ホスト昇格: ", groupId, " -> 新ホスト: ", fpubEncode(newHost.get())

    return newHost

# メイン WebSocket ハンドラ
proc cb(req: Request) {.async, gcsafe.} =
  let isWebSocket = (req.url.path == "/") and req.headers.hasKey("upgrade") and
                    req.headers.getOrDefault("upgrade").toLowerAscii() == "websocket"

  if isWebSocket:
    try:
      var ws = await newWebSocket(req)
      echo "[接続] クライアント接続"

      var clientPubkey: Option[SkPublicKey] = none(SkPublicKey)

      while ws.readyState == Open:
        let (opcode, packet) = await ws.receivePacket()

        # --- 制御フレーム処理 ---
        if opcode == Opcode.Ping:
          await ws.send(packet, Pong)
          continue
        if opcode == Opcode.Pong:
          continue
        if opcode == Opcode.Close:
          break

        if packet.len == 0:
          continue

        # --- Text フレーム = JSON シードリクエスト ---
        if opcode == Opcode.Text:
          try:
            let doc = parseJson(packet)
            if doc.hasKey("type") and doc["type"].getStr() == "seed_request":
              await handleSeedRequest(ws, doc)
          except:
            # 不明なパケットは無視
            discard
          continue

        var strm = newStringStream(packet)
        let msgType = strm.readChar()

        # --- EVENT (0x01) ---
        if msgType == MsgTypeEvent:
          try:
            let event = decodeEvent(strm)
            if not verifyContent(event.pubkey, event.content, event.signature):
              echo "[拒否] 不正な署名"
              await ws.send("ERR: Invalid signature")
              continue

            if event.transType notin [TransTypeJSON, TransTypeString, TransTypeBinary,
                                       TransTypeSigned, TransTypeEncrypted, TransTypeWebRTC]:
              echo "[拒否] 未定義 TransType: ", event.transType
              await ws.send("ERR: Unknown trans type")
              continue

            if event.transType == TransTypeJSON:
              try: discard parseJson(event.content)
              except:
                echo "[拒否] 不正な JSON"
                await ws.send("ERR: Invalid JSON content")
                continue

            clientPubkey = some(event.pubkey)
            updateActivePeer(PeerInfo(
              pubkey: event.pubkey,
              addresses: @[],  # アドレス情報は別途取得
              lastSeen: uint64(epochTime()),
              trustScore: 0.5
            ))

            {.gcsafe.}:
              let txn = dbenv.newTxn()
              let encoded = encodeEvent(event)
              let timeKey = "evt_" & $epochTime() & "_" & $event.transType & "_" & $rand(100000)
              case event.transType
              of TransTypeJSON: txn.put(dbiJson, timeKey, encoded)
              of TransTypeString: txn.put(dbiString, timeKey, encoded)
              of TransTypeBinary: txn.put(dbiBinary, timeKey, encoded)
              of TransTypeSigned: txn.put(dbiJson, timeKey, encoded)
              of TransTypeEncrypted: txn.put(dbiBinary, timeKey, encoded)
              of TransTypeWebRTC:
                # WebRTCシグナリングは保存せず即時中継 (実装要)
                discard
              else: discard
              txn.commit()

            await ws.send("OK: Event accepted")
          except Exception as e:
            echo "[エラー] イベントパース失敗: ", e.msg
            await ws.send("ERR: Invalid event")

        # --- REQ (0x02) ---
        elif msgType == MsgTypeReq:
          try:
            let subReq = decodeReq(strm)
            echo "[購読] ID: ", subReq.subId, " TransType: ", transTypeName(subReq.transType)

            {.gcsafe.}:
              let txn = dbenv.newTxn()
              case subReq.transType
              of TransTypeJSON: await pushEventsFromDbi(txn, dbiJson, subReq, ws)
              of TransTypeString: await pushEventsFromDbi(txn, dbiString, subReq, ws)
              of TransTypeBinary: await pushEventsFromDbi(txn, dbiBinary, subReq, ws)
              else:
                await pushEventsFromDbi(txn, dbiJson, subReq, ws)
                await pushEventsFromDbi(txn, dbiString, subReq, ws)
                await pushEventsFromDbi(txn, dbiBinary, subReq, ws)
              txn.commit()

            await ws.send("EOE: End of stored events for " & subReq.subId)
          except Exception as e:
            echo "[エラー] REQ処理失敗: ", e.msg

        # --- DEL (0x03) ---
        elif msgType == MsgTypeDel:
          try:
            let delReq = decodeDelReq(strm)
            if not verifyDel(delReq):
              echo "[拒否] DEL署名検証失敗"
              await ws.send("ERR: Invalid DEL signature")
              continue

            {.gcsafe.}:
              let txn = dbenv.newTxn()
              let cursor = txn.cursorOpen(dbiJson)
              var kVal, dVal: Val
              var deleted = 0
              while cursorGet(cursor, addr kVal, addr dVal, NEXT) == 0:
                var enc = newString(int(dVal.mvSize))
                if dVal.mvSize > 0:
                  copyMem(addr enc[0], dVal.mvData, int(dVal.mvSize))
                let evt = decodeEvent(newStringStream(enc))
                if evt.pubkey == delReq.pubkey:
                  discard txn.del(dbiJson, addr kVal, addr dVal)
                  inc(deleted)
              cursor.cursorClose()
              txn.commit()
              echo "[削除] ", deleted, " 件のイベントを削除"
              await ws.send("OK: Deleted " & $deleted & " events")
          except Exception as e:
            echo "[エラー] DEL処理失敗: ", e.msg

        # --- AUTH (0x04) ---
        elif msgType == MsgTypeAuth:
          try:
            let auth = decodeAuth(strm)
            if not verifyAuth(auth):
              echo "[拒否] AUTH署名検証失敗"
              await ws.send("ERR: Invalid AUTH")
              continue
            clientPubkey = some(auth.pubkey)
            await ws.send("OK: Authenticated")
          except Exception as e:
            echo "[エラー] AUTH処理失敗: ", e.msg

        # --- SIGNAL (0x05) WebRTCシグナリング ---
        elif msgType == MsgTypeSignal:
          try:
            let signal = decodeSignal(strm)
            if not verifySignal(signal):
              echo "[拒否] シグナリング署名検証失敗"
              continue

            # SignalHostChange などグループ管理シグナルの処理
            if signal.signalType == SignalHostChange:
              let (newHost, groupId) = parseHostChangeSignal(signal.content)
              echo "[Group] HostChange受信: ", groupId, " -> ", fpubEncode(newHost)

            # 宛先に中継 (実装要: 購読者検索・配信)
            echo "[Signal] シグナリング中継: ", signalTypeName(signal.signalType),
               " from: ", fpubEncode(signal.sender), " to: ", fpubEncode(signal.target)
          except Exception as e:
            echo "[エラー] シグナリング処理失敗: ", e.msg

        # --- PEER_LIST_REQ (0x07) F2Fピアリスト要求 ---
        elif msgType == MsgTypePeerListReq:
          try:
            # 簡易実装: バイナリデコード
            var strm2 = newStringStream(strm.readAll())
            let reqPubkey = strm2.readStr(33)  # 要求者の公開鍵 (簡易)
            echo "[F2F] PeerListReq from: ", reqPubkey

            # アクティブピアリストを返す
            let seedNodes = getActiveSeedNodes(MAX_CACHE_SIZE)
            var peerList = PeerList(
              version: uint64(epochTime()),
              peerCount: uint16(seedNodes.len),
              peers: seedNodesToPeerInfo(seedNodes),
              signature: emptySignature()
            )
            # 署名は呼び出し側で行う想定
            let encoded = encodePeerList(peerList)
            var resp = ""
            resp.add(MsgTypePeerListPush)
            resp.add(encoded)
            await ws.send(resp, Binary)
          except Exception as e:
            echo "[エラー] PeerListReq処理失敗: ", e.msg

        # --- JSONベースのシードリクエスト (テキストフレーム) ---
        else:
          # テキストフレームとして処理を試みる
          try:
            let textPacket = packet  # バイナリだが JSON の可能性
            let doc = parseJson(textPacket)
            if doc.hasKey("type") and doc["type"].getStr() == "seed_request":
              await handleSeedRequest(ws, doc)
          except:
            # 不明なパケットは無視
            discard

      # 切断時のクリーンアップ
      if clientPubkey.isSome:
        removeActivePeer(clientPubkey.get())
        # グループからも削除
        {.gcsafe.}:
          for groupId, session in groupSessions.mpairs:
            for i, m in session.group.members:
              if m.pubkey == clientPubkey.get():
                session.group.members[i].isConnected = false
                # ホストが切断したら昇格処理
                if m.isHost:
                  discard promoteGroupHost(groupId)
                break

    except WebSocketClosedError:
      echo "[切断] クライアント切断"
    except Exception as e:
      echo "[エラー] WebSocket例外: ", e.msg
  else:
    if req.url.path == "/":
      await req.respond(Http200, "Fodpr Relay & Seed Server")
    else:
      await req.respond(Http404, "Not Found")

proc main() {.async.} =
  initDatabase()
  seedServerPriv = some(initSeedServerKey())
  initLock(activePeersLock)
  initLock(groupSessionsLock)
  groupSessions = initTable[string, GroupSession]()

  let port = if paramCount() > 0: Port(parseInt(paramStr(1))) else: Port(8000)
  echo "================================================"
  echo " Fodpr Relay & F2F Seed Server"
  echo " Running on ws://0.0.0.0:", port.int, "/"
  echo " Seed Pubkey: ", fpubEncode(seedServerPriv.get().toPublicKey())
  echo " (Ctrl+C で安全に終了)"
  echo "================================================"

  setControlCHook(ctrlcHandler)

  var server = newAsyncHttpServer()
  var serveTask = server.serve(port, cb)

  while not stopFlag.load():
    await sleepAsync(100)

  echo "[終了] シャットダウン中..."
  server.close()
  try:
    await serveTask
  except CatchableError:
    discard

  dbenv.close(dbiJson)
  dbenv.close(dbiString)
  dbenv.close(dbiBinary)
  dbenv.envClose()
  deinitLock(activePeersLock)
  deinitLock(groupSessionsLock)

  echo "[終了] 正常終了"

when isMainModule:
  waitFor main()