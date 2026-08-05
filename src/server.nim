## server.nim
## Fodpr のリレーサーバー（WebSocket サーバー）を実装するモジュール。
##
## クライアントからのイベント投稿（EVENT）を受け取り、
## 署名検証を行ってから保存する。また購読要求（REQ）に対しては、
## 条件に一致する保存済みイベントを PUSH 形式で返信する。
##
## 起動方法:  src/server   (ws://0.0.0.0:8000/ で待ち受け)
##
## Ctrl+C (SIGINT) を押すと、リスニングソケットを閉じて
## 安全にサーバーを終了する。

import std/atomics
import asynchttpserver, asyncdispatch, streams, strutils, endians, os, times, random
import ws
import secp256k1
import lmdb
import protocol, crypto

# LMDB の環境とデータベースハンドル
var dbenv: LMDBEnv
var dbiProfiles: Dbi
var dbiEvents: Dbi

# Ctrl+C (SIGINT) を受けたことを記録するフラグ。
# シグナルハンドラは「シグナル割り込みの中」で実行されるため、
# ヒープ確保や echo などの操作は禁止されている。
# そのためアトミック変数への書き込みのみを行う。
var stopFlag: Atomic[bool]

# Ctrl+C を受けたときに OS から呼び出されるハンドラ。
# 安全のため、フラグを立てるだけで他の処理は行わない。
proc ctrlcHandler() {.noconv.} =
  stopFlag.store(true)
  
# LMDB の初期化処理
proc initDatabase() =
  # データ保存ディレクトリの作成
  if not dirExists("data"):
      createDir("data")
  
  # 環境の作成とオープン(複数のDBIを使うためmaxdbsを指定)
  dbenv = newLMDBEnv("data", maxdbs = 2)
  
  # トランザクションを開始してプロフィール用とイベント用のDBIを開く
  let txn = dbenv.newTxn()
  dbiProfiles = txn.dbiOpen("profiles", CREATE)
  dbiEvents = txn.dbiOpen("events", CREATE)
  txn.commit()
  
  echo "[DB] LMDB ストレージの初期化が完了しました(./data)"

# 各 HTTP リクエストを処理するコールバック。
# URL が "/" (ルートパス) で WebSocket アップグレードヘッダがあるときだけ
# WebSocket として扱い、それ以外は 404 を返す。
proc cb(req: Request) {.async, gcsafe.} =
    let isWebSocket = (req.url.path == "/") and req.headers.hasKey("upgrade") and req.headers.getOrDefault("upgrade").toLowerAscii() == "websocket"

    if isWebSocket:
        try:
            # HTTP リクエストを WebSocket 接続にアップグレード
            var ws = await newWebSocket(req)
            echo "[接続] クライアントが接続しました"

            # 接続が開いている限りパケットを受信し続ける
            while ws.readyState == Open:
                let packet = await ws.receiveStrPacket()
                if packet.len == 0:
                    continue  # 空パケットは無視

                echo "[受信] バイナリパケット受信(サイズ: ", packet.len, " bytes)"

                # パケットをストリームとして開き、先頭 1 バイトで種別を判別
                var strm = newStringStream(packet)
                let msgType = strm.readChar()

                # --- イベント投稿 (EVENT) の処理 ---
                if msgType == MsgTypeEvent:
                    try:
                        # バイナリデータからイベントを復元
                        let event = decodeEvent(strm)

                        # 署名を検証する。偽装・改ざんされたイベントは拒否する。
                        if not verifyContent(event.pubkey, event.content, event.signature):
                            echo "[拒否] 不正な署名のイベントを検知しました"
                            await ws.send("ERR: Invalid signature")
                            continue

                        # 検証に成功したイベントを保存
                        # ({.gcsafe.} ブロックで async クロージャ内の操作を許可)
                        {.gcsafe.}:
                            let txn = dbenv.newTxn()
                            let encoded = encodeEvent(event)
                            
                            if event.kind == KindMetaData:
                                # プロフィール(Kind 0): pubkey をキーにして保存
                                let pubKeyStr = $event.pubkey.toRawCompressed()
                                txn.put(dbiProfiles, pubKeyStr, encoded)
                                txn.commit()
                                echo "[保存] プロフィールを更新しました(Pubkey: ", pubKeyStr, ")"
                            else:
                                # タイムラインイベント(Kind 1, 2など): 一意なキー(現在時刻等)で保存
                                let timeKey = "evt_" & $epochTime() & "_" & $event.kind & "_" & $rand(100000)
                                txn.put(dbiEvents, timeKey, encoded)
                                txn.commit()
                                echo "[保存] タイムラインイベントを保存しました(Kind: ", event.kind, ")"
                                
                        await ws.send("OK: Event accepted")
                    except Exception as e:
                        echo "[エラー] イベントパース失敗: ", e.msg
                        await ws.send("ERR: Invalid event")

                # --- 購読要求 (REQ) の処理 ---
                elif msgType == MsgTypeReq:
                    try:
                        let subReq = decodeReq(strm)
                        echo "[購読] サブスクリプション要求受領 [ID: ", subReq.subId, "] (Kind: ", subReq.kind, ")"

                        # 保存済みイベントから条件に一致するものを走査
                        {.gcsafe.}:
                            let txn = dbenv.newTxn()
                            
                            # プロフィール(Kind 0)の配信処理
                            if subReq.kind == 0 or subReq.kind == KindMetaData:
                                let cursor = txn.cursorOpen(dbiProfiles)
                                var kVal, dVal: Val
                                
                                # カーソルで全プロフィールを走査
                                while cursorGet(cursor, addr kVal, addr dVal, NEXT) == 0:
                                    var retrievedPubkey = newString(int(kVal.mvSize))
                                    if kVal.mvSize > 0:
                                        copyMem(addr retrievedPubkey[0], kVal.mvData, int(kVal.mvSize))
                                        
                                    # tagKey によるフィルタリング
                                    if subReq.tagKey == "pubkey" and subReq.tagVal != "" and subReq.tagVal != retrievedPubkey:
                                        continue
                                        
                                    var encoded = newString(int(dVal.mvSize))
                                    if dVal.mvSize > 0:
                                        copyMem(addr encoded[0], dVal.mvData, int(dVal.mvSize))
                                        
                                    # PUSH パケット作成・送信
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
                                    await ws.send(pushData)
                                    
                                cursor.cursorClose()
                                
                            # タイムラインイベント(Kind 1, 2など)の配信処理
                            let cursorEvt = txn.cursorOpen(dbiEvents)
                            var ekVal, edVal: Val
                            
                            while cursorGet(cursorEvt, addr ekVal, addr edVal, NEXT) == 0:
                                var encoded = newString(int(edVal.mvSize))
                                if edVal.mvSize > 0:
                                    copyMem(addr encoded[0], edVal.mvData, int(edVal.mvSize))
                                    
                                # デコードして Kind を判定
                                var strmEvt = newStringStream(encoded)
                                let decodedEvt = decodeEvent(strmEvt)
                                
                                if decodedEvt.kind == KindMetaData:
                                    continue
                                
                                if subReq.kind == 0 or decodedEvt.kind != subReq.kind:
                                    continue
                                    
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
                                await ws.send(pushData)
                                
                            cursorEvt.cursorClose()
                            txn.commit()

                        # 保存済みイベントの配信が終わったことを通知
                        await ws.send("EOE: End of stored events for " & subReq.subId)
                    except Exception as e:
                        echo "[エラー] REQ処理失敗: ", e.msg

        # クライアントが接続を閉じたときのハンドリング
        except WebSocketClosedError:
            echo "[切断] クライアントが切断しました"
        except Exception as e:
            echo "[エラー] WebSocket例外: ", e.msg
    else:
        if req.url.path == "/":
            await req.respond(Http200, "クライアントから接続してください (Fodpr Relay Server)")
        else:
            await req.respond(Http404, "Not Found")

# サーバーのエントリーポイント。ポート 8000 で WebSocket を待ち受ける。
proc main() {.async.} =
    # LMDB の初期化(起動時に実行)
    initDatabase()

    let port = Port(8000)
    echo "================================================"
    echo " Fodpr Relay Server running on ws://0.0.0.0:", port.int, "/"
    echo " (Ctrl+C で安全に終了できます)"
    echo "================================================"

    # Ctrl+C で安全に終了できるようシグナルハンドラを登録
    setControlCHook(ctrlcHandler)

    var server = newAsyncHttpServer()

    # serve は無限ループするため、バックグラウンドタスクとして起動する
    var serveTask = server.serve(port, cb)

    # Ctrl+C が押されるまで待機
    while not stopFlag.load():
        await sleepAsync(100)

    echo "[終了] Ctrl+C を受信しました。サーバーを終了します..."

    # リスニングソケットを閉じる。
    # これにより serve 内部の acceptAddr が失敗し、serve ループが終了する。
    server.close()
    try:
        await serveTask
    except CatchableError:
        # close() による acceptAddr の失敗は正常な終了経路なので無視する
        discard

    # LMDB のクローズ
    dbenv.close(dbiProfiles)
    dbenv.close(dbiEvents)
    dbenv.envClose()
        
    echo "[終了] サーバーは正常に終了しました。"

# このファイルが直接実行されたときだけ main を起動する
when isMainModule:
    waitFor main()
