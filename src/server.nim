import asynchttpserver, asyncdispatch, streams, strutils, endians
import ws

import protocol, crypto

var storedEvents: seq[FodprEvent] = @[]

proc cb(req: Request) {.async, gcsafe.} =
    if req.url.path == "/ws":
        try:
            var ws = await newWebSocket(req)
            echo "[接続] クライアントが接続しました"
            
            while ws.readyState == Open:
                let packet = await ws.receiveStrPacket()
                if packet.len == 0:
                    continue
                    
                echo "[受信] バイナリパケット受信(サイズ: ", packet.len, " bytes)"
                
                var strm = newStringStream(packet)
                let msgType = strm.readChar()
                
                if msgType == MsgTypeEvent:
                    try:
                        let event = decodeEvent(strm)
                        
                        if not verifyContent(event.pubkey, event.content, event.signature):
                            echo "[拒否] 不正な署名のイベントを検知しました"
                            await ws.send("ERR: Invalid signature")
                            continue
                        
                        {.gcsafe.}:
                            storedEvents.add(event)
                            let seLen = storedEvents.len
                          
                        echo "[保存] イベントを受信・保存しました"
                        echo "(総数: ", seLen, ")"
                        echo " Content: ", event.content
                        await ws.send("OK: Event accepted")
                    except Exception as e:
                        echo "[エラー] イベントパース失敗: ", e.msg
                        await ws.send("ERR: Invalid event")
                
                elif msgType == MsgTypeReq:
                    try:
                        let subReq = decodeReq(strm)
                        echo "[購読] サブスクリプション要求受領 [ID: ", subReq.subId, "] (Kind: ", subReq.kind, ")"
                        
                        {.gcsafe.}:
                            for ev in storedEvents:
                              if subReq.kind == 0 or ev.kind == subReq.kind:
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
                                    
                                pushData.add(encodeEvent(ev))
                                    
                                await ws.send(pushData)
                                
                        await ws.send("EOE: End of stored events for " & subReq.subId)
                    except Exception as e:
                        echo "[エラー] REQ処理失敗: ", e.msg
                    
        except WebSocketClosedError:
            echo "[切断] クライアントが切断しました"
        except Exception as e:
            echo "[エラー] WebSocket例外: ", e.msg
    else:
        await req.respond(Http404, "Fodpr Relay Server - Endpoint is /ws")
        
proc main() {.async.} =
    let port = Port(8000)
    
    echo "================================================"
    echo " Fodpr Relay Server running on ws://0.0.0.0:", port.int, "/ws"
    echo "================================================"
    
    var server = newAsyncHttpServer()
    waitFor server.serve(port, cb)
            
when isMainModule:
    waitFor main()