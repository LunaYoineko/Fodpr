import asyncdispatch, streams, times, strutils, endians
import ws
import protocol

proc main() {.async.} =
    let url = "ws://localhost:8000/ws"
    echo "=== Fodpr Client (Sender) ==="
    echo url, " へ接続中..."
    
    try:
        var ws = await newWebSocket(url)
        echo "接続成功！"
        
        var sampleEvent = FodprEvent(
            kind: 1,
            createdAt: uint64(getTime().toUnix()),
            pubkey: newSeq[byte](32),
            tags: @["p:target_user_id", "e:parent_event_id"],
            content: "Fodprのサブスクリプションテストメッセージ！",
            signature: newSeq[byte](64)
        )
        
        for i in 0..<32: sampleEvent.pubkey[i] = byte(i)
        for i in 0..<64: sampleEvent.signature[i] = byte(i * 2)
        
        var packet = ""
        packet.add(MsgTypeEvent)
        packet.add(encodeEvent(sampleEvent))
        
        echo "サーバーへバイナリパケットを送信中..."
        await ws.send(packet)
        let res1 = await ws.receiveStrPacket()
        echo "サーバーからの応答: ", res1
        
        var req = FodprReq(
            subId: "sub_123",
            kind: 1,
            tagKey: "",
            tagVal: ""
        )
        
        echo "サブスクリプション (REQ) を送信中..."
        await ws.send(encodeReq(req))
        
        while true:
            let respPacket = await ws.receiveStrPacket()
            if respPacket.len == 0: break
            
            if not respPacket.startsWith(MsgTypePush):
                echo "サーバー通知: ", respPacket
                if respPacket.startsWith("EOE:"):
                    break
                continue
                
            var strm = newStringStream(respPacket)
            let mType = strm.readChar()
            
            let idLenBytes = strm.readStr(2)
            var idNet, idLen: uint16
            copyMem(addr idNet, unsafeAddr idLenBytes[0], 2)
            bigEndian16(addr idLen, addr idNet)
            let subId = strm.readStr(int(idLen))
            
            let fetchedEvent = decodeEvent(strm)
            
            echo "--- [受信イベント (SubId: ", subId, ")] ---"
            echo " Kind : ", fetchedEvent.kind
            echo " Content : ", fetchedEvent.content
            echo "-------------------------------------------"
        
        ws.close()
        echo "テスト完了！"
    except Exception as e:
        echo "エラー発生: ", e.msg
        
when isMainModule:
    waitFor main()