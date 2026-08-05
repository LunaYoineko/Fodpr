## Fodpr.nim
## Fodpr プロトコルのクライアント（送信者）のデモ実装。
##
## 起動方法:  src/Fodpr
##
## 動作の流れ:
##   1. リレーサーバー (ws://localhost:8000/ws) に接続
##   2. 鍵ペアを生成し、テストメッセージに署名して EVENT を投稿
##   3. REQ (購読要求) を送信
##   4. サーバーが返してくる保存済みイベント (PUSH) を受信して表示

import asyncdispatch, streams, times, strutils, endians
import ws
import secp256k1
import protocol
import crypto

proc main() {.async.} =
    let url = "ws://localhost:8000/"
    echo "=== Fodpr Client (Sender) ==="
    echo url, " へ接続中..."

    try:
        # リレーサーバーへ WebSocket 接続を確立
        var ws = await newWebSocket(url)
        echo "接続成功！"

        # テスト用の鍵ペアを生成（署名・検証に使用）
        var kp = generateFodprKey()
        let content = "Fodprのサブスクリプションテストメッセージ！"

        # テストイベントを作成。
        let profileContent = """{"name": "FodprTaro","about": "バイナリプロトコル始動"}""" 
        var profileEvent = FodprEvent(
            kind: KindMetaData,
            createdAt: uint64(getTime().toUnix()),
            pubkey: kp.publicKey,
            tags: @[],
            content: profileContent,
            signature: signContent(kp.privateKey, profileContent)
        )
        
        var pPacket = ""
        pPacket.add(MsgTypeEvent)
        pPacket.add(encodeEvent(profileEvent))
        await ws.send(pPacket)
        let res1 = await ws.receiveStrPacket()
        echo "Kind0送信結果: ", res1
                
        # content に対する署名は秘密鍵で生成し、公開鍵も同梱する。
        var sampleEvent = FodprEvent(
            kind: 1,
            createdAt: uint64(getTime().toUnix()),
            pubkey: kp.publicKey,
            tags: @["p:target_user_id", "e:parent_event_id"],
            content: content,
            signature: signContent(kp.privateKey, content)
        )

        # EVENT パケット（種別バイト + エンコード済みイベント）を組み立てて送信
        var packet = ""
        packet.add(MsgTypeEvent)
        packet.add(encodeEvent(sampleEvent))
        await ws.send(packet)
        let res2 = await ws.receiveStrPacket()
        echo "Kind1送信結果: ", res2
        
        let dummyImageBytes = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR..."
        
        var mediaEvent = FodprEvent(
            kind: KindMedia,
            createdAt: uint64(getTime().toUnix()),
            pubkey: kp.publicKey,
            tags: @["m:image/png", "size:1024"],
            content: dummyImageBytes,
            signature: signContent(kp.privateKey, dummyImageBytes)
        )
        
        var mPacket = ""
        mPacket.add(MsgTypeEvent)
        mPacket.add(encodeEvent(mediaEvent))
        await ws.send(mPacket)
        let res3 = await ws.receiveStrPacket()
        echo "Kind2送信結果: ", res3

        let targetPubKeyStr = $kp.publicKey.toRawCompressed()
        
        # 購読要求 (REQ) を作成。
        # kind=1 のイベントを購読し、タグによる絞り込みは行わない。
        var req = FodprReq(
            subId: "sub_metadata_only",
            kind: KindMedia,
            tagKey: "pubkey",
            tagVal: targetPubKeyStr
        )

        echo "サブスクリプション (REQ) を送信中..."
        await ws.send(encodeReq(req))

        # サーバーからの応答を逐次受信して処理
        while true:
            let respPacket = await ws.receiveStrPacket()
            if respPacket.len == 0: break  # 空パケットで終了

            # PUSH (0x81) 以外はテキスト応答なのでそのまま表示
            if not respPacket.startsWith(MsgTypePush):
                echo "サーバー通知: ", respPacket
                if respPacket.startsWith("EOE:"):
                    break  # 保存済みイベント配信の終了通知でループ終了
                continue

            # PUSH パケットの解析:
            #   MsgTypePush(1) | subIdLen(2) | subId | イベント本体
            var strm = newStringStream(respPacket)
            let mType = strm.readChar()  # 種別バイトは読み飛ばし

            # subId を復元
            let idLenBytes = strm.readStr(2)
            var idNet, idLen: uint16
            copyMem(addr idNet, unsafeAddr idLenBytes[0], 2)
            bigEndian16(addr idLen, addr idNet)
            let subId = strm.readStr(int(idLen))

            # 残りをイベントとしてデコード
            let fetchedEvent = decodeEvent(strm)

            echo "--- [受信イベント (SubId: ", subId, ")] ---"
            echo " PubKey : ", $fetchedEvent.pubkey.toRawCompressed()
            echo " Kind : ", fetchedEvent.kind
            if fetchedEvent.kind == KindMedia:
                echo " Content : [バイナリデータ / サイズ: ", fetchedEvent.content.len, " bytes]"
            else:
                echo " Content : ", fetchedEvent.content
            echo "-------------------------------------------"

        ws.close()
        echo "テスト完了！"
    except Exception as e:
        echo "エラー発生: ", e.msg

# このファイルが直接実行されたときだけ main を起動する
when isMainModule:
    waitFor main()
