## fodpr_client.nim
## Fodpr プロトコルのクライアント（送信者）のサンプル実装。
##
## 起動方法:  nim c -r examples/fodpr_client.nim   (要: リレーサーバー起動中)
##
## 動作の流れ:
##   1. リレーサーバー (ws://localhost:8000/) に接続
##   2. 鍵ペアを生成し、JSON / String / Binary の 3 タイプのイベントに署名して投稿
##   3. REQ (購読要求, TransType: All) を送信
##   4. サーバーが返してくる保存済みイベント (PUSH) を受信し、
##      送信タイプごとに適した配信方法で表示
##
## 注意: このサンプルは ws ライブラリ (WebSocket) を使うため、
##       wss:// 接続を有効にする ssl が config.nims で定義されている。

import asyncdispatch, streams, times, strutils, endians, json
import ws
import Fodpr

# 送信タイプに応じた配信方法で受信イベントを表示する。
#   - TransTypeJSON   : JSON としてパースして整形表示
#   - TransTypeString : そのまま文字列として表示
#   - TransTypeBinary : そのまま表示せずサイズのみ表示
proc renderEvent(subId: string, evt: FodprEvent) =
    echo "--- [受信イベント (SubId: ", subId, ")] ---"
    echo " PubKey     : ", $evt.pubkey.toRawCompressed()
    echo " TransType  : ", transTypeName(evt.transType), " (", evt.transType, ")"
    case evt.transType
    of TransTypeJSON:
        try:
            echo " Content (JSON) :"
            echo pretty(parseJson(evt.content))
        except:
            echo " Content (JSON) : ", evt.content
    of TransTypeString:
        echo " Content : ", evt.content
    of TransTypeBinary:
        echo " Content : [バイナリデータ / サイズ: ", evt.content.len, " bytes]"
    else:
        echo " Content : (不明な送信タイプ)"
    echo " Tags     : ", evt.tags
    echo "-------------------------------------------"

proc main() {.async.} =
    let url = "ws://localhost:8000/"
    echo "=== Fodpr Client (Sender) ==="
    echo url, " へ接続中..."

    try:
        # リレーサーバーへ WebSocket 接続を確立
        var ws = await newWebSocket(url)
        echo "接続成功！"

        # テスト用の鍵ペアを生成（署名・検証に使用）
        let kp = generateFodprKey()

        # --- 1. TransTypeJSON: 構造化データ (JSON) ---
        let profileContent = """{"name": "FodprTaro","about": "バイナリプロトコル始動"}"""
        var jsonEvent = FodprEvent(
            transType: TransTypeJSON,
            createdAt: uint64(getTime().toUnix()),
            pubkey: kp.publicKey,
            tags: @[],
            content: profileContent,
            signature: signContent(kp.privateKey, profileContent)
        )
        var jPacket = ""
        jPacket.add(MsgTypeEvent)
        jPacket.add(encodeEvent(jsonEvent))
        await ws.send(jPacket, Binary)
        echo "JSON 送信結果   : ", await ws.receiveStrPacket()

        # --- 2. TransTypeString: テキスト投稿 (UTF-8 文字列) ---
        let textContent = "Fodprのサブスクリプションテストメッセージ！"
        var stringEvent = FodprEvent(
            transType: TransTypeString,
            createdAt: uint64(getTime().toUnix()),
            pubkey: kp.publicKey,
            tags: @["p:target_user_id", "e:parent_event_id"],
            content: textContent,
            signature: signContent(kp.privateKey, textContent)
        )
        var sPacket = ""
        sPacket.add(MsgTypeEvent)
        sPacket.add(encodeEvent(stringEvent))
        await ws.send(sPacket, Binary)
        echo "String 送信結果 : ", await ws.receiveStrPacket()

        # --- 3. TransTypeBinary: バイナリデータ（画像など） ---
        let dummyImageBytes = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR..."
        var binaryEvent = FodprEvent(
            transType: TransTypeBinary,
            createdAt: uint64(getTime().toUnix()),
            pubkey: kp.publicKey,
            tags: @["m:image/png", "size:1024"],
            content: dummyImageBytes,
            signature: signContent(kp.privateKey, dummyImageBytes)
        )
        var bPacket = ""
        bPacket.add(MsgTypeEvent)
        bPacket.add(encodeEvent(binaryEvent))
        await ws.send(bPacket, Binary)
        echo "Binary 送信結果 : ", await ws.receiveStrPacket()

        # --- 4. REQ: すべてのタイプを購読して各配信方法を確認 ---
        var req = FodprReq(
            subId: "sub_all",
            transType: TransTypeAll,
            tagKey: "",
            tagVal: ""
        )
        echo ""
        echo "サブスクリプション (REQ, TransType: All) を送信中..."
        await ws.send(encodeReq(req), Binary)

        # サーバーからの応答を逐次受信して処理
        while true:
            # テキストフレーム (OK / EOE などの通知) とバイナリフレーム (PUSH) を区別する
            let (opcode, respPacket) = await ws.receivePacket()
            if respPacket.len == 0:
                break  # 空パケットで終了

            if opcode != Binary:
                # テキスト通知はそのまま表示
                echo "サーバー通知: ", respPacket
                if respPacket.startsWith("EOE:"):
                    break  # 保存済みイベント配信の終了通知でループ終了
                continue

            # バイナリフレームは PUSH パケットとして解析
            #   MsgTypePush(1) | subIdLen(2) | subId | イベント本体
            var strm = newStringStream(respPacket)
            discard strm.readChar()  # 種別バイトは読み飛ばし

            # subId を復元
            let idLenBytes = strm.readStr(2)
            var idNet, idLen: uint16
            copyMem(addr idNet, unsafeAddr idLenBytes[0], 2)
            bigEndian16(addr idLen, addr idNet)
            let subId = strm.readStr(int(idLen))

            # 残りをイベントとしてデコードして配信方法で表示
            let fetchedEvent = decodeEvent(strm)
            renderEvent(subId, fetchedEvent)

        ws.close()
        echo ""
        echo "テスト完了！"
    except Exception as e:
        echo "エラー発生: ", e.msg

# このファイルが直接実行されたときだけ main を起動する
when isMainModule:
    waitFor main()
