## protocol_demo.nim
## protocol.nim を使ったサンプルプログラム。
##
## サーバー不要でオフライン実行できる。以下の流れを試せる:
##   1. 鍵ペア生成 (crypto.nim)
##   2. 署名付きイベントの作成 (FodprEvent + signContent)
##   3. encodeEvent → decodeEvent によるエンコード / デコード (ラウンドトリップ)
##   4. 署名検証 (verifyContent)
##   5. 購読要求 (FodprReq) の encodeReq / decodeReq
##
## ビルド/実行:
##   nim c -r examples/protocol_demo.nim   (ルートディレクトリで実行)

import times, streams
import protocol, crypto

proc main() =
  # ------------------------------------------------------------------
  # 1. 鍵ペア生成
  # ------------------------------------------------------------------
  echo "=== 1. 鍵ペア生成 ==="
  let kp = generateFodprKey()
  echo "秘密鍵 (fsec 形式): ", fsecEncode(kp.privateKey)
  echo "公開鍵 (fpub 形式): ", fpubEncode(kp.publicKey)

  # ------------------------------------------------------------------
  # 2. 署名付きイベントの作成
  # ------------------------------------------------------------------
  echo ""
  echo "=== 2. イベント作成と署名 ==="
  let content = "こんにちは、Fodpr！"
  let event = FodprEvent(
    kind: 1,                              # イベント種別
    createdAt: uint64(getTime().toUnix()),# 作成時刻 (Unix 秒)
    pubkey: kp.publicKey,                 # 送信者の公開鍵
    tags: @["p:target_user", "e:parent"], # タグ
    content: content,                     # 本文
    signature: signContent(kp.privateKey, content) # 本文への署名
  )
  echo "Content : ", event.content
  echo "Kind    : ", event.kind
  echo "Tags    : ", event.tags

  # ------------------------------------------------------------------
  # 3. encodeEvent → decodeEvent (ラウンドトリップ)
  # ------------------------------------------------------------------
  echo ""
  echo "=== 3. エンコード / デコード ==="
  # イベントをバイナリ列へ変換
  let encoded = encodeEvent(event)
  echo "エンコード結果のサイズ: ", encoded.len, " bytes"
  # バイト列をストリームとして開き、元のイベントへ復元
  var strm = newStringStream(encoded)
  let decoded = decodeEvent(strm)
  echo "デコード後の Content : ", decoded.content
  echo "デコード後の Kind    : ", decoded.kind
  echo "デコード後の Tags    : ", decoded.tags

  # ------------------------------------------------------------------
  # 4. 署名検証
  # ------------------------------------------------------------------
  echo ""
  echo "=== 4. 署名検証 ==="
  let valid = verifyContent(decoded.pubkey, decoded.content, decoded.signature)
  echo "署名検証の結果: ", valid

  # ------------------------------------------------------------------
  # 5. 購読要求 (REQ) のエンコード / デコード
  # ------------------------------------------------------------------
  echo ""
  echo "=== 5. REQ エンコード / デコード ==="
  let req = FodprReq(
    subId: "sub_1",
    kind: 1,
    tagKey: "p",
    tagVal: "target_user"
  )
  # REQ をバイナリ列へ変換してから復元する
  # (encodeReq は先頭に種別バイト MsgTypeReq を付与するため、
  #  デコード前に読み飛ばす)
  let reqEnc = encodeReq(req)
  var reqStrm = newStringStream(reqEnc)
  discard reqStrm.readChar()  # 種別バイトを読み飛ばし
  let reqDec = decodeReq(reqStrm)
  echo "subId : ", reqDec.subId
  echo "kind  : ", reqDec.kind
  echo "tagKey: ", reqDec.tagKey
  echo "tagVal: ", reqDec.tagVal

  echo ""
  echo "サンプル実行完了！"

when isMainModule:
  main()
