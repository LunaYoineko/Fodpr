## protocol_demo.nim
## protocol.nim を使ったサンプルプログラム。
##
## サーバー不要でオフライン実行できる。以下の流れを試せる:
##   1. 鍵ペア生成 (crypto.nim)
##   2. 送信タイプ (TransTypeJSON / String / Binary) ごとの署名付きイベント作成
##   3. encodeEvent → decodeEvent によるエンコード / デコード (ラウンドトリップ)
##   4. 署名検証 (verifyContent)
##   5. 購読要求 (FodprReq) の encodeReq / decodeReq
##
## ビルド/実行:
##   nim c -r examples/protocol_demo.nim   (ルートディレクトリで実行)

import times, streams
import protocol, crypto

# 送信タイプごとのイベントを生成するヘルパー
proc makeEvent(transType: uint16, content: string, kp: FodprKeyPair): FodprEvent =
  return FodprEvent(
    transType: transType,
    createdAt: uint64(getTime().toUnix()),
    pubkey: kp.publicKey,
    tags: @["p:target_user", "e:parent"],
    content: content,
    signature: signContent(kp.privateKey, content)
  )

proc main() =
  # ------------------------------------------------------------------
  # 1. 鍵ペア生成
  # ------------------------------------------------------------------
  echo "=== 1. 鍵ペア生成 ==="
  let kp = generateFodprKey()
  echo "秘密鍵 (fsec 形式): ", fsecEncode(kp.privateKey)
  echo "公開鍵 (fpub 形式): ", fpubEncode(kp.publicKey)

  # ------------------------------------------------------------------
  # 2. 送信タイプごとの署名付きイベント作成
  # ------------------------------------------------------------------
  echo ""
  echo "=== 2. イベント作成と署名 ==="

  # TransTypeJSON: プロフィールなどの構造化データ
  let jsonEvent = makeEvent(TransTypeJSON, """{"name": "FodprTaro","about": "バイナリプロトコル始動"}""", kp)
  echo "TransType : ", transTypeName(jsonEvent.transType)
  echo "Content   : ", jsonEvent.content

  # TransTypeString: テキスト投稿
  let strEvent = makeEvent(TransTypeString, "こんにちは、Fodpr！", kp)
  echo "TransType : ", transTypeName(strEvent.transType)
  echo "Content   : ", strEvent.content

  # TransTypeBinary: バイナリデータ（画像など）
  let binEvent = makeEvent(TransTypeBinary, "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...", kp)
  echo "TransType : ", transTypeName(binEvent.transType)
  echo "Content   : [バイナリデータ / サイズ: ", binEvent.content.len, " bytes]"

  # ------------------------------------------------------------------
  # 3. encodeEvent → decodeEvent (ラウンドトリップ)
  # ------------------------------------------------------------------
  echo ""
  echo "=== 3. エンコード / デコード (String イベントで確認) ==="
  # イベントをバイナリ列へ変換
  let encoded = encodeEvent(strEvent)
  echo "エンコード結果のサイズ: ", encoded.len, " bytes"
  # バイト列をストリームとして開き、元のイベントへ復元
  var strm = newStringStream(encoded)
  let decoded = decodeEvent(strm)
  echo "デコード後の TransType : ", transTypeName(decoded.transType)
  echo "デコード後の Content   : ", decoded.content
  echo "デコード後の Tags      : ", decoded.tags

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
    transType: TransTypeAll,
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
  echo "subId    : ", reqDec.subId
  echo "transType: ", transTypeName(reqDec.transType)
  echo "tagKey   : ", reqDec.tagKey
  echo "tagVal   : ", reqDec.tagVal

  echo ""
  echo "サンプル実行完了！"

when isMainModule:
  main()
