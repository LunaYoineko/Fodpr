## f2f_client.nim
## Fodpr F2F ネットワークのサンプルクライアント実装
##
## インビテーションコードによる接続、ピアキャッシュ管理、
## 完全P2P通信のデモを行う。
##
## 実行方法:
##   nim c -r examples/f2f_client.nim

import asyncdispatch, times, strutils, os
import Fodpr

proc main() {.async.} =
  echo "=== Fodpr F2F Client Demo ==="
  echo ""

  # 1. 鍵ペア生成
  echo "1. 鍵ペアを生成中..."
  let myKey = generateFodprKey()
  echo "   公開鍵: ", fpubEncode(myKey.publicKey)
  echo "   秘密鍵: ", fsecEncode(myKey.privateKey)
  echo ""

  # 2. ローカルキャッシュ読み込み
  echo "2. ローカルピアキャッシュを読み込み中..."
  var cache = loadCache()
  echo "   キャッシュバージョン: ", cache.version
  echo "   保存ピア数: ", cache.peers.len
  echo "   最終更新: ", cache.lastUpdated.int64.fromUnix().format("yyyy-MM-dd HH:mm:ss")
  echo ""

  # 3. キャッシュからピア選択
  if cache.peers.len > 0:
    echo "3. キャッシュから接続候補を選択..."
    let candidates = selectPeers(cache, 3)
    for i, p in candidates:
      echo "   [", i, "] ", fpubEncode(p.pubkey), " (信頼度: ", p.reliabilityScore, ", 最終接続: ", p.lastSeen.int64.fromUnix().format("HH:mm:ss"), ")"
  else:
    echo "3. キャッシュが空です。インビテーションまたはシードフォールバックが必要です。"
  echo ""

  # 4. インビテーションコード生成デモ
  echo "4. インビテーションコード生成デモ..."
  let targetPeer = PeerInfo(
    pubkey: myKey.publicKey,
    addresses: @["[2001:db8::1]:8000", "wss://example.com/ws"],
    lastSeen: uint64(epochTime()),
    identityTrust: 1.0,
    reliabilityScore: 1.0
  )

  let inv = invitation.createInvitation(myKey.privateKey, targetPeer, 3600, INVITATION_SCOPE_WOT)
  let invCode = invitation.encodeInvitation(inv)
  let invUri = invitation.encodeInvitationUri(inv)

  echo "   生成されたコード: ", invCode
  echo "   URI形式: ", invUri
  echo ""

  # 5. インビテーションコード検証デモ
  echo "5. インビテーションコード検証デモ..."
  let decoded = invitation.decodeInvitation(invCode)
  let valid = invitation.verifyInvitation(decoded)
  echo "   検証結果: ", if valid: "有効" else: "無効"
  echo "   発行者: ", fpubEncode(decoded.issuer)
  echo "   接続先: ", fpubEncode(decoded.targetPeer.pubkey)
  echo "   有効期限: ", decoded.expiresAt.int64.fromUnix().format("yyyy-MM-dd HH:mm:ss")
  echo "   スコープ: ", if decoded.scope == INVITATION_SCOPE_WOT: "WoT招待" else: "単発接続"
  echo ""

  # 6. QRコード用テキスト出力
  echo "6. QRコード用テキスト:"
  echo "   ", invitation.encodeInvitationQr(inv)
  echo ""

  # 7. ピアリスト作成・署名デモ
  echo "7. ピアリスト交換デモ..."
  var peerList = PeerList(
    version: cache.version + 1,
    peerCount: uint16(min(cache.peers.len, MAX_CACHE_SIZE)),
    peers: cache.peers[0..<min(cache.peers.len, MAX_CACHE_SIZE)],
    signature: emptySignature()
  )
  peerList.signature = signPeerList(myKey.privateKey, peerList)
  let plValid = verifyPeerList(peerList)
  echo "   ピアリスト署名検証: ", if plValid: "成功" else: "失敗"
  echo "   含まれるピア数: ", peerList.peerCount
  echo ""

  # 8. WoT紹介メッセージ作成デモ
  echo "8. WoT紹介メッセージ作成デモ..."
  let newPeer = PeerInfo(
    pubkey: generateFodprKey().publicKey,
    addresses: @["[2001:db8::2]:8000"],
    lastSeen: uint64(epochTime()),
    identityTrust: 0.8,
    reliabilityScore: 0.8
  )
  let intro = discovery.createWoTIntroduction(myKey.privateKey, newPeer)
  let introValid = verifyWoTIntro(intro)
  echo "   紹介メッセージ署名検証: ", if introValid: "成功" else: "失敗"
  echo "   紹介者: ", fpubEncode(intro.introducer)
  echo "   新ピア: ", fpubEncode(intro.newPeer.pubkey)
  echo ""

  # 9. IPv6一時アドレス生成デモ
  echo "9. IPv6一時アドレス生成デモ..."
  let tempAddr = transport.generateIpv6TempAddress()
  echo "   アドレス: ", tempAddr.address
  echo "   プレフィックス: ", tempAddr.prefix
  echo "   作成時刻: ", tempAddr.createdAt.int64.fromUnix().format("HH:mm:ss")
  echo "   有効期限: ", tempAddr.expiresAt.int64.fromUnix().format("HH:mm:ss")
  echo "   有効性: ", if transport.isTempAddressValid(tempAddr): "有効" else: "期限切れ"
  echo ""

  # 10. WebRTC設定デモ
  echo "10. WebRTC設定..."
  let config = transport.defaultWebRTCConfig()
  echo "   ICEサーバー: ", config.iceServers.join(", ")
  echo "   IPv6のみ: ", config.ipv6Only
  echo "   一時アドレス: ", config.tempAddressEnabled
  echo ""

  # 11. シードフォールバック (デモ: 実際には接続しない)
  echo "11. シードフォールバック (デモ)..."
  echo "   デフォルトシードリレー:"
  for seed in DEFAULT_SEED_RELAYS:
    echo "     - ", seed
  echo "   ※ 実際の接続は行いません (スタブ実装)"
  echo ""

  # 12. キャッシュ保存
  echo "12. キャッシュを保存..."
  saveCache(cache)
  echo "   保存完了: ~/.fodpr/cache/peer_cache.json"
  echo ""

  echo "=== デモ完了 ==="
  echo ""
  echo "次のステップ:"
  echo "  - 実際のP2P接続には transport.nim の establishF2FConnection を使用"
  echo "  - シグナリングには signaling.nim の createF2FOffer 等を使用"
  echo "  - WoTベースのピア発見には discovery.nim / wot.nim を使用"

when isMainModule:
  waitFor main()