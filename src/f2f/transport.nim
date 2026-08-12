## transport.nim
## F2F: トランスポート層 (IPv6一時アドレス + WebRTCデータチャネル)
##
## IPv6プライバシー拡張 (RFC 4941) を利用した一時アドレス生成と
## WebRTCデータチャネルによる完全P2P通信を提供する。

import asyncdispatch, net, ws, times, random, strutils, streams
import protocol, crypto

const
  IPV6_TEMP_PREFIX_LEN = 64  # 一時アドレスのプレフィックス長
  IPV6_ROTATION_INTERVAL_MS = 300_000  # 5分ごとにローテーション
  CONNECTION_TIMEOUT_MS = 15000
  MAX_RETRIES = 3
  DATA_CHANNEL_BUFFER_SIZE = 16384

# Forward declarations for SDP functions
proc createSdpOffer*(localAddr: string, iceServers: seq[string]): string
proc createSdpAnswer*(localAddr: string, iceServers: seq[string]): string
proc extractAddressFromSdp*(sdp: string): string
proc generateFingerprint*(): string

type
  # WebRTC 設定 (スタブ - 実際は JavaScript WASM またはネイティブ実装)
  WebRTCConfig* = object
    iceServers*: seq[string]      # STUN/TURN サーバー (初期接続用のみ)
    ipv6Only*: bool               # IPv6のみ使用
    tempAddressEnabled*: bool     # 一時アドレス使用

  # WebRTC データチャネル (抽象化 - 実装はプラットフォーム依存)
  WebRTCDataChannel* = object
    label*: string
    ordered*: bool
    maxRetransmits*: int
    onOpen*: proc() {.async.}
    onClose*: proc() {.async.}
    onMessage*: proc(data: string) {.async.}
    onError*: proc(error: string) {.async.}

# WebRTCデータチャネル送信 (スタブ)
proc send*(channel: WebRTCDataChannel, data: string, opcode: Opcode = Opcode.Binary): Future[bool] {.async.} =
  # スタブ実装 - 実際の実装では WebRTC データチャネルの send メソッドを呼ぶ
  echo "Sending data via WebRTC data channel (stub): ", data.len, " bytes"
  return true

# WebRTCデータチャネル受信 (スタブ)
proc receive*(channel: WebRTCDataChannel): Future[string] {.async.} =
  # スタブ実装 - 実際の実装では WebRTC データチャネルからデータを受信
  echo "Receiving data via WebRTC data channel (stub)"
  return ""

# F2F 接続
type
  F2FConnection* = object
    dataChannel*: WebRTCDataChannel
    remotePubkey*: SkPublicKey
    localIpv6Temp*: string
    remoteIpv6Temp*: string
    seq*: uint64
    state*: ConnectionState
    createdAt*: uint64
    lastActivity*: uint64
    localConfig*: WebRTCConfig
    remoteConfig*: WebRTCConfig

  ConnectionState* = enum
    Connecting,    # 接続中
    Connected,     # 確立済み
    Disconnected,  # 切断済み
    Failed         # 失敗

  # IPv6 一時アドレス情報
  Ipv6TempAddress* = object
    address*: string      # 完全な IPv6 アドレス
    prefix*: string       # ネットワークプレフィックス
    interfaceId*: string  # インターフェースID (ランダム生成)
    createdAt*: uint64
    expiresAt*: uint64

# カスタム例外
type
  TransportError* = object of CatchableError

# ---------------------------------------------------------------------------
# IPv6 一時アドレス生成 (RFC 4941)
# ---------------------------------------------------------------------------

# 現在のネットワークプレフィックスを取得 (OS依存 - スタブ)
proc getCurrentIpv6Prefix*(): string =
  # 実際の実装では OS のネットワークインターフェースから取得
  # 例: "2001:db8:1234:5678::/64"
  # スタブでは固定値を返す
  return "2001:db8::/64"

# ランダムなインターフェースIDを生成 (64bit)
proc generateRandomInterfaceId*(): string =
  random.randomize()
  let part1 = random.rand(int(0xFFFFFFFF))
  let part2 = random.rand(int(0xFFFFFFFF))
  return $part1.toHex(8) & $part2.toHex(8)

# 一時IPv6アドレスを生成
proc generateIpv6TempAddress*(): Ipv6TempAddress =
  let prefix = getCurrentIpv6Prefix()
  let interfaceId = generateRandomInterfaceId()
  let now = uint64(epochTime())
  let expiresAt = now + (IPV6_ROTATION_INTERVAL_MS div 1000)

  # プレフィックスからネットワーク部分を抽出
  var networkPart = prefix
  if networkPart.endsWith("::/64"):
    networkPart = networkPart[0..^6]  # "::/64" を除去

  # 完全なアドレス構築
  let address = networkPart & ":" & interfaceId[0..3] & ":" &
                interfaceId[4..7] & ":" & interfaceId[8..11] & ":" & interfaceId[12..15]

  return Ipv6TempAddress(
    address: "[" & address & "]",
    prefix: prefix,
    interfaceId: interfaceId,
    createdAt: now,
    expiresAt: expiresAt
  )

# 一時アドレスが有効かチェック
proc isTempAddressValid*(address: Ipv6TempAddress): bool =
  let now = uint64(epochTime())
  return now < address.expiresAt

# 一時アドレスをローテーション
proc rotateIpv6Address*(): Ipv6TempAddress =
  return generateIpv6TempAddress()

# ---------------------------------------------------------------------------
# WebRTC データチャネル抽象化 (スタブ実装)
# ---------------------------------------------------------------------------

# 実際のWebRTC実装へのプレースホルダ
# 本番では以下のいずれかを使用:
#   - wasm-bindgen で JavaScript WebRTC API を呼ぶ
#   - libwebrtc ネイティブバインディング
#   - pion/webrtc (Go) 等のライブラリとの FFI

proc createWebRTCDataChannel*(
  config: WebRTCConfig,
  label: string = "fodpr-f2f"
): WebRTCDataChannel =
  # スタブ実装
  result = WebRTCDataChannel(
    label: label,
    ordered: true,
    maxRetransmits: 0,
    onOpen: nil,
    onClose: nil,
    onMessage: nil,
    onError: nil
  )

# データチャネル接続 (Offer/Answer 交換後)
proc connectDataChannel*(
  channel: WebRTCDataChannel,
  remoteSdp: string
): Future[bool] {.async.} =
  # 実際の実装では:
  # 1. setRemoteDescription(remoteSdp)
  # 2. ICE candidate 交換
  # 3. onopen 待ち
  echo "Connecting data channel (stub)..."
  await sleepAsync(100)
  return true

# データ送信
proc sendData*(
  channel: WebRTCDataChannel,
  data: string
): Future[bool] {.async.} =
  try:
    await channel.onMessage(data)  # スタブ: コールバック呼び出し
    return true
  except:
    return false

# データ受信 (コールバック経由)
# onMessage フィールドに直接代入して使用

# ---------------------------------------------------------------------------
# F2F 接続確立フロー
# ---------------------------------------------------------------------------

# F2F 接続確立 (発信側)
proc establishF2FConnection*(
  localPriv: SkSecretKey,
  remotePeer: PeerInfo,
  config: WebRTCConfig
): Future[tuple[success: bool, conn: F2FConnection]] {.async.} =
  let localPubkey = localPriv.toPublicKey()

  # 1. ローカル一時アドレス生成
  let localTempAddr = generateIpv6TempAddress()

  # 2. WebRTC 設定
  let dataChannel = createWebRTCDataChannel(config)

  # 3. Offer 生成 (SDP にローカル一時アドレスを含める)
  # 実際の実装では createOffer() で SDP 生成
  let localSdp = createSdpOffer(localTempAddr.address, config.iceServers)

  # 4. F2F シグナリングで Offer 送信
  # ここでは既に確立済みのチャネル経由で送信すると仮定
  # 実際には signaling.nim を使用

  # 5. Answer 受信待ち
  # ...

  # 6. ICE candidate 交換
  # ...

  # 7. 接続確立
  let connected = await connectDataChannel(dataChannel, "")  # Answer SDP

  if not connected:
    return (false, F2FConnection(
      dataChannel: dataChannel,
      remotePubkey: remotePeer.pubkey,
      localIpv6Temp: localTempAddr.address,
      remoteIpv6Temp: "",
      seq: 0,
      state: Failed,
      createdAt: uint64(epochTime()),
      lastActivity: uint64(epochTime()),
      localConfig: config,
      remoteConfig: config
    ))

  let conn = F2FConnection(
    dataChannel: dataChannel,
    remotePubkey: remotePeer.pubkey,
    localIpv6Temp: localTempAddr.address,
    remoteIpv6Temp: if remotePeer.addresses.len > 0: remotePeer.addresses[0] else: "",
    seq: 0,
    state: Connected,
    createdAt: uint64(epochTime()),
    lastActivity: uint64(epochTime()),
    localConfig: config,
    remoteConfig: config
  )

  return (true, conn)

# F2F 接続確立 (着信側)
proc acceptF2FConnection*(
  localPriv: SkSecretKey,
  remotePubkey: SkPublicKey,
  offerSdp: string,
  config: WebRTCConfig
): Future[tuple[success: bool, conn: F2FConnection, answerSdp: string]] {.async.} =
  let localPubkey = localPriv.toPublicKey()

  # 1. ローカル一時アドレス生成
  let localTempAddr = generateIpv6TempAddress()

  # 2. WebRTC 設定
  let dataChannel = createWebRTCDataChannel(config)

  # 3. Offer からリモートアドレス抽出
  let remoteAddr = extractAddressFromSdp(offerSdp)

  # 4. Answer 生成
  let answerSdp = createSdpAnswer(localTempAddr.address, config.iceServers)

  # 5. Answer 送信 (シグナリング経由)
  # ...

  # 6. 接続確立
  let connected = await connectDataChannel(dataChannel, answerSdp)

  if not connected:
    return (false, F2FConnection(
      dataChannel: dataChannel,
      remotePubkey: remotePubkey,
      localIpv6Temp: localTempAddr.address,
      remoteIpv6Temp: remoteAddr,
      seq: 0,
      state: Failed,
      createdAt: uint64(epochTime()),
      lastActivity: uint64(epochTime()),
      localConfig: config,
      remoteConfig: config
    ), "")

  let conn = F2FConnection(
    dataChannel: dataChannel,
    remotePubkey: remotePubkey,
    localIpv6Temp: localTempAddr.address,
    remoteIpv6Temp: remoteAddr,
    seq: 0,
    state: Connected,
    createdAt: uint64(epochTime()),
    lastActivity: uint64(epochTime()),
    localConfig: config,
    remoteConfig: config
  )

  return (true, conn, answerSdp)

# SDP Offer 作成 (スタブ)
proc createSdpOffer*(localAddr: string, iceServers: seq[string]): string =
  # 実際の実装では WebRTC ライブラリの createOffer() を使用
  # ここでは最小限の SDP テンプレート
  var sdp = "v=0\r\n"
  sdp &= "o=- " & $epochTime().int64 & " 2 IN IP6 " & localAddr[1..^2] & "\r\n"
  sdp &= "s=Fodpr F2F\r\n"
  sdp &= "t=0 0\r\n"
  sdp &= "a=group:BUNDLE 0\r\n"
  sdp &= "a=msid-semantic: WMS\r\n"
  sdp &= "m=application 9 DTLS/SCTP 5000\r\n"
  sdp &= "c=IN IP6 " & localAddr[1..^2] & "\r\n"
  sdp &= "a=ice-ufrag:fodpr\r\n"
  sdp &= "a=ice-pwd:" & generateRandomInterfaceId()[0..23] & "\r\n"
  sdp &= "a=ice-options:trickle\r\n"
  sdp &= "a=fingerprint:sha-256 " & generateFingerprint() & "\r\n"
  sdp &= "a=setup:actpass\r\n"
  sdp &= "a=mid:0\r\n"
  sdp &= "a=sctp-port:5000\r\n"
  sdp &= "a=max-message-size:" & $DATA_CHANNEL_BUFFER_SIZE & "\r\n"

  for server in iceServers:
    sdp &= "a=ice-server:" & server & "\r\n"

  return sdp

# SDP Answer 作成 (スタブ)
proc createSdpAnswer*(localAddr: string, iceServers: seq[string]): string =
  var sdp = "v=0\r\n"
  sdp &= "o=- " & $epochTime().int64 & " 2 IN IP6 " & localAddr[1..^2] & "\r\n"
  sdp &= "s=Fodpr F2F\r\n"
  sdp &= "t=0 0\r\n"
  sdp &= "a=group:BUNDLE 0\r\n"
  sdp &= "m=application 9 DTLS/SCTP 5000\r\n"
  sdp &= "c=IN IP6 " & localAddr[1..^2] & "\r\n"
  sdp &= "a=ice-ufrag:fodpr\r\n"
  sdp &= "a=ice-pwd:" & generateRandomInterfaceId()[0..23] & "\r\n"
  sdp &= "a=ice-options:trickle\r\n"
  sdp &= "a=fingerprint:sha-256 " & generateFingerprint() & "\r\n"
  sdp &= "a=setup:active\r\n"
  sdp &= "a=mid:0\r\n"
  sdp &= "a=sctp-port:5000\r\n"
  sdp &= "a=max-message-size:" & $DATA_CHANNEL_BUFFER_SIZE & "\r\n"

  for server in iceServers:
    sdp &= "a=ice-server:" & server & "\r\n"

  return sdp

# SDP からアドレス抽出 (スタブ)
proc extractAddressFromSdp*(sdp: string): string =
  for line in sdp.splitLines():
    if line.startsWith("c=IN IP6 "):
      return "[" & line[9..^1] & "]"
  return ""

# DTLS フィンガープリント生成 (スタブ)
proc generateFingerprint*(): string =
  random.randomize()
  var parts = newSeq[string]()
  for i in 0..<32:
    parts.add($random.rand(255).toHex(2))
  return parts.join(":")

# ---------------------------------------------------------------------------
# F2F データ送受信
# ---------------------------------------------------------------------------

# F2F データメッセージ作成 (署名付き)
proc createF2FDataMessage*(
  localPriv: SkSecretKey,
  conn: F2FConnection,
  content: string,
  tags: seq[string] = @[]
): FodprData =
  let now = uint64(epochTime())
  var msg = FodprData(
    sender: localPriv.toPublicKey(),
    target: conn.remotePubkey,
    seq: conn.seq,
    timestamp: now,
    tags: tags,
    content: content,
    signature: emptySignature()
  )
  msg.signature = signData(localPriv, msg)
  return msg

# F2F データ送信
proc sendF2FData*(
  conn: var F2FConnection,
  localPriv: SkSecretKey,
  content: string,
  tags: seq[string] = @[]
): Future[bool] {.async.} =
  if conn.state != Connected:
    return false

  let msg = createF2FDataMessage(localPriv, conn, content, tags)
  let encoded = encodeData(msg)

  # MsgTypeData (0x06) でラップして送信
  var packet = ""
  packet.add(MsgTypeData)
  packet.add(encoded)

  let ok = await sendData(conn.dataChannel, packet)
  if ok:
    conn.seq += 1
    conn.lastActivity = uint64(epochTime())

  return ok

# F2F データ受信ハンドラ設定
proc setOnF2FDataReceived*(
  conn: var F2FConnection,
  handler: proc(msg: FodprData) {.async.}
) =
  conn.dataChannel.onMessage = proc(data: string) {.async.} =
    if data.len < 2:
      return
    if byte(data[0]) != byte(MsgTypeData):
      return

    var strm = newStringStream(data[1..^1])
    let msg = decodeData(strm)

    # 署名検証
    if not verifyData(msg):
      echo "F2F data signature verification failed"
      return

    # シーケンス番号チェック (リプレイ攻撃防止)
    if msg.seq <= conn.seq and conn.seq > 0:
      echo "Replay attack detected or out-of-order message"
      return

    conn.seq = msg.seq
    conn.lastActivity = uint64(epochTime())

    await handler(msg)

# ---------------------------------------------------------------------------
# IPv6 アドレス自動ローテーション
# ---------------------------------------------------------------------------

# アドレスローテーションタスク開始
proc startIpv6Rotation*(
  conn: var F2FConnection,
  localPriv: SkSecretKey,
  onRotate: proc(newAddr: string) {.async.} = nil
): Future[void] {.async.} =
  while conn.state == Connected:
    await sleepAsync(IPV6_ROTATION_INTERVAL_MS)

    if conn.state != Connected:
      break

    # 新しい一時アドレス生成
    let newAddr = generateIpv6TempAddress()

    # 実際の実装では:
    # 1. 新しいアドレスで ICE 再交渉
    # 2. 相手にも新しいアドレスを通知 (FodprSignal の Candidate で通知)
    # 3. 切り替え完了まで古いアドレスも維持

    conn.localIpv6Temp = newAddr.address

    if onRotate != nil:
      await onRotate(newAddr.address)

# 接続キープアライブ
proc startKeepAlive*(
  conn: var F2FConnection,
  localPriv: SkSecretKey,
  intervalMs: int = 30000
): Future[void] {.async.} =
  while conn.state == Connected:
    await sleepAsync(intervalMs)

    if conn.state != Connected:
      break

    # 空の Ping メッセージ送信
    let ok = await sendF2FData(conn, localPriv, "ping", @["type:keepalive"])
    if not ok:
      conn.state = Disconnected
      break

# ---------------------------------------------------------------------------
# 設定デフォルト
# ---------------------------------------------------------------------------

proc defaultWebRTCConfig*(): WebRTCConfig =
  WebRTCConfig(
    iceServers: @[
      "stun:stun.l.google.com:19302",
      "stun:stun1.l.google.com:19302"
    ],
    ipv6Only: true,
    tempAddressEnabled: true
  )