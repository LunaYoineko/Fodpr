## signaling.nim
## F2F: P2Pシグナリングモジュール (リレー非依存)
##
## WebRTCシグナリングを確立済みP2Pデータチャネル経由で直接行う。
## 既存の TransTypeWebRTC / MsgTypeSignal はシード/リレー用として残す。

import asyncdispatch, ws, json, strutils, streams, times
import protocol, crypto, options, transport

const
  SIGNAL_TIMEOUT_MS = 10000
  MAX_CANDIDATES = 10

type
  # WebRTC シグナリング状態
  SignalingState* = enum
    Idle,           # 未開始
    SentOffer,      # Offer 送信済み
    ReceivedOffer,  # Offer 受信済み
    SentAnswer,     # Answer 送信済み
    Completed       # 確立完了

  # ICE Candidate 情報
  IceCandidate* = object
    candidate*: string      # SDP candidate 行
    sdpMid*: string
    sdpMLineIndex*: int
    foundation*: string
    priority*: int
    address*: string           # IPアドレス (IPv6一時アドレス含む)
    port*: int
    typ*: string            # host, srflx, relay 等

  # SDP 情報
  SessionDescription* = object
    sdpType*: string           # "offer" / "answer"
    sdp*: string

  # シグナリングセッション
  SignalingSession* = object
    state*: SignalingState
    localPubkey*: SkPublicKey
    remotePubkey*: SkPublicKey
    localSdp*: Option[SessionDescription]
    remoteSdp*: Option[SessionDescription]
    localCandidates*: seq[IceCandidate]
    remoteCandidates*: seq[IceCandidate]
    dataChannel*: WebRTCDataChannel
    createdAt*: uint64
    lastActivity*: uint64

# カスタム例外
type
  SignalingError* = object of CatchableError

# ---------------------------------------------------------------------------
# 内部ヘルパー
# ---------------------------------------------------------------------------

proc iceCandidateToJson(c: IceCandidate): JsonNode =
  %*{
    "candidate": %* c.candidate,
    "sdpMid": %* c.sdpMid,
    "sdpMLineIndex": %* c.sdpMLineIndex,
    "foundation": %* c.foundation,
    "priority": %* c.priority,
    "addr": %* c.address,
    "port": %* c.port,
    "typ": %* c.typ
  }

proc jsonToIceCandidate(node: JsonNode): IceCandidate =
  IceCandidate(
    candidate: node["candidate"].getStr(),
    sdpMid: node["sdpMid"].getStr(),
    sdpMLineIndex: node["sdpMLineIndex"].getInt(),
    foundation: node["foundation"].getStr(),
    priority: node["priority"].getInt(),
    address: node["addr"].getStr(),
    port: node["port"].getInt(),
    typ: node["typ"].getStr()
  )

proc sessionDescriptionToJson(s: SessionDescription): JsonNode =
  %*{
    "type": %* s.sdpType,
    "sdp": %* s.sdp
  }

proc jsonToSessionDescription(node: JsonNode): SessionDescription =
  SessionDescription(
    sdpType: node["type"].getStr(),
    sdp: node["sdp"].getStr()
  )

# ---------------------------------------------------------------------------
# 公開 API: F2FSignal 作成・送信
# ---------------------------------------------------------------------------

# F2F Offer 作成
proc createF2FOffer*(
  priv: SkSecretKey,
  target: SkPublicKey,
  sdp: string
): F2FSignal =
  var signal = F2FSignal(
    signalType: SignalOffer,
    sender: priv.toPublicKey(),
    target: target,
    content: sdp,
    signature: emptySignature(),
    viaRelay: false
  )
  signal.signature = signF2FSignal(priv, signal)
  return signal

# F2F Answer 作成
proc createF2FAnswer*(
  priv: SkSecretKey,
  target: SkPublicKey,
  sdp: string
): F2FSignal =
  var signal = F2FSignal(
    signalType: SignalAnswer,
    sender: priv.toPublicKey(),
    target: target,
    content: sdp,
    signature: emptySignature(),
    viaRelay: false
  )
  signal.signature = signF2FSignal(priv, signal)
  return signal

# F2F ICE Candidate 作成
proc createF2FCandidate*(
  priv: SkSecretKey,
  target: SkPublicKey,
  candidate: IceCandidate
): F2FSignal =
  let content = $iceCandidateToJson(candidate)
  var signal = F2FSignal(
    signalType: SignalCandidate,
    sender: priv.toPublicKey(),
    target: target,
    content: content,
    signature: emptySignature(),
    viaRelay: false
  )
  signal.signature = signF2FSignal(priv, signal)
  return signal

# F2Fシグナリングメッセージを送信 (P2Pデータチャネル経由)
proc sendF2FSignal*(
  dataChannel: WebRTCDataChannel,
  signal: F2FSignal
): Future[bool] {.async.} =
  try:
    let encoded = encodeF2FSignal(signal)
    # F2Fデータチャネルメッセージとして送信
    # MsgTypeData (0x06) + TransTypeF2FSignal (8) でラップ
    var packet = ""
    packet.add(MsgTypeData)
    packet.add(encoded)
    discard await dataChannel.send(packet, Binary)
    return true
  except Exception as e:
    echo "Failed to send F2F signal: ", e.msg
    return false

# F2Fシグナリングメッセージを受信・検証
proc receiveF2FSignal*(
  dataChannel: WebRTCDataChannel
): Future[Option[F2FSignal]] {.async.} =
  try:
    let packet = await dataChannel.receive()
    if packet.len < 2:
      return none(F2FSignal)

    # 先頭バイトが MsgTypeData (0x06) かチェック
    if byte(packet[0]) != byte(MsgTypeData):
      return none(F2FSignal)

    # 残りを F2FSignal としてデコード
    var strm = newStringStream(packet[1..^1])
    let signal = decodeF2FSignal(strm)

    # 署名検証
    if not verifyF2FSignal(signal):
      echo "F2F signal signature verification failed"
      return none(F2FSignal)

    return some(signal)
  except Exception as e:
    echo "Failed to receive F2F signal: ", e.msg
    return none(F2FSignal)

# ---------------------------------------------------------------------------
# シグナリングセッション管理
# ---------------------------------------------------------------------------

# 新しいシグナリングセッション作成 (発信側)
proc createSignalingSession*(
  localPriv: SkSecretKey,
  remotePubkey: SkPublicKey,
  dataChannel: WebRTCDataChannel
): SignalingSession =
  result = SignalingSession(
    state: Idle,
    localPubkey: localPriv.toPublicKey(),
    remotePubkey: remotePubkey,
    localSdp: none(SessionDescription),
    remoteSdp: none(SessionDescription),
    localCandidates: @[],
    remoteCandidates: @[],
    dataChannel: dataChannel,
    createdAt: uint64(epochTime()),
    lastActivity: uint64(epochTime())
  )

# Offer 送信
proc sendOffer*(
  session: var SignalingSession,
  localPriv: SkSecretKey,
  sdp: string
): Future[bool] {.async.} =
  let offer = createF2FOffer(localPriv, session.remotePubkey, sdp)
  session.localSdp = some(SessionDescription(sdpType: "offer", sdp: sdp))
  session.state = SentOffer
  session.lastActivity = uint64(epochTime())
  return await sendF2FSignal(session.dataChannel, offer)

# Offer 受信処理
proc handleOffer*(
  session: var SignalingSession,
  signal: F2FSignal
): Option[SessionDescription] =
  if signal.signalType != SignalOffer:
    return none(SessionDescription)

  session.remoteSdp = some(jsonToSessionDescription(parseJson(signal.content)))
  session.state = ReceivedOffer
  session.lastActivity = uint64(epochTime())
  return session.remoteSdp

# Answer 送信
proc sendAnswer*(
  session: var SignalingSession,
  localPriv: SkSecretKey,
  sdp: string
): Future[bool] {.async.} =
  let answer = createF2FAnswer(localPriv, session.remotePubkey, sdp)
  session.localSdp = some(SessionDescription(sdpType: "answer", sdp: sdp))
  session.state = SentAnswer
  session.lastActivity = uint64(epochTime())
  return await sendF2FSignal(session.dataChannel, answer)

# Answer 受信処理
proc handleAnswer*(
  session: var SignalingSession,
  signal: F2FSignal
): Option[SessionDescription] =
  if signal.signalType != SignalAnswer:
    return none(SessionDescription)

  session.remoteSdp = some(jsonToSessionDescription(parseJson(signal.content)))
  session.state = Completed
  session.lastActivity = uint64(epochTime())
  return session.remoteSdp

# ICE Candidate 送信
proc sendCandidate*(
  session: var SignalingSession,
  localPriv: SkSecretKey,
  candidate: IceCandidate
): Future[bool] {.async.} =
  let signal = createF2FCandidate(localPriv, session.remotePubkey, candidate)
  session.localCandidates.add(candidate)
  session.lastActivity = uint64(epochTime())
  return await sendF2FSignal(session.dataChannel, signal)

# ICE Candidate 受信処理
proc handleCandidate*(
  session: var SignalingSession,
  signal: F2FSignal
): Option[IceCandidate] =
  if signal.signalType != SignalCandidate:
    return none(IceCandidate)

  let candidate = jsonToIceCandidate(parseJson(signal.content))
  session.remoteCandidates.add(candidate)
  session.lastActivity = uint64(epochTime())
  return some(candidate)

# シグナリングメッセージの統合ハンドラ
proc handleF2FSignal*(
  session: var SignalingSession,
  signal: F2FSignal
): tuple[handled: bool, action: string] =
  session.lastActivity = uint64(epochTime())

  case signal.signalType
  of SignalOffer:
    if session.state == Idle:
      discard handleOffer(session, signal)
      return (true, "received_offer")
  of SignalAnswer:
    if session.state == SentOffer:
      discard handleAnswer(session, signal)
      return (true, "received_answer")
  of SignalCandidate:
    discard handleCandidate(session, signal)
    return (true, "received_candidate")
  else:
    return (false, "unknown_signal_type")

# 接続確立完了チェック
proc isConnectionEstablished*(session: SignalingSession): bool =
  session.state == Completed

# セッションタイムアウトチェック
proc isSessionTimedOut*(session: SignalingSession, timeoutMs: int = SIGNAL_TIMEOUT_MS): bool =
  let now = uint64(epochTime())
  return now - session.lastActivity > timeoutMs.uint64

# ローカルSDP/リモートSDP取得
proc getLocalSdp*(session: SignalingSession): Option[SessionDescription] =
  return session.localSdp

proc getRemoteSdp*(session: SignalingSession): Option[SessionDescription] =
  return session.remoteSdp

# ICE Candidate 収集 (WebRTC 実装依存 - スタブ)
proc gatherIceCandidates*(
  session: var SignalingSession,
  localPriv: SkSecretKey,
  onCandidate: proc(candidate: IceCandidate) {.async.}
): Future[void] {.async.} =
  # 実際の実装では WebRTC ライブラリの onicecandidate コールバックで
  # 候補を取得し、sendCandidate で送信する
  # ここではスタブ
  echo "ICE candidate gathering not implemented in stub"