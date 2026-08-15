## ipv6test.nim
## Fodpr IPv6 F2F 接続テストツール (SDL2 GUI)
## ============================================================
## 起動時に秘密鍵を作成 (永続化) し、以下の操作を行う:
##   [1] 招待コード発行      自分の公開鍵 + IPv6アドレスを署名付きでエンコード
##   [2] 招待コード入力      相手の招待コードを入力 (テキスト入力 / クリップボード)
##   [3] IPv6接続テスト実行  招待コード内の IPv6:port へ TCP 接続
##
## 対象: Linux x86_64 / Android (APK)
##
## ビルド (Linux):   nim c -d:release examples/ipv6test.nim
## 実行 (Linux):     ./examples/ipv6test
## ビルド (Android): android/build_apk.sh を参照
##
## 依存: sdl2 (nimble install sdl2) / stb_truetype (同梱)

import os, strutils, times, net, nativesockets, options, threadpool, math
import sdl2
import Fodpr
import fontrender

const
  APP_VERSION = "0.2.0"
  DEFAULT_PORT = 8000
  CONNECT_TIMEOUT_MS = 5000
  KEY_STORE_REL = ".fodpr/ipv6test/identity.fsec"
  MAX_LOG = 12
  LOGICAL_W = 460
  LOGICAL_H = 960
  PAD = 8

  FONT_ASSET = "DroidSansFallbackFull.ttf"
  LATIN_FONT_ASSET = "DejaVuSans.ttf"

# ---------------------------------------------------------------------------
# 共有状態 (接続テスト結果はスレッドから書き込まれる)
# ---------------------------------------------------------------------------

type
  SharedTestResult = object
    done: bool
    busy: bool
    ok: bool
    rttMs: float
    err: string
    host: string
    port: int

  ConnectTask = object
    host: string
    port: int
    timeoutMs: int
    res: ptr SharedTestResult

  SharedUdpResult = object
    done: bool
    busy: bool
    ok: bool
    roundTrips: int
    punchesSent: int
    punchesRecv: int
    rttMs: float
    replyMsg: string
    err: string
    host: string
    port: int

  UdpTask = object
    host: string
    port: int
    priv: SkSecretKey
    res: ptr SharedUdpResult

var gShared: SharedTestResult
var gUdpShared: SharedUdpResult
var gUdpThread: Thread[UdpTask]

# ---------------------------------------------------------------------------
# 鍵管理
# ---------------------------------------------------------------------------

when defined(android):
  proc androidInternalPath(): string =
    proc sdlAndroidInternalPath(): cstring {.importc: "SDL_AndroidGetInternalStoragePath",
                                             dynlib: "libSDL2.so".}
    result = $sdlAndroidInternalPath()

proc keyStorePath(): string =
  when defined(android):
    let base = androidInternalPath()
    if base.len > 0:
      return base / KEY_STORE_REL
  getHomeDir() / KEY_STORE_REL

proc loadDebugInvite(): string =
  ## デバッグ用: <internal>/invite.txt があれば招待コードを読み込む
  when defined(android):
    let base = androidInternalPath()
    if base.len > 0:
      let p = base / "invite.txt"
      if fileExists(p):
        return readFile(p).strip()
  else:
    let p = getHomeDir() / "invite.txt"
    if fileExists(p):
      return readFile(p).strip()
  ""

proc loadOrCreateKey(): FodprKeyPair =
  let path = keyStorePath()
  if fileExists(path):
    try:
      let priv = fsecDecode(readFile(path).strip())
      return FodprKeyPair(privateKey: priv, publicKey: priv.toPublicKey())
    except CatchableError:
      discard
  result = generateFodprKey()
  createDir(path.parentDir())
  writeFile(path, fsecEncode(result.privateKey))

# ---------------------------------------------------------------------------
# IPv6 アドレス発見 (Linux / Android: /proc/net/if_inet6)
# ---------------------------------------------------------------------------

proc formatIpv6(hexStr: string): string =
  ## 32 hex chars を RFC 5952 形式 (ゼロ圧縮) に整形する。
  var groups = newSeq[string](8)
  for i in 0..7:
    groups[i] = hexStr[i * 4 ..< i * 4 + 4].strip(chars = {'0'}, leading = true, trailing = false)
    if groups[i].len == 0: groups[i] = "0"
  var bestStart = -1
  var bestLen = 0
  var curStart = -1
  var curLen = 0
  for i in 0..7:
    if groups[i] == "0":
      if curStart < 0: curStart = i
      inc curLen
      if curLen > bestLen:
        bestLen = curLen
        bestStart = curStart
    else:
      curStart = -1
      curLen = 0
  if bestLen < 2: bestStart = -1
  result = ""
  var i = 0
  while i < 8:
    if i == bestStart:
      result.add("::")
      i += bestLen
    else:
      if result.len > 0 and not result.endsWith("::"):
        result.add(":")
      result.add(groups[i])
      inc i
  if result.len == 0: result = "::"

# ---------------------------------------------------------------------------
# デバッグログ (リリース版は -d:ipv6Debug を指定しない限り出力されない)
# ---------------------------------------------------------------------------
proc debugLog(args: varargs[string, `$`]) =
  when defined(ipv6Debug):
    stderr.writeLine("[DEBUG] ", args.join(" "))

when defined(android):
  const ANDROID_LOG_DEBUG = 3
  proc fodprLog(msg: string) =
    proc alogPrint(prio: cint; tag, fmt: cstring): cint {.
      importc: "__android_log_print", varargs, header: "<android/log.h>".}
    discard alogPrint(ANDROID_LOG_DEBUG, "Fodpr", "%s", msg)
else:
  proc fodprLog(msg: string) =
    stderr.writeLine("Fodpr: ", msg)

proc getLocalIpv6ViaUdp(): string =
  ## UDP connect テクニックでローカル IPv6 を取得する。
  ## Android は /proc/net/if_inet6 が SELinux で読めないため、その代替。
  ## UDP connect はパケットを送らずルーティングテーブルの参照のみ行う。
  try:
    let s = newSocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    try:
      s.connect("2001:4860:4860::8888", Port(9))
      let local = s.getLocalAddr()[0]
      if local.len > 0:
        result = local
    finally:
      s.close()
  except OSError:
    debugLog("getLocalIpv6ViaUdp: OSError (IPv6 ルートなし?)")

proc getIpv6Info(): tuple[globalAddrs, linkAddrs: seq[string]] =
  ## /proc/net/if_inet6 をパースして global / link-local アドレスを取得する。
  var seenAny = false
  if fileExists("/proc/net/if_inet6"):
    var lineCount = 0
    try:
      for line in lines("/proc/net/if_inet6"):
        inc lineCount
        let raw = line.strip()
        let f = raw.splitWhitespace()
        debugLog("raw(", f.len, "): ", raw)
        if f.len < 6:
          debugLog("  skip: too few fields (", f.len, ")")
          continue
        let addrHex = f[0]
        let ifname = f[^1]
        let scope = f[3]
        let flags = f[4]
        let prefixlen = f[2]
        debugLog("  addr=", addrHex, " idx=", f[1], " plen=", prefixlen,
                 " scope(f3)=", scope, " flags(f4)=", flags, " ifname=", ifname)
        if ifname == "lo":
          debugLog("  skip: lo")
          continue
        seenAny = true
        let address = formatIpv6(addrHex)
        if scope == "00" or scope == "80":
          debugLog("  -> GLOBAL: ", address)
          result.globalAddrs.add(address)
        elif scope == "20":
          debugLog("  -> link-local: ", address, "%", ifname)
          result.linkAddrs.add(address & "%" & ifname)
        else:
          if flags == "00" or flags == "80":
            debugLog("  -> GLOBAL(via f4): ", address, "  (scope f3=", scope, " が未知値)")
            result.globalAddrs.add(address)
          else:
            debugLog("  -> ignored (scope=", scope, " flags=", flags, ")")
      if lineCount == 0:
        debugLog("/proc/net/if_inet6 は空ファイル (IPv6 無効?)")
      if not seenAny:
        debugLog("ファイルは存在するが lo 以外のアドレスがない")
    except OSError as e:
      debugLog("/proc/net/if_inet6 読み取りエラー: ", e.msg)
  else:
    debugLog("/proc/net/if_inet6 not found (IPv6 無効? / 権限?)")
  if result.globalAddrs.len == 0:
    let via = getLocalIpv6ViaUdp()
    if via.len > 0:
      debugLog("UDP fallback で取得: ", via)
      result.globalAddrs.add(via)
    else:
      debugLog("UDP fallback も失敗")
  debugLog("SUMMARY global=", result.globalAddrs.len, " link=", result.linkAddrs.len)

# ---------------------------------------------------------------------------
# エンドポイント解析
# ---------------------------------------------------------------------------

proc parseEndpoint(s: string): tuple[host: string, port: int, ok: bool] =
  ## "[ipv6]:port" / "[ipv6]" / "ipv6" 形式をパースする。
  var str = s.strip()
  if str.len == 0 or str.contains("://"):
    return ("", 0, false)
  if str.startsWith("["):
    let close = str.find(']')
    if close < 0: return ("", 0, false)
    let host = str[1 ..< close]
    if close + 1 < str.len:
      if str[close + 1] != ':': return ("", 0, false)
      let portStr = str[close + 2 .. ^1]
      let port = parseInt(portStr)
      return (host, port, true)
    return (host, DEFAULT_PORT, true)
  if str.count(':') >= 2:
    return (str, DEFAULT_PORT, true)
  return ("", 0, false)

# ---------------------------------------------------------------------------
# 招待コード発行
# ---------------------------------------------------------------------------

proc buildInvitationCode(key: FodprKeyPair, ipv6Global: seq[string]): string =
  var addrs: seq[string]
  for a in ipv6Global:
    addrs.add("[" & a & "]:" & $DEFAULT_PORT)
  if addrs.len == 0:
    addrs.add("[::1]:" & $DEFAULT_PORT)
  let peer = PeerInfo(
    pubkey: key.publicKey,
    addresses: addrs,
    lastSeen: uint64(epochTime()),
    identityTrust: 1.0,
    reliabilityScore: 1.0,
    country: ""
  )
  let inv = createInvitation(key.privateKey, peer, 3600, INVITATION_SCOPE_WOT)
  result = encodeInvitation(inv)

# ---------------------------------------------------------------------------
# IPv6 TCP 接続テスト (別スレッドで実行)
# ---------------------------------------------------------------------------

proc worker(task: ConnectTask) {.thread.} =
  var sock = newSocket(domain = AF_INET6, sockType = SOCK_STREAM, protocol = IPPROTO_TCP)
  var ok = false
  var err = ""
  let startTime = epochTime()
  try:
    sock.connect(task.host, Port(task.port), task.timeoutMs)
    ok = true
  except CatchableError as e:
    err = e.msg
  finally:
    try:
      sock.close()
    except:
      discard
  let rttMs = (epochTime() - startTime) * 1000.0
  task.res.done = true
  task.res.ok = ok
  task.res.err = err
  task.res.rttMs = rttMs
  task.res.host = task.host
  task.res.port = task.port
  task.res.busy = false

# ---------------------------------------------------------------------------
# UDP ホールパンチテスト (別スレッドで実行)
# ---------------------------------------------------------------------------

proc udpWorker(task: UdpTask) {.thread.} =
  ## UDP パンチを送り続け、相手からの応答 (seq 一致) で往復成功とする。
  ## その後メッセージを送信し、相手の応答メッセージを待つ。
  let myMsg = "Android->Host: Hello from Fodpr! こんにちは。メッセージ交換テストです。"
  let res = runHolePunch(task.port, task.host, task.port, task.priv,
                         maxRounds = 25, intervalMs = 150, recvTimeoutMs = 500,
                         sendMsg = myMsg)
  task.res.done = true
  task.res.ok = res.ok
  task.res.roundTrips = res.roundTrips
  task.res.punchesSent = res.punchesSent
  task.res.punchesRecv = res.punchesRecv
  task.res.rttMs = res.rttMs
  task.res.replyMsg = res.replyMsg
  task.res.err = res.err
  task.res.busy = false

# ---------------------------------------------------------------------------
# アプリ状態
# ---------------------------------------------------------------------------

type
  ButtonId = enum
    btnIssue,       # 招待コード発行
    btnInputToggle, # 入力モード切替
    btnTest,        # 接続テスト実行
    btnUdp,         # UDPパンチテスト
    btnPaste,       # クリップボード貼り付け
    btnClearInput,  # 入力クリア
    btnQuit         # 終了

  UiButton = object
    id: ButtonId
    rect: Rect
    label: string
    enabled: bool

  AppState = object
    key: FodprKeyPair
    pubkeyStr: string
    myIpv6: seq[string]
    myLinkIpv6: seq[string]
    issuedCode: string
    inputBuf: string
    inputMode: bool
    resultLine: string
    resultOk: bool
    resultHas: bool
    log: seq[string]
    font: Font
    fontLatin: Font
    testing: bool
    udpBusy: bool
    quit: bool
    buttons: seq[UiButton]
    redraw: bool

var gThread: Thread[ConnectTask]

proc newAppState(): AppState =
  result = AppState(
    key: generateFodprKey(),
    pubkeyStr: "",
    myIpv6: @[],
    myLinkIpv6: @[],
    issuedCode: "",
    inputBuf: "",
    inputMode: false,
    resultLine: "",
    resultOk: false,
    resultHas: false,
    log: @[],
    testing: false,
    udpBusy: false,
    quit: false,
    buttons: @[],
    redraw: true
  )
  result.pubkeyStr = fpubEncode(result.key.publicKey)

var gApp = newAppState()

proc addLog(msg: string) =
  let ts = now().format("HH:mm:ss")
  gApp.log.add("[" & ts & "] " & msg)
  if gApp.log.len > MAX_LOG:
    gApp.log = gApp.log[^MAX_LOG .. ^1]

proc setFailure(msg: string) =
  addLog(msg)
  fodprLog("SETFAIL: " & msg)
  gApp.resultHas = true
  gApp.resultOk = false
  gApp.resultLine = msg

# 招待コードのデコードを安全に行う (requireInit な InvitationCode は Option でラップ)
proc tryDecodeInvitation(code: string): tuple[inv: Option[InvitationCode], err: string] =
  try:
    return (inv: some(decodeInvitation(code)), err: "")
  except CatchableError as e:
    return (inv: none(InvitationCode), err: e.msg)

proc startConnectTest(code: string) =
  if gApp.testing: return
  let dec = tryDecodeInvitation(code)
  if dec.err != "":
    setFailure("招待コードのデコード失敗: " & dec.err)
    return
  let inv = dec.inv.get()

  if not verifyInvitation(inv):
    setFailure("招待コードの検証失敗 (署名不正 / 期限切れ)")
    return

  addLog("接続先: " & fpubEncode(inv.targetPeer.pubkey)[0 ..< 16] & "...")
  fodprLog("DECODE OK, addrs=" & inv.targetPeer.addresses.join(","))
  var targets: seq[string]
  for a in inv.targetPeer.addresses:
    let ep = parseEndpoint(a)
    if ep.ok:
      targets.add(ep.host & "\x00" & $ep.port)

  if targets.len == 0:
    setFailure("招待コード内に接続可能な IPv6 アドレスがありません")
    return

  let sep = targets[0].find('\x00')
  let host = targets[0][0 ..< sep]
  let port = parseInt(targets[0][sep + 1 .. ^1])
  addLog("接続テスト: [" & host & "]:" & $port)
  fodprLog("CONNECTING to " & host & ":" & $port)

  gApp.testing = true
  gApp.resultHas = false
  gShared.done = false
  gShared.busy = true
  gShared.ok = false
  gShared.err = ""
  gShared.host = host
  gShared.port = port
  gShared.rttMs = 0.0

  var task = ConnectTask(
    host: host,
    port: port,
    timeoutMs: CONNECT_TIMEOUT_MS,
    res: addr gShared
  )
  createThread(gThread, worker, task)

proc checkTestResult() =
  if not gApp.testing: return
  if gShared.busy: return
  # テスト完了
  gApp.testing = false
  gApp.resultHas = true
  if gShared.ok:
    gApp.resultOk = true
    gApp.resultLine = "接続成功 [" & gShared.host & "]:" & $gShared.port &
                      " (" & gShared.rttMs.formatFloat(ffDecimal, 1) & " ms)"
    addLog("接続成功 [" & gShared.host & "]:" & $gShared.port &
           " (" & gShared.rttMs.formatFloat(ffDecimal, 1) & " ms)")
  else:
    gApp.resultOk = false
    gApp.resultLine = "接続失敗 [" & gShared.host & "]:" & $gShared.port &
                      " - " & gShared.err
    addLog("接続失敗 [" & gShared.host & "]:" & $gShared.port & " - " & gShared.err)
    fodprLog("CONNECT FAIL: " & gShared.err & " host=" & gShared.host & " port=" & $gShared.port)
  if gThread.running():
    joinThread(gThread)

proc startUdpPunch(code: string) =
  if gApp.testing or gApp.udpBusy: return
  let dec = tryDecodeInvitation(code)
  if dec.err != "":
    setFailure("招待コードのデコード失敗: " & dec.err)
    return
  let inv = dec.inv.get()
  if not verifyInvitation(inv):
    setFailure("招待コードの検証失敗 (署名不正 / 期限切れ)")
    return
  var host = ""
  var port = DEFAULT_PORT
  for a in inv.targetPeer.addresses:
    let ep = parseEndpoint(a)
    if ep.ok:
      host = ep.host
      port = ep.port
      break
  if host.len == 0:
    setFailure("招待コード内に接続可能な IPv6 アドレスがありません")
    return

  addLog("UDPパンチ: [" & host & "]:" & $port & " (ポート開放不要)")
  fodprLog("UDPPUNCH to " & host & ":" & $port)

  gApp.udpBusy = true
  gUdpShared.done = false
  gUdpShared.busy = true
  gUdpShared.ok = false
  gUdpShared.err = ""
  gUdpShared.host = host
  gUdpShared.port = port
  gUdpShared.roundTrips = 0
  gUdpShared.punchesSent = 0
  gUdpShared.punchesRecv = 0
  gUdpShared.rttMs = 0.0
  gUdpShared.replyMsg = ""

  var task = UdpTask(host: host, port: port, priv: gApp.key.privateKey,
                     res: addr gUdpShared)
  createThread(gUdpThread, udpWorker, task)

proc checkUdpResult() =
  if not gApp.udpBusy: return
  if gUdpShared.busy: return
  gApp.udpBusy = false
  gApp.resultHas = true
  if gUdpShared.ok:
    gApp.resultOk = true
    if gUdpShared.replyMsg.len > 0:
      gApp.resultLine = "受信: " & gUdpShared.replyMsg &
                        "  (RTT " & gUdpShared.rttMs.formatFloat(ffDecimal, 1) & " ms)"
      addLog(gApp.resultLine)
      addLog("UDPホールパンチ成功: 往復 " & $gUdpShared.roundTrips & "回")
      fodprLog("MSGREPLY: " & gUdpShared.replyMsg)
    else:
      gApp.resultLine = "UDPパンチ成功 [" & gUdpShared.host & "]:" & $gUdpShared.port &
                        " (RTT " & gUdpShared.rttMs.formatFloat(ffDecimal, 1) & " ms)"
      addLog(gApp.resultLine)
    fodprLog("UDPPUNCH OK rtt=" & gUdpShared.rttMs.formatFloat(ffDecimal, 1) &
             "ms rt=" & $gUdpShared.roundTrips & " sent=" & $gUdpShared.punchesSent &
             " recv=" & $gUdpShared.punchesRecv)
  else:
    gApp.resultOk = false
    gApp.resultLine = "UDPパンチ失敗 [" & gUdpShared.host & "]:" & $gUdpShared.port &
                      " - " & gUdpShared.err
    addLog(gApp.resultLine)
    fodprLog("UDPPUNCH FAIL: " & gUdpShared.err &
             " host=" & gUdpShared.host & " port=" & $gUdpShared.port)
  if gUdpThread.running():
    joinThread(gUdpThread)

# ---------------------------------------------------------------------------
# フォント読み込み
# ---------------------------------------------------------------------------

proc loadAppFont(): Font =
  # Android: APK assets / Linux: 実行ディレクトリ
  result = loadFontFromRw(rwFromFile(FONT_ASSET, "rb"))
  if result.loaded: return result
  result = loadFontFromRw(rwFromFile("assets/" & FONT_ASSET, "rb"))
  if result.loaded: return result
  let exeDir = getAppDir()
  result = loadFontFromFile(exeDir / FONT_ASSET)
  if result.loaded: return result
  result = loadFontFromFile(exeDir / "assets" / FONT_ASSET)
  if result.loaded: return result
  # システムフォント (フォールバック)
  result = loadFontFromFile("/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf")
  if result.loaded: return result
  result = loadFontFromFile("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc")
  if result.loaded: return result
  result = loadFontFromFile("/system/fonts/NotoSansCJK-Regular.ttc")
  if result.loaded: return result
  result = loadFontFromFile("/system/fonts/DroidSansFallback.ttf")

proc loadLatinFont(): Font =
  ## 英語 (ASCII/ラテン文字) 用フォールバックフォント。
  ## DroidSansFallbackFull にはラテン文字が無いため、別途読み込む。
  result = loadFontFromRw(rwFromFile(LATIN_FONT_ASSET, "rb"))
  if result.loaded: return result
  result = loadFontFromRw(rwFromFile("assets/" & LATIN_FONT_ASSET, "rb"))
  if result.loaded: return result
  let exeDir = getAppDir()
  result = loadFontFromFile(exeDir / LATIN_FONT_ASSET)
  if result.loaded: return result
  result = loadFontFromFile(exeDir / "assets" / LATIN_FONT_ASSET)
  if result.loaded: return result
  result = loadFontFromFile("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
  if result.loaded: return result
  result = loadFontFromFile("/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf")
  if result.loaded: return result
  result = loadFontFromFile("/system/fonts/Roboto-Regular.ttf")
  if result.loaded: return result
  result = loadFontFromFile("/system/fonts/RobotoCondensed-Regular.ttf")
  if result.loaded: return result
  result = loadFontFromFile("/system/fonts/Roboto-Light.ttf")

# ---------------------------------------------------------------------------
# 描画ヘルパ
# ---------------------------------------------------------------------------

const
  colBg: Color       = (r: 22'u8,  g: 24'u8,  b: 40'u8,   a: 255'u8)
  colPanel: Color    = (r: 34'u8,  g: 38'u8,  b: 60'u8,   a: 255'u8)
  colPanel2: Color   = (r: 42'u8,  g: 46'u8,  b: 72'u8,   a: 255'u8)
  colText: Color     = (r: 232'u8, g: 232'u8, b: 255'u8,  a: 255'u8)
  colDim: Color      = (r: 150'u8, g: 154'u8, b: 180'u8,  a: 255'u8)
  colCyan: Color     = (r: 92'u8,  g: 214'u8, b: 255'u8,  a: 255'u8)
  colGreen: Color    = (r: 92'u8,  g: 230'u8, b: 160'u8,  a: 255'u8)
  colRed: Color      = (r: 255'u8, g: 107'u8, b: 107'u8,  a: 255'u8)
  colYellow: Color   = (r: 255'u8, g: 209'u8, b: 102'u8,  a: 255'u8)
  colBtnBg: Color    = (r: 47'u8,  g: 59'u8,  b: 102'u8,  a: 255'u8)
  colBtnBgHot: Color = (r: 66'u8,  g: 82'u8,  b: 140'u8,  a: 255'u8)
  colBtnLine: Color  = (r: 92'u8,  g: 107'u8, b: 176'u8,  a: 255'u8)
  colBtnHot: Color   = (r: 150'u8, g: 180'u8, b: 255'u8,  a: 255'u8)

proc toU32(c: Color): uint32 =
  (uint32(c.a) shl 24) or (uint32(c.r) shl 16) or (uint32(c.g) shl 8) or uint32(c.b)

proc drawText(surf: SurfacePtr, size: float, color: Color, s: string, x, y: int) =
  blitText(surf, gApp.font, size, color, s, cint(x), cint(y))

proc drawRect(surf: SurfacePtr, x, y, w, h: int, color: Color) =
  var r = rect(cint(x), cint(y), cint(w), cint(h))
  discard fillRect(surf, addr r, toU32(color))

proc drawLine(surf: SurfacePtr, y: int, color: Color) =
  drawRect(surf, PAD, y, LOGICAL_W - PAD * 2, 1, color)

proc drawPanel(surf: SurfacePtr, x, y, w, h: int, color: Color) =
  drawRect(surf, x, y, w, h, color)
  drawRect(surf, x, y, w, 1, colBtnLine)
  drawRect(surf, x, y + h - 1, w, 1, colBtnLine)

proc wrapLines(text: string, maxW: int, size: float): seq[string] =
  wrapTextPx(gApp.font, size, text, maxW)

proc drawWrapped(surf: SurfacePtr, size: float, color: Color, s: string,
                 x, y: int, maxW: int, maxLines: int): tuple[lines, height: int] =
  ## テキストを折り返して描画。maxLines を超えた分は切り捨て。
  let wrapped = wrapLines(s, maxW, size)
  let shown = min(wrapped.len, maxLines)
  var yy = y
  for i in 0 ..< shown:
    drawText(surf, size, color, wrapped[i], x, yy)
    yy += int(size + 3.0)
  result.lines = shown
  result.height = shown * int(size + 3.0)

proc drawButton(surf: SurfacePtr, btn: UiButton, hot: bool) =
  let color = if btn.enabled:
                (if hot: colBtnBgHot else: colBtnBg)
              else:
                colPanel
  drawPanel(surf, int(btn.rect.x), int(btn.rect.y),
            int(btn.rect.w), int(btn.rect.h), color)
  let tc = if btn.enabled: (if hot: colBtnHot else: colText) else: colDim
  var size = 14.0
  let labelW = measureText(gApp.font, size, btn.label).w
  var fs = size
  if labelW > btn.rect.w - 12:
    fs = size * (btn.rect.w - 12).float / labelW.float
    if fs < 10.0: fs = 10.0
  let tw = measureText(gApp.font, fs, btn.label).w
  let th = measureText(gApp.font, fs, btn.label).h
  let cx = btn.rect.x + (btn.rect.w - cint(tw)) div 2
  let cy = btn.rect.y + (btn.rect.h - cint(th)) div 2
  drawText(surf, fs, tc, btn.label, int(cx), int(cy))

# ---------------------------------------------------------------------------
# 画面描画
# ---------------------------------------------------------------------------

proc drawFrame(surf: SurfacePtr) =
  let font = gApp.font
  gApp.buttons.setLen(0)

  var y = PAD + 2

  # --- タイトル ---
  drawText(surf, 22, colCyan, "Fodpr IPv6 F2F 接続テスト", PAD, y)
  y += 30
  drawText(surf, 11, colDim, "v" & APP_VERSION & "   " &
    (if font.loaded: "" else: "[フォント未ロード: 表示が乱れる可能性]"), PAD, y)
  y += 18
  drawLine(surf, y, colBtnLine)
  y += 10

  # --- 公開鍵 ---
  drawText(surf, 14, colYellow, "公開鍵:", PAD, y)
  y += 22
  let pkRes = drawWrapped(surf, 12, colText, gApp.pubkeyStr, PAD + 4, y,
                          LOGICAL_W - PAD * 2 - 8, 4)
  y += cint(pkRes.height) + 8

  # --- 自分の IPv6 ---
  drawText(surf, 14, colYellow, "自分のIPv6 (GLOBAL):", PAD, y)
  y += 22
  if gApp.myIpv6.len > 0:
    for a in gApp.myIpv6:
      let r = drawWrapped(surf, 12, colGreen, a, PAD + 4, y,
                          LOGICAL_W - PAD * 2 - 8, 2)
      y += cint(r.height)
  else:
    drawText(surf, 12, colRed, "(IPv6 GLOBAL アドレスがありません)", PAD + 4, y)
    y += 17
  if gApp.myLinkIpv6.len > 0:
    let r = drawWrapped(surf, 12, colCyan,
                        "リンクローカル: " & gApp.myLinkIpv6[0], PAD + 4, y,
                        LOGICAL_W - PAD * 2 - 8, 1)
    y += cint(r.height)
  y += 6
  drawLine(surf, y, colBtnLine)
  y += 10

  # --- ボタン (2x3) ---
  let btnW = (LOGICAL_W - PAD * 2 - 10) div 2
  let btnH = 46
  let row1 = y
  gApp.buttons.add(UiButton(id: btnIssue,
    rect: rect(cint(PAD), cint(row1), cint(btnW), cint(btnH)),
    label: "招待コード発行", enabled: not gApp.testing and not gApp.udpBusy))
  gApp.buttons.add(UiButton(id: btnInputToggle,
    rect: rect(cint(PAD + btnW + 10), cint(row1), cint(btnW), cint(btnH)),
    label: (if gApp.inputMode: "入力終了" else: "入力モード"),
    enabled: not gApp.testing and not gApp.udpBusy))
  let row2 = row1 + btnH + 10
  gApp.buttons.add(UiButton(id: btnTest,
    rect: rect(cint(PAD), cint(row2), cint(btnW), cint(btnH)),
    label: (if gApp.testing: "接続テスト中..." else: "接続テスト実行"),
    enabled: not gApp.testing and not gApp.udpBusy and gApp.inputBuf.strip().len > 0))
  gApp.buttons.add(UiButton(id: btnUdp,
    rect: rect(cint(PAD + btnW + 10), cint(row2), cint(btnW), cint(btnH)),
    label: (if gApp.udpBusy: "UDPパンチ中..." else: "UDPパンチテスト"),
    enabled: not gApp.testing and not gApp.udpBusy and gApp.inputBuf.strip().len > 0))
  let row3 = row2 + btnH + 10
  gApp.buttons.add(UiButton(id: btnQuit,
    rect: rect(cint(PAD), cint(row3), cint(btnW), cint(btnH)),
    label: "終了", enabled: true))

  # ボタン描画
  for b in gApp.buttons:
    drawButton(surf, b, hot = false)
  y = row3 + btnH + 12

  # --- 招待コード (発行済み) ---
  drawText(surf, 14, colYellow, "招待コード:", PAD, y)
  y += 22
  if gApp.issuedCode.len > 0:
    drawPanel(surf, PAD, y, LOGICAL_W - PAD * 2, 66, colPanel)
    let r = drawWrapped(surf, 11, colGreen, gApp.issuedCode, PAD + 6, y + 6,
                        LOGICAL_W - PAD * 2 - 12, 4)
    y += cint(r.height) + 14
  else:
    drawPanel(surf, PAD, y, LOGICAL_W - PAD * 2, 30, colPanel)
    drawText(surf, 12, colDim, "(未発行)", PAD + 8, y + 8)
    y += 34
  y += 8

  # --- 入力 ---
  drawText(surf, 14, colYellow, "入力コード:", PAD, y)
  y += 22
  # 入力フィールド
  let inputW = LOGICAL_W - PAD * 2
  drawPanel(surf, PAD, y, inputW, 36,
            (if gApp.inputMode: colPanel2 else: colPanel))
  var display = gApp.inputBuf
  if gApp.inputMode:
    display.add("_")
  let disp = drawWrapped(surf, 13, (if gApp.inputMode: colCyan else: colDim),
                         (if display.len > 0: display else: "(タップして入力)"),
                         PAD + 8, y + 9, inputW - 16, 1)
  y += cint(disp.height) + 10
  # 入力モード中の補助ボタン
  if gApp.inputMode:
    let pasteW = 92
    let clearW = 92
    let pasteBtn = UiButton(id: btnPaste,
      rect: rect(cint(PAD), cint(y), cint(pasteW), 38), label: "ペースト", enabled: true)
    let clearBtn = UiButton(id: btnClearInput,
      rect: rect(cint(PAD + pasteW + 8), cint(y), cint(clearW), 38),
      label: "クリア", enabled: true)
    gApp.buttons.add(pasteBtn)
    gApp.buttons.add(clearBtn)
    drawButton(surf, pasteBtn, hot = false)
    drawButton(surf, clearBtn, hot = false)
    drawText(surf, 11, colDim, "Enterでテスト / キーボード入力", PAD + pasteW + clearW + 24, y + 12)
    y += 38 + 8
  else:
    drawText(surf, 11, colDim, "招待コードを入力して 接続テスト実行 を押す", PAD, y + 2)
    y += 18
  y += 6

  # --- 結果 ---
  drawText(surf, 14, colYellow, "結果:", PAD, y)
  y += 22
  if gApp.testing:
    drawText(surf, 13, colCyan, "接続テスト中... (" & gShared.host & ":" & $gShared.port & ")",
             PAD + 4, y)
    y += 18
  elif gApp.udpBusy:
    drawText(surf, 13, colCyan, "UDPパンチ中... (" & gUdpShared.host & ":" &
             $gUdpShared.port & ") 相手の起動を確認", PAD + 4, y)
    y += 18
  elif gApp.resultHas:
    let r = drawWrapped(surf, 13,
      (if gApp.resultOk: colGreen else: colRed),
      gApp.resultLine, PAD + 4, y, LOGICAL_W - PAD * 2 - 8, 2)
    y += cint(r.height)
  else:
    drawText(surf, 13, colDim, "(未実行)", PAD + 4, y)
    y += 18
  y += 6
  drawLine(surf, y, colBtnLine)
  y += 8

  # --- ログ ---
  drawText(surf, 14, colYellow, "ログ:", PAD, y)
  y += 22
  let maxLogLines = max(1, (LOGICAL_H - y - PAD - 8) div 16)
  let logShown = min(gApp.log.len, maxLogLines)
  for i in (gApp.log.len - logShown) ..< gApp.log.len:
    let r = drawWrapped(surf, 11, colText, gApp.log[i], PAD + 4, y,
                        LOGICAL_W - PAD * 2 - 8, 1)
    y += cint(r.height)
    if y >= LOGICAL_H - PAD: break

# ---------------------------------------------------------------------------
# イベント処理
# ---------------------------------------------------------------------------

proc buttonById(id: ButtonId): ptr UiButton =
  for b in gApp.buttons.mitems:
    if b.id == id:
      return addr b
  nil

proc handleClick(x, y: cint) =
  for b in gApp.buttons:
    if x >= b.rect.x and x <= b.rect.x + b.rect.w and
       y >= b.rect.y and y <= b.rect.y + b.rect.h:
      if not b.enabled: return
      case b.id
      of btnIssue:
        if not gApp.testing:
          gApp.issuedCode = buildInvitationCode(gApp.key, gApp.myIpv6)
          addLog("招待コードを発行しました")
      of btnInputToggle:
        gApp.inputMode = not gApp.inputMode
        if gApp.inputMode:
          startTextInput()
        else:
          stopTextInput()
        addLog(if gApp.inputMode: "入力モード開始" else: "入力モード終了")
      of btnTest:
        if not gApp.testing and not gApp.udpBusy and gApp.inputBuf.strip().len > 0:
          startConnectTest(gApp.inputBuf.strip())
      of btnUdp:
        if not gApp.testing and not gApp.udpBusy and gApp.inputBuf.strip().len > 0:
          startUdpPunch(gApp.inputBuf.strip())
      of btnPaste:
        if toBool(hasClipboardText()):
          let s = $getClipboardText()
          if s.len > 0:
            gApp.inputBuf.add(s)
            addLog("クリップボードから貼り付け (" & $s.len & " 文字)")
        else:
          addLog("クリップボードが空です")
      of btnClearInput:
        gApp.inputBuf = ""
        addLog("入力をクリアしました")
      of btnQuit:
        gApp.quit = true
      return

proc handleKey(sym: cint) =
  if gApp.inputMode:
    case sym
    of K_ESCAPE:
      gApp.inputMode = false
      stopTextInput()
      gApp.inputBuf = ""
      addLog("入力キャンセル")
    of K_RETURN, K_KP_ENTER:
      if gApp.inputBuf.strip().len > 0:
        gApp.inputMode = false
        stopTextInput()
        addLog("入力確定")
        startConnectTest(gApp.inputBuf.strip())
      else:
        gApp.inputMode = false
        stopTextInput()
        addLog("入力キャンセル (空)")
    of K_BACKSPACE:
      if gApp.inputBuf.len > 0:
        gApp.inputBuf = gApp.inputBuf[0 .. ^2]
    else:
      discard
    return
  # 非入力モード
  case sym
  of K_ESCAPE, K_Q:
    gApp.quit = true
  of K_1:
    handleClick(0, 0) # placeholder
    # 発行
    gApp.issuedCode = buildInvitationCode(gApp.key, gApp.myIpv6)
    addLog("招待コードを発行しました")
  of K_2:
    if not gApp.testing and not gApp.udpBusy:
      gApp.inputMode = true
      startTextInput()
      addLog("入力モード開始")
  of K_3:
    if not gApp.testing and not gApp.udpBusy and gApp.inputBuf.strip().len > 0:
      startConnectTest(gApp.inputBuf.strip())
  of K_5:
    if not gApp.testing and not gApp.udpBusy and gApp.inputBuf.strip().len > 0:
      startUdpPunch(gApp.inputBuf.strip())
  of K_4:
    gApp.quit = true
  else:
    discard

# ---------------------------------------------------------------------------
# メイン
# ---------------------------------------------------------------------------

proc runApp() =
  gApp = newAppState()
  gApp.key = loadOrCreateKey()
  gApp.pubkeyStr = fpubEncode(gApp.key.publicKey)
  let ipv6 = getIpv6Info()
  gApp.myIpv6 = ipv6.globalAddrs
  gApp.myLinkIpv6 = ipv6.linkAddrs

  if sdl2.init(INIT_VIDEO) != SdlSuccess:
    quit(1)

  let win = createWindow("Fodpr IPv6 F2F 接続テスト",
                         SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                         LOGICAL_W, LOGICAL_H, 0)
  if win == nil:
    quit(1)
  let ren = createRenderer(win, -1, 0)
  if ren == nil:
    quit(1)
  discard setLogicalSize(ren, LOGICAL_W, LOGICAL_H)

  gApp.font = loadAppFont()
  gApp.fontLatin = loadLatinFont()
  gApp.font.setFallback(addr gApp.fontLatin)
  let fontStatus = "フォント: CJK=" & (if gApp.font.loaded: "OK" else: "FAIL") &
                   " Latin=" & (if gApp.fontLatin.loaded: "OK" else: "FAIL")
  addLog(fontStatus)
  fodprLog(fontStatus)

  let frame = createRGBSurfaceWithFormat(0, LOGICAL_W, LOGICAL_H, 32,
                                         SDL_PIXELFORMAT_ARGB8888)
  if frame == nil:
    quit(1)
  let tex = createTexture(ren, SDL_PIXELFORMAT_ARGB8888,
                          SDL_TEXTUREACCESS_STREAMING, LOGICAL_W, LOGICAL_H)

  addLog("起動しました (pubkey: " & gApp.pubkeyStr[0 ..< 12] & "...)")
  addLog("IPv6 GLOBAL: " & (if gApp.myIpv6.len > 0: gApp.myIpv6.join(", ") else: "なし"))

  let dbgInvite = loadDebugInvite()
  if dbgInvite.len > 0:
    gApp.inputBuf = dbgInvite
    addLog("invite.txt を読み込み (" & $dbgInvite.len & " 文字)")
    startConnectTest(dbgInvite)
    addLog("接続テストを自動開始")

  var e: Event
  var dumpPath = getEnv("IPV6TEST_DUMP_FRAME", "")
  var frameDumped = false
  while not gApp.quit:
    # --- イベント処理 ---
    while toBool(pollEvent(e)):
      case e.kind
      of QuitEvent:
        gApp.quit = true
      of MouseButtonDown:
        handleClick(e.button.x, e.button.y)
      of KeyDown:
        handleKey(e.key.keysym.sym)
      of TextInput:
        if gApp.inputMode:
          gApp.inputBuf.add($cast[cstring](addr e.text.text[0]))
      else:
        discard

    # --- 接続テスト結果チェック ---
    checkTestResult()
    checkUdpResult()

    # --- 描画 ---
    discard fillRect(frame, nil, toU32(colBg))
    drawFrame(frame)
    if dumpPath.len > 0 and not frameDumped:
      discard saveBMP(frame, dumpPath)
      frameDumped = true
      dumpPath = ""
    discard updateTexture(tex, nil, frame.pixels, frame.pitch)
    discard copy(ren, tex, nil, nil)
    present(ren)

    sleep(16)

  # --- 終了処理 ---
  if gApp.testing or gApp.udpBusy:
    sleep(50)
  stopTextInput()
  destroyTexture(tex)
  freeSurface(frame)
  destroyRenderer(ren)
  destroyWindow(win)
  sdl2.quit()

# Android: SDL が SDL_main を探す
when defined(android):
  const ANDROID_LOG_ERROR = 6
  proc alog(prio: cint; tag, fmt: cstring): cint {.
    importc: "__android_log_print", varargs, header: "<android/log.h>".}
  proc nimMain() {.importc: "NimMain".}
  proc sdlMain(argc: cint, argv: ptr cstring): cint {.exportc: "SDL_main", dynlib.} =
    nimMain()
    try:
      runApp()
      discard alog(ANDROID_LOG_ERROR, "Fodpr", "runApp returned normally (unexpected)")
    except CatchableError as e:
      discard alog(ANDROID_LOG_ERROR, "Fodpr", "runApp exception: %s", e.msg)
    except Defect as e:
      discard alog(ANDROID_LOG_ERROR, "Fodpr", "runApp defect: %s", e.msg)
    result = 0

when isMainModule and not defined(android):
  runApp()
