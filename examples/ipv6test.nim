## ipv6test.nim
## Fodpr IPv6 F2F 接続テストツール (ターミナルTUI)
## ============================================================
## 起動時に秘密鍵を作成 (永続化) し、以下の操作を行う:
##   [1] 招待コード発行      自分の公開鍵 + IPv6アドレスを署名付きでエンコード
##   [2] 招待コード入力      相手の招待コードを入力 (貼り付け可)
##   [3] IPv6接続テスト実行  招待コード内の IPv6:port へ TCP 接続
##
## 対象: Linux x86_64 / Android (Termux)
##
## ビルド: nim c -d:release examples/ipv6test.nim
## 実行:   ./examples/ipv6test
##
## 依存:  illwill (nimble install illwill)

import illwill, terminal, strutils, times, os, net, nativesockets, options, threadpool
import Fodpr

const
  APP_VERSION = "0.1.0"
  DEFAULT_PORT = 8000
  CONNECT_TIMEOUT_MS = 5000
  KEY_STORE_REL = ".fodpr/ipv6test/identity.fsec"
  MAX_LOG = 12

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

var gShared: SharedTestResult

# ---------------------------------------------------------------------------
# 鍵管理
# ---------------------------------------------------------------------------

proc keyStorePath(): string =
  getHomeDir() / KEY_STORE_REL

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

# ---------------------------------------------------------------------------
# IPv6 アドレス発見 (Linux / Android: /proc/net/if_inet6)
# ---------------------------------------------------------------------------

proc getIpv6Info(): tuple[globalAddrs, linkAddrs: seq[string]] =
  ## /proc/net/if_inet6 をパースして global / link-local アドレスを取得する。
  ## /proc/net/if_inet6 の各行は通常:
  ##   addr ifindex prefixlen scope flags ifname
  ## だが Android カーネルによって列がシフトすることがあるため、
  ## scope 候補 (f[3] と f[4]) の両方をチェックする。
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
        let ifname = f[^1]            # 最後のフィールドは必ず ifname
        let scope = f[3]              # 標準レイアウトの scope
        let flags = f[4]              # flags
        let prefixlen = f[2]
        debugLog("  addr=", addrHex, " idx=", f[1], " plen=", prefixlen,
                         " scope(f3)=", scope, " flags(f4)=", flags, " ifname=", ifname)
        if ifname == "lo":
          debugLog("  skip: lo")
          continue
        seenAny = true
        let address = formatIpv6(addrHex)
        # グローバル判定: scope が 00 または 80 (Android は 00, 一部レイアウトで flags が 80)
        # リンクローカル: 20
        if scope == "00" or scope == "80":
          debugLog("  -> GLOBAL: ", address)
          result.globalAddrs.add(address)
        elif scope == "20":
          debugLog("  -> link-local: ", address, "%", ifname)
          result.linkAddrs.add(address & "%" & ifname)
        else:
          # f[4] が global を示す列になっている可能性もチェック
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
      debugLog("/proc/net/if_inet6 読み取りエラー (Permission denied?): ", e.msg)
  else:
    debugLog("/proc/net/if_inet6 not found (IPv6 無効? / 権限?)")
  debugLog("SUMMARY global=", result.globalAddrs.len,
                 " link=", result.linkAddrs.len)

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
# TUI
# ---------------------------------------------------------------------------

type
  UiMode = enum
    modeIdle,    # 待機
    modeInput,   # 招待コード入力中
    modeTesting  # 接続テスト実行中

  QuitRequestedError = object of CatchableError

  AppState = object
    mode: UiMode
    key: FodprKeyPair
    pubkeyStr: string
    myIpv6: seq[string]        # global
    myLinkIpv6: seq[string]    # link-local
    issuedCode: string
    inputBuf: string
    resultLine: string
    resultOk: bool
    resultHas: bool
    log: seq[string]

proc newAppState(): AppState =
  result = AppState(
    mode: modeIdle,
    key: generateFodprKey(),
    pubkeyStr: "",
    myIpv6: @[],
    myLinkIpv6: @[],
    issuedCode: "",
    inputBuf: "",
    resultLine: "",
    resultOk: false,
    resultHas: false,
    log: @[])
  result.pubkeyStr = fpubEncode(result.key.publicKey)

var gApp = newAppState()
var gThread: Thread[ConnectTask]

proc addLog(msg: string) =
  let ts = now().format("HH:mm:ss")
  gApp.log.add("[" & ts & "] " & msg)
  if gApp.log.len > MAX_LOG:
    gApp.log = gApp.log[^MAX_LOG .. ^1]

proc setFailure(msg: string) =
  addLog(msg)
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
  let dec = tryDecodeInvitation(code)
  if dec.err != "":
    setFailure("招待コードのデコード失敗: " & dec.err)
    return
  let inv = dec.inv.get()

  # 検証 (署名 / 有効期限 / バージョン)
  if not verifyInvitation(inv):
    setFailure("招待コードの検証失敗 (署名不正 / 期限切れ)")
    return

  addLog("接続先: " & fpubEncode(inv.targetPeer.pubkey))
  var targets: seq[string]
  for a in inv.targetPeer.addresses:
    let ep = parseEndpoint(a)
    if ep.ok:
      targets.add(ep.host & "\x00" & $ep.port)

  if targets.len == 0:
    setFailure("招待コード内に接続可能な IPv6 アドレスがありません")
    return

  # 最初の対象へ接続 (成功するまで順次トライはしない: まず1本目)
  let sep = targets[0].find('\x00')
  let host = targets[0][0 ..< sep]
  let port = parseInt(targets[0][sep + 1 .. ^1])
  addLog("接続テスト: [" & host & "]:" & $port)

  gApp.mode = modeTesting
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
  if gApp.mode != modeTesting: return
  if gShared.busy: return
  # テスト完了
  gApp.mode = modeIdle
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
  if gThread.running():
    joinThread(gThread)

proc keyToChar(k: Key): string =
  ## 印刷可能 ASCII キーを文字に変換。それ以外は空文字。
  let v = ord(k)
  if v >= 32 and v <= 126:
    return $chr(v)
  return ""

proc wrapText(s: string, width: int): seq[string] =
  if width <= 0: return @[""]
  var line = ""
  for ch in s:
    if line.len >= width:
      result.add(line)
      line = ""
    line.add(ch)
  if line.len > 0: result.add(line)
  if result.len == 0: result.add("")

proc drawBorderLine(tb: var TerminalBuffer, y: int, w: int) =
  tb.write(0, y, repeat("─", w))

proc drawScreen(tb: var TerminalBuffer, w, h: int) =
  tb.resetAttributes()
  var y = 0

  # --- ヘッダ ---
  tb.setForegroundColor(fgCyan, bright = true)
  tb.write(0, y, "Fodpr IPv6 F2F 接続テスト  v" & APP_VERSION)
  y += 1
  tb.resetAttributes()
  drawBorderLine(tb, y, w)
  y += 1

  # --- 自分の情報 ---
  tb.setForegroundColor(fgYellow, bright = true)
  tb.write(0, y, "公開鍵: ")
  tb.setForegroundColor(fgWhite)
  let pubkeyLine = gApp.pubkeyStr
  for line in wrapText(pubkeyLine, w - 1):
    if y < h:
      tb.write(0, y, line)
      y += 1
  if y < h:
    y += 0
  tb.resetAttributes()
  tb.write(0, y, "自分のIPv6 (GLOBAL):")
  y += 1
  if gApp.myIpv6.len > 0:
    for a in gApp.myIpv6:
      if y < h:
        tb.setForegroundColor(fgGreen)
        tb.write(0, y, "  " & a)
        y += 1
  else:
    if y < h:
      tb.setForegroundColor(fgRed)
      tb.write(0, y, "  (IPv6 GLOBAL アドレスがありません)")
      y += 1
  if gApp.myLinkIpv6.len > 0:
    if y < h:
      tb.setForegroundColor(fgCyan)
      tb.write(0, y, "  リンクローカル: " & gApp.myLinkIpv6[0])
      y += 1
  tb.resetAttributes()
  if y < h:
    drawBorderLine(tb, y, w)
    y += 1

  # --- 招待コード発行 ---
  tb.setForegroundColor(fgYellow, bright = true)
  tb.write(0, y, "[1] 招待コードを発行")
  y += 1
  tb.resetAttributes()
  if gApp.issuedCode.len > 0:
    tb.setForegroundColor(fgGreen)
    tb.write(0, y, "招待コード:")
    y += 1
    for line in wrapText(gApp.issuedCode, w - 2):
      if y < h:
        tb.write(1, y, line)
        y += 1
  else:
    tb.write(0, y, "招待コード: (未発行)")
    y += 1
  tb.resetAttributes()
  if y < h:
    drawBorderLine(tb, y, w)
    y += 1

  # --- 招待コード入力 ---
  tb.setForegroundColor(fgYellow, bright = true)
  tb.write(0, y, "[2] 招待コード入力")
  y += 1
  tb.resetAttributes()
  var inputLabel = "入力: "
  var inputVal = gApp.inputBuf
  if gApp.mode == modeInput:
    inputVal &= "_"
    tb.setForegroundColor(fgCyan, bright = true)
  else:
    tb.setForegroundColor(fgWhite)
  tb.write(0, y, inputLabel & inputVal)
  y += 1
  tb.resetAttributes()
  if y < h:
    drawBorderLine(tb, y, w)
    y += 1

  # --- 接続テスト ---
  tb.setForegroundColor(fgYellow, bright = true)
  tb.write(0, y, "[3] IPv6 接続テスト実行")
  y += 1
  tb.resetAttributes()
  if gApp.mode == modeTesting:
    tb.setForegroundColor(fgCyan, bright = true)
    tb.write(0, y, "接続テスト中... (" & gShared.host & ":" & $gShared.port & ")")
  elif gApp.resultHas:
    if gApp.resultOk:
      tb.setForegroundColor(fgGreen, bright = true)
    else:
      tb.setForegroundColor(fgRed, bright = true)
    tb.write(0, y, gApp.resultLine)
  else:
    tb.write(0, y, "結果: (未実行)")
  y += 1
  tb.resetAttributes()
  if y < h:
    drawBorderLine(tb, y, w)
    y += 1

  # --- ログ ---
  tb.setForegroundColor(fgYellow, bright = true)
  tb.write(0, y, "ログ:")
  y += 1
  tb.setForegroundColor(fgWhite)
  for line in gApp.log:
    if y < h:
      tb.write(0, y, line)
      y += 1
  tb.resetAttributes()
  if y < h:
    drawBorderLine(tb, y, w)
    y += 1

  # --- フッタ ---
  tb.setForegroundColor(fgCyan)
  tb.write(0, y, " q:終了  1:発行  2:入力  3:接続  Esc:キャンセル")
  tb.resetAttributes()

proc handleKey(k: Key) =
  case gApp.mode
  of modeInput:
    if k == Key.Escape:
      gApp.mode = modeIdle
      gApp.inputBuf = ""
      addLog("入力キャンセル")
    elif k == Key.Enter:
      if gApp.inputBuf.len > 0:
        let code = gApp.inputBuf.strip()
        gApp.mode = modeIdle
        addLog("入力確定")
        startConnectTest(code)
      else:
        gApp.mode = modeIdle
        addLog("入力キャンセル (空)")
    elif k == Key.Backspace:
      if gApp.inputBuf.len > 0:
        gApp.inputBuf = gApp.inputBuf[0 .. ^2]
    else:
      let ch = keyToChar(k)
      if ch.len > 0:
        gApp.inputBuf.add(ch)
  of modeIdle:
    if k == Key.Q or k == Key.ShiftQ or k == Key.CtrlC:
      raise newException(QuitRequestedError, "quit")
    elif k == Key.One:
      gApp.issuedCode = buildInvitationCode(gApp.key, gApp.myIpv6)
      addLog("招待コードを発行しました")
    elif k == Key.Two:
      gApp.inputBuf = ""
      gApp.mode = modeInput
    elif k == Key.Three:
      if gApp.inputBuf.len > 0:
        startConnectTest(gApp.inputBuf.strip())
      else:
        addLog("招待コードが入力されていません")
  of modeTesting:
    # テスト中は操作を受け付けない
    discard

proc main() =
  # --- 起動時処理 ---
  gApp.key = loadOrCreateKey()
  gApp.pubkeyStr = fpubEncode(gApp.key.publicKey)
  let ipv6 = getIpv6Info()
  gApp.myIpv6 = ipv6.globalAddrs
  gApp.myLinkIpv6 = ipv6.linkAddrs

  illwillInit(fullScreen = false)
  hideCursor()
  try:
    # illwill は TTY 無しでも動作するが、terminalWidth/Height が 0 を返すことがある。
    # 最小1列x1行にクランプして newTerminalBuffer の RangeDefect を回避する。
    let w = max(terminalWidth(), 1)
    let h = max(terminalHeight(), 1)
    var tb = newTerminalBuffer(w, h)

    addLog("起動しました (pubkey: " & gApp.pubkeyStr[0 .. min(11, gApp.pubkeyStr.len - 1)] & "...)")
    addLog("IPv6 GLOBAL: " & (if gApp.myIpv6.len > 0: gApp.myIpv6.join(", ") else: "なし"))

    var running = true
    while running:
      tb = newTerminalBuffer(w, h)
      drawScreen(tb, w, h)
      tb.display()

      checkTestResult()

      # キーイベントを一括処理 (貼り付け対策)
      var k = getKey()
      while k != Key.None:
        try:
          handleKey(k)
        except QuitRequestedError:
          running = false
          break
        k = getKey()
      sleep(20)
  finally:
    showCursor()
    illwillDeinit()

when isMainModule:
  main()
