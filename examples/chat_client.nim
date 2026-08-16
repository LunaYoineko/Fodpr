## chat_client.nim
## Fodpr F2F チャットクライアント (Linux / Android)
## ==================================================================
## メッシュネットワーク (UDP ホールパンチ) 上で動作する本番向けチャットアプリ。
## - 複数ピア同時接続・メッセージ中継 (F2Fメッシュ)
## - 全メッセージ Fodpr 署名付き (なりすまし・改ざん防止)
## - 接続フロー: 手動で相手の [ipv6]:port を追加 / 招待コード発行・読込
##   (ハードコードされた招待コードは使わない)
## - 秘密鍵・ピア一覧・チャット履歴をローカルに永続化
## - ネイティブ解像度で描画 (Galaxy Z Fold3 等の大画面を鮮明に表示)
##
## ビルド (Linux):   nim c -d:release --threads:on examples/chat_client.nim
## 実行 (Linux):     ./chat_client [localPort]
## ビルド (Android): APP_SRC=examples/chat_client.nim bash android/build_apk.sh
## ビルド (macOS):   bash macos/build.sh
## 実行 (macOS):     ./examples/chat_client [localPort]
##
## 依存: sdl2 / fontrender (examples/ 内)

import os, strutils, times, net, options, math
when not defined(android):
  import osproc
import sdl2
import Fodpr
import fontrender
import f2f/mesh

when hostOS == "macosx":
  # ネイティブメニューバー (macos/fodpr_menu.m を clang でコンパイルしてリンク)
  proc fodprInstallMenu() {.importc: "fodpr_install_menu", cdecl.}

const
  APP_VERSION = "0.1.0"
  KEY_STORE_REL = ".fodpr/chat/identity.fsec"
  PEERS_REL = ".fodpr/chat/peers.txt"
  HISTORY_REL = ".fodpr/chat/history.log"
  MAX_HISTORY_LOAD = 300
  MAX_LOG = 4
  INVITE_EXPIRY_HOURS = 24

  FONT_ASSET = "DroidSansFallbackFull.ttf"
  LATIN_FONT_ASSET = "DejaVuSans.ttf"

# ---------------------------------------------------------------------------
# 状態
# ---------------------------------------------------------------------------

type
  ChatMsg = object
    time: string       # HH:MM:SS
    sender: string     # 表示名 (自分 / 相手の公開鍵の短縮形)
    text: string
    isMine: bool

  FocusField = enum
    focusNone, focusAddr, focusMsg

  ButtonId = enum
    btnAddPeer,     # 接続先入力からピア追加
    btnInvite,      # 招待コード発行
    btnInviteLoad,  # 招待コード読込 (接続先入力から)
    btnCopy,        # 発行済み招待コードをコピー
    btnSend,        # メッセージ送信
    btnQuit         # 終了

  UiButton = object
    id: ButtonId
    rect: Rect
    label: string
    enabled: bool

  RectI = tuple[x, y, w, h: int]

  AppState = object
    winW, winH: int
    font, fontLatin: Font
    key: FodprKeyPair
    mesh: MeshNode
    meshOk: bool
    myPort: int
    myIpv6: seq[string]
    myPubShort: string
    addrInput: string
    msgInput: string
    focus: FocusField
    issuedInvite: string
    msgScroll: int
    msgFollow: bool
    dragY: int
    dragScroll: int
    dragging: bool
    quit: bool
    log: seq[string]
    buttons: seq[UiButton]
    addrField: RectI
    msgField: RectI
    msgView: RectI
    pendingAdds: seq[string]  # CLI --add (起動時に自動接続)
    pendingSays: seq[string]  # CLI --say (起動数秒後に自動送信)

var gMessages: seq[ChatMsg]

proc newAppState(): AppState =
  let k = generateFodprKey()
  result = AppState(
    winW: 0, winH: 0,
    font: Font(), fontLatin: Font(),
    key: k,
    mesh: MeshNode(priv: k.privateKey, myPub: k.publicKey, myPort: DEFAULT_PORT,
                   msgSeq: 1, peers: @[], seen: @[], events: @[]),
    meshOk: false,
    myPort: DEFAULT_PORT,
    myIpv6: @[],
    myPubShort: "",
    addrInput: "", msgInput: "",
    focus: focusNone,
    issuedInvite: "",
    msgScroll: 0, msgFollow: true,
    dragY: 0, dragScroll: 0, dragging: false,
    quit: false,
    log: @[],
    buttons: @[],
    addrField: (x: 0, y: 0, w: 0, h: 0),
    msgField: (x: 0, y: 0, w: 0, h: 0),
    msgView: (x: 0, y: 0, w: 0, h: 0),
    pendingAdds: @[],
    pendingSays: @[]
  )

var gApp = newAppState()

# ---------------------------------------------------------------------------
# パス・永続化 (Android: 内部ストレージ / それ以外: ホーム)
# ---------------------------------------------------------------------------

when defined(android):
  proc androidInternalPath(): string =
    proc sdlAndroidInternalPath(): cstring {.importc: "SDL_AndroidGetInternalStoragePath",
                                             dynlib: "libSDL2.so".}
    result = $sdlAndroidInternalPath()

proc storePath(rel: string): string =
  when defined(android):
    let base = androidInternalPath()
    if base.len > 0:
      return base / rel
  getHomeDir() / rel

proc loadOrCreateKey(): FodprKeyPair =
  let path = storePath(KEY_STORE_REL)
  if fileExists(path):
    try:
      let priv = fsecDecode(readFile(path).strip())
      return FodprKeyPair(privateKey: priv, publicKey: priv.toPublicKey())
    except CatchableError:
      discard
  result = generateFodprKey()
  createDir(path.parentDir())
  writeFile(path, fsecEncode(result.privateKey))

proc loadPeers(): seq[string] =
  let path = storePath(PEERS_REL)
  if not fileExists(path):
    return @[]
  for line in lines(path):
    let s = line.strip()
    if s.len > 0:
      result.add(s)

proc savePeers() =
  var linesOut: seq[string]
  for p in gApp.mesh.peers:
    linesOut.add("[" & p.host & "]:" & $p.port)
  let path = storePath(PEERS_REL)
  createDir(path.parentDir())
  writeFile(path, linesOut.join("\n") & "\n")

proc loadHistory(): seq[ChatMsg] =
  let path = storePath(HISTORY_REL)
  if not fileExists(path):
    return @[]
  var lines: seq[tuple[time, sender, text: string]]
  for line in lines(path):
    let f = line.split('\t')
    if f.len >= 3:
      lines.add((time: f[0], sender: f[1], text: f[2]))
  if lines.len > MAX_HISTORY_LOAD:
    lines = lines[^MAX_HISTORY_LOAD .. ^1]
  for l in lines:
    result.add(ChatMsg(time: l.time, sender: l.sender, text: l.text,
                       isMine: l.sender == "自分"))

proc appendHistory(m: ChatMsg) =
  let path = storePath(HISTORY_REL)
  createDir(path.parentDir())
  var f: File
  if not f.open(path, fmAppend):
    return
  f.writeLine(m.time & "\t" & m.sender & "\t" & m.text)
  f.close()

# ---------------------------------------------------------------------------
# IPv6 アドレス発見 (Linux / Android)
# ---------------------------------------------------------------------------

proc formatIpv6(hexStr: string): string =
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

proc getLocalIpv6ViaUdp(): string =
  try:
    let s = newSocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    try:
      s.connect("2001:4860:4860::8888", Port(9))
      let local = s.getLocalAddr()[0]
      if local.len > 0:
        result = local
    finally:
      s.close()
  except CatchableError:
    discard

proc getGlobalIpv6(): seq[string] =
  var seen: seq[string]
  proc addAddr(a: string) =
    for s in seen:
      if s == a: return
    seen.add(a)
  if fileExists("/proc/net/if_inet6"):
    try:
      for line in lines("/proc/net/if_inet6"):
        let f = line.splitWhitespace()
        if f.len < 6: continue
        if f[3] != "00": continue      # global scope
        let s = f[0]
        if s.endsWith("fe") or s.endsWith("fd"): continue  # link-local/ULA
        addAddr(formatIpv6(s))
    except CatchableError:
      discard
  # macOS / iOS fallback: parse ifconfig for global IPv6
  when hostOS == "macosx":
    let output = execCmdEx("ifconfig -a")
    for line in output.output.splitLines():
      if "inet6" in line and "scopeid" in line:
        let f = line.splitWhitespace()
        for j in 1 ..< f.len:
          if f[j] == "inet6" and j + 1 < f.len:
            let ipAddr = f[j + 1]
            if not ipAddr.startsWith("fe80") and not ipAddr.startsWith("fd"):
              addAddr(ipAddr)
            break
  let via = getLocalIpv6ViaUdp()
  if via.len > 0:
    addAddr(via)
  result = seen

# ---------------------------------------------------------------------------
# ログ
# ---------------------------------------------------------------------------

proc addLog(msg: string) =
  let ts = now().format("HH:mm:ss")
  gApp.log.add("[" & ts & "] " & msg)
  if gApp.log.len > MAX_LOG:
    gApp.log = gApp.log[^MAX_LOG .. ^1]

proc fodprLog(msg: string) =
  when defined(android):
    const ANDROID_LOG_DEBUG = 3
    proc alogPrint(prio: cint; tag, fmt: cstring): cint {.
      importc: "__android_log_print", varargs, header: "<android/log.h>".}
    discard alogPrint(ANDROID_LOG_DEBUG, "FodprChat", "%s", msg)
  else:
    stderr.writeLine("FodprChat: ", msg)

# ---------------------------------------------------------------------------
# チャット操作
# ---------------------------------------------------------------------------

proc shortPub(pub: SkPublicKey): string =
  try:
    let s = fpubEncode(pub)
    if s.len > 12: result = s[0 ..< 12] & ".."
    else: result = s
  except CatchableError:
    result = "(?)"

proc appendChat(sender: string, text: string, isMine: bool) =
  let m = ChatMsg(time: now().format("HH:mm:ss"), sender: sender,
                  text: text, isMine: isMine)
  gMessages.add(m)
  appendHistory(m)
  gApp.msgFollow = true

proc sendChat() =
  let text = gApp.msgInput.strip()
  if text.len == 0: return
  if not gApp.meshOk:
    addLog("ネットワークが未初期化のため送信できません")
    return
  if gApp.mesh.peers.len == 0:
    addLog("接続先ピアがありません (左パネルから追加 / 招待コード読込)")
  sendBroadcast(gApp.mesh, text)
  gApp.msgInput = ""
  appendChat("自分", text, isMine = true)

proc addPeerFromInput() =
  let s = gApp.addrInput.strip()
  if s.len == 0:
    addLog("接続先を入力してください ([ipv6]:port)")
    return
  let ep = parseEndpoint(s)
  if not ep.ok:
    addLog("アドレス形式が不正: " & s)
    return
  let idx = addPeer(gApp.mesh, ep.host, ep.port)
  if idx < 0:
    addLog("ピア追加失敗 (上限到達 or 重複)")
  else:
    addLog("ピア追加: [" & ep.host & "]:" & $ep.port)
    savePeers()

proc tryDecodeInvitation(code: string): tuple[inv: Option[InvitationCode], err: string] =
  try:
    return (inv: some(decodeInvitation(code)), err: "")
  except CatchableError as e:
    return (inv: none(InvitationCode), err: e.msg)

proc loadInviteFromInput() =
  let s = gApp.addrInput.strip()
  if s.len == 0:
    addLog("招待コードを入力してください")
    return
  var code = s
  if code.startsWith("fodpr://invite/"):
    code = code[len("fodpr://invite/") .. ^1]
  let dec = tryDecodeInvitation(code)
  if dec.err != "":
    addLog("招待コードのデコード失敗: " & dec.err)
    return
  let inv = dec.inv.get()
  if not verifyInvitation(inv):
    addLog("招待コードの検証失敗 (署名不正 / 期限切れ)")
    return
  addLog("招待者: " & shortPub(inv.targetPeer.pubkey))
  var added = 0
  for a in inv.targetPeer.addresses:
    let ep = parseEndpoint(a)
    if not ep.ok: continue
    if addPeer(gApp.mesh, ep.host, ep.port) >= 0:
      inc added
      addLog("  接続先追加: [" & ep.host & "]:" & $ep.port)
  if added == 0:
    addLog("招待コード内に新規の接続可能アドレスがありません")
  savePeers()

proc issueInvite() =
  var addrs: seq[string]
  for a in gApp.myIpv6:
    addrs.add("[" & a & "]:" & $gApp.myPort)
  if addrs.len == 0:
    addrs.add("[::1]:" & $gApp.myPort)
  let peer = PeerInfo(
    pubkey: gApp.key.publicKey,
    addresses: addrs,
    lastSeen: uint64(epochTime()),
    identityTrust: 1.0,
    reliabilityScore: 1.0,
    country: ""
  )
  let inv = createInvitation(gApp.key.privateKey, peer,
                             uint64(INVITE_EXPIRY_HOURS * 3600),
                             INVITATION_SCOPE_WOT)
  gApp.issuedInvite = encodeInvitation(inv)
  addLog("招待コードを発行しました (有効 " & $INVITE_EXPIRY_HOURS & "時間)")
  if setClipboardText(cstring(gApp.issuedInvite)) == 0:
    addLog("クリップボードにコピーしました")

# ---------------------------------------------------------------------------
# フォント読み込み
# ---------------------------------------------------------------------------

proc loadAppFont(): Font =
  result = loadFontFromRw(rwFromFile(FONT_ASSET, "rb"))
  if result.loaded: return result
  result = loadFontFromRw(rwFromFile("assets/" & FONT_ASSET, "rb"))
  if result.loaded: return result
  let exeDir = getAppDir()
  result = loadFontFromFile(exeDir / FONT_ASSET)
  if result.loaded: return result
  result = loadFontFromFile(exeDir / "assets" / FONT_ASSET)
  if result.loaded: return result
  when hostOS == "macosx":
    # .app バンドル内 (FodprChat.app/Contents/Resources) のフォント
    result = loadFontFromFile(getAppDir() / ".." / "Resources" / FONT_ASSET)
    if result.loaded: return result
  result = loadFontFromFile("/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf")
  if result.loaded: return result
  result = loadFontFromFile("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc")
  if result.loaded: return result
  result = loadFontFromFile("/system/fonts/NotoSansCJK-Regular.ttc")
  if result.loaded: return result
  result = loadFontFromFile("/system/fonts/DroidSansFallback.ttf")
  when hostOS == "macosx":
    result = loadFontFromFile("/System/Library/Fonts/NotoSansCJKJP.bundle/Contents/Resources/NotoSansCJKJP.ttc")
    if result.loaded: return result
    result = loadFontFromFile("/System/Library/Fonts/NotoSansCJK.ttc")
    if result.loaded: return result
    result = loadFontFromFile("/System/Library/Fonts/AppleSDGothicNeo.ttcof")
    if result.loaded: return result
    result = loadFontFromFile("/System/Library/Fonts/STHeitiTC-Light.ttc")
    if result.loaded: return result

proc loadLatinFont(): Font =
  result = loadFontFromRw(rwFromFile(LATIN_FONT_ASSET, "rb"))
  if result.loaded: return result
  result = loadFontFromRw(rwFromFile("assets/" & LATIN_FONT_ASSET, "rb"))
  if result.loaded: return result
  let exeDir = getAppDir()
  result = loadFontFromFile(exeDir / LATIN_FONT_ASSET)
  if result.loaded: return result
  result = loadFontFromFile(exeDir / "assets" / LATIN_FONT_ASSET)
  if result.loaded: return result
  when hostOS == "macosx":
    # .app バンドル内 (FodprChat.app/Contents/Resources) のフォント
    result = loadFontFromFile(getAppDir() / ".." / "Resources" / LATIN_FONT_ASSET)
    if result.loaded: return result
  result = loadFontFromFile("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
  if result.loaded: return result
  result = loadFontFromFile("/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf")
  if result.loaded: return result
  result = loadFontFromFile("/system/fonts/Roboto-Regular.ttf")
  when hostOS == "macosx":
    result = loadFontFromFile("/System/Library/Fonts/Helvetica.ttc")
    if result.loaded: return result
    result = loadFontFromFile("/System/Library/Fonts/SFNS.ttf")
    if result.loaded: return result
    result = loadFontFromFile("/Library/Fonts/Arial.ttf")

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

proc drawRect(surf: SurfacePtr, x, y, w, h: int, color: Color) =
  if w <= 0 or h <= 0: return
  var r = rect(cint(x), cint(y), cint(w), cint(h))
  discard fillRect(surf, addr r, toU32(color))

proc drawPanel(surf: SurfacePtr, x, y, w, h: int, color: Color) =
  drawRect(surf, x, y, w, h, color)
  drawRect(surf, x, y, w, 1, colBtnLine)
  drawRect(surf, x, y + h - 1, w, 1, colBtnLine)

proc drawText(surf: SurfacePtr, size: float, color: Color, s: string, x, y: int) =
  blitText(surf, gApp.font, size, color, s, cint(x), cint(y))

proc drawWrapped(surf: SurfacePtr, size: float, color: Color, s: string,
                 x, y: int, maxW: int): int {.discardable.} =
  let wrapped = wrapTextPx(gApp.font, size, s, maxW)
  var yy = y
  for line in wrapped:
    drawText(surf, size, color, line, x, yy)
    yy += int(size + 3.0)
  result = yy - y

proc scale(v: float): int =
  ## 高さ基準のスケール。Linux(760px) で 1.0、Fold3 オープン(1768px) で約 2.3。
  let s = gApp.winH.float / 760.0
  max(1, int(round(v * s)))

proc fontBase(): float =
  let s = gApp.winH.float / 760.0
  clamp(14.0 * s, 14.0, 34.0)

proc drawButton(surf: SurfacePtr, btn: UiButton, hot: bool) =
  let color = if btn.enabled:
                (if hot: colBtnBgHot else: colBtnBg)
              else:
                colPanel
  drawPanel(surf, btn.rect.x.int, btn.rect.y.int,
            btn.rect.w.int, btn.rect.h.int, color)
  let tc = if btn.enabled: (if hot: colBtnHot else: colText) else: colDim
  let size = fontBase() * 0.8
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

proc inRectI(x, y: int, r: RectI): bool =
  x >= r.x and x <= r.x + r.w and y >= r.y and y <= r.y + r.h

# ---------------------------------------------------------------------------
# 画面描画
# ---------------------------------------------------------------------------

proc msgHeights(size: float, maxW: int): seq[int] =
  result.setLen(gMessages.len)
  for i in 0 ..< gMessages.len:
    let metaH = int(size * 0.75 + 3.0) + 2
    let bodyLines = wrapTextPx(gApp.font, size, gMessages[i].text, maxW).len
    result[i] = metaH + bodyLines * int(size + 3.0) + scale(10)

proc drawFrame(surf: SurfacePtr) =
  let W = gApp.winW
  let H = gApp.winH
  let base = fontBase()
  let pad = scale(8)
  gApp.buttons.setLen(0)

  # ---------- ヘッダ ----------
  let headerH = scale(52)
  drawRect(surf, 0, 0, W, headerH, colPanel)
  drawRect(surf, 0, headerH - 1, W, 1, colBtnLine)
  drawText(surf, base * 1.15, colCyan, "Fodpr Chat", pad, pad + 2)
  var headerY = pad + int(base * 1.15) + 4
  let st = if not gApp.meshOk: "ネットワークNG"
           else: "port=" & $gApp.myPort & " 接続=" & $gApp.mesh.peers.len &
                 " 生存=" & $countAlive(gApp.mesh)
  drawText(surf, base * 0.7, (if gApp.meshOk: colGreen else: colRed),
           st, pad, headerY)
  headerY += int(base * 0.7) + 4
  drawText(surf, base * 0.7, colDim, "ID: " & gApp.myPubShort, pad, headerY)
  drawText(surf, base * 0.7, colDim, "v" & APP_VERSION,
           W - pad * 3 - scale(80), pad + 2)

  # ---------- レイアウト領域 ----------
  let topY = headerH + scale(6)
  let leftW = clamp(int(W.float * 0.26), scale(240), scale(360))
  let rightX = leftW + scale(10)
  let rightW = W - rightX - pad
  let bottomBarH = scale(70)
  let msgViewH = H - topY - bottomBarH - scale(12)

  # ---------- 左パネル ----------
  drawPanel(surf, pad, topY, leftW - pad * 2, H - topY - pad, colPanel)
  let px = pad + scale(8)             # パネル内の左端
  let panelW = leftW - pad * 2 - scale(16)

  # ボタン行の位置 (下から順に確保)
  let btnW = (panelW - scale(8)) div 2
  let btnH = scale(44)
  let logY = H - pad - scale(4) - 2 * int(fontBase() * 0.5 + 6)
  let copyY = logY - btnH - scale(6)
  let invPanelY = copyY - scale(64) - scale(4) - int(base * 0.6) - scale(6)
  let addrInY = invPanelY - scale(38) - int(base * 0.6) - scale(10)
  let btnRow2 = addrInY - int(base * 0.6) - scale(8) - btnH
  let btnRow1 = btnRow2 - btnH - scale(8)

  # ピア一覧
  var y = topY + scale(8)
  let labelSize = base * 0.8
  drawText(surf, labelSize, colYellow, "ピア (" & $gApp.mesh.peers.len & ")",
           px, y)
  y += int(labelSize) + scale(6)
  let rowH = int(base * 0.72) + scale(6)
  for i in 0 ..< gApp.mesh.peers.len:
    if y + rowH > btnRow1 - scale(10): break
    let p = gApp.mesh.peers[i]
    let aliveNow = isPeerAlive(p)
    let mark = if aliveNow: "●" else: "○"
    let pub = (if p.pubkey.isSome: shortPub(p.pubkey.get) else: "---")
    var line = "[" & $i & "] " & mark & " " & pub
    if p.alive:
      let age = epochTime() - p.lastSeen
      line.add(" " & age.formatFloat(ffDecimal, 0) & "s")
    if p.viaAutoLearn:
      line.add(" *")
    drawText(surf, base * 0.62, (if aliveNow: colGreen else: colDim),
             line, px, y)
    y += rowH

  # ボタン (2x2)
  gApp.buttons.add(UiButton(id: btnAddPeer,
    rect: rect(cint(px), cint(btnRow1), cint(btnW), cint(btnH)),
    label: "接続先追加", enabled: true))
  gApp.buttons.add(UiButton(id: btnInvite,
    rect: rect(cint(px + btnW + scale(8)), cint(btnRow1), cint(btnW), cint(btnH)),
    label: "招待発行", enabled: true))
  gApp.buttons.add(UiButton(id: btnInviteLoad,
    rect: rect(cint(px), cint(btnRow2), cint(btnW), cint(btnH)),
    label: "招待コード読込", enabled: true))
  gApp.buttons.add(UiButton(id: btnQuit,
    rect: rect(cint(px + btnW + scale(8)), cint(btnRow2), cint(btnW), cint(btnH)),
    label: "終了", enabled: true))
  for b in gApp.buttons:
    if b.id == btnAddPeer or b.id == btnInvite or b.id == btnInviteLoad or b.id == btnQuit:
      drawButton(surf, b, hot = false)

  # 接続先入力フィールド
  let lblY = addrInY - int(base * 0.6) - scale(4)
  drawText(surf, base * 0.6, colDim, "接続先 / 招待コード:",
           px, lblY)
  drawPanel(surf, px, addrInY, panelW, scale(38),
            (if gApp.focus == focusAddr: colPanel2 else: colPanel))
  gApp.addrField = (x: px, y: addrInY, w: panelW, h: scale(38))
  var addrDisp = gApp.addrInput
  if gApp.focus == focusAddr: addrDisp.add("_")
  drawWrapped(surf, base * 0.62, (if gApp.focus == focusAddr: colCyan else: colDim),
              (if addrDisp.len > 0: addrDisp else: "(タップして入力)"),
              px + scale(8), addrInY + scale(8), panelW - scale(16))

  # 発行済み招待コード
  let invLblY = invPanelY - int(base * 0.6) - scale(4)
  drawText(surf, base * 0.6, colYellow, "発行済み招待コード:",
           px, invLblY)
  drawPanel(surf, px, invPanelY, panelW, scale(64), colPanel2)
  if gApp.issuedInvite.len > 0:
    drawWrapped(surf, base * 0.5, colGreen, gApp.issuedInvite,
                px + scale(6), invPanelY + scale(6), panelW - scale(12))
  else:
    drawText(surf, base * 0.55, colDim, "(未発行)", px + scale(6), invPanelY + scale(12))
  let copyBtn = UiButton(id: btnCopy,
    rect: rect(cint(px), cint(copyY), cint(panelW), cint(btnH)),
    label: "招待コードをコピー", enabled: gApp.issuedInvite.len > 0)
  gApp.buttons.add(copyBtn)
  drawButton(surf, copyBtn, hot = false)

  # ログ
  for i, l in gApp.log:
    drawWrapped(surf, base * 0.5, colDim, l, px, logY + i * int(base * 0.5 + 6),
                panelW)

  # ---------- 右側: チャット履歴 ----------
  let msgX = rightX
  drawPanel(surf, msgX, topY, rightW, msgViewH, colPanel)
  gApp.msgView = (x: msgX, y: topY, w: rightW, h: msgViewH)
  let innerX = msgX + scale(10)
  let innerW = rightW - scale(20)

  let heights = msgHeights(base, innerW - scale(8))
  var totalH = 0
  for h in heights: totalH += h

  let maxScroll = max(0, totalH - msgViewH + scale(10))
  if gApp.msgFollow: gApp.msgScroll = maxScroll
  if gApp.msgScroll > maxScroll: gApp.msgScroll = maxScroll
  if gApp.msgScroll < 0: gApp.msgScroll = 0

  var drawY = 0
  for i in 0 ..< gMessages.len:
    let msgTop = drawY
    let msgBot = msgTop + heights[i]
    if msgBot > gApp.msgScroll and msgTop < gApp.msgScroll + msgViewH:
      let m = gMessages[i]
      let metaSize = base * 0.6
      let metaCol = if m.isMine: colGreen else: colCyan
      drawText(surf, metaSize, metaCol, m.time & " " & m.sender,
               innerX, topY + scale(6) + msgTop - gApp.msgScroll)
      let bodyY = topY + scale(6) + msgTop - gApp.msgScroll + int(metaSize + 3.0) + 2
      if m.isMine:
        drawRect(surf, innerX - scale(4), bodyY - scale(2),
                 innerW + scale(8), heights[i] - int(metaSize + 3.0), colPanel2)
      drawWrapped(surf, base, colText, m.text, innerX, bodyY, innerW - scale(8))
    drawY = msgBot
    if drawY > gApp.msgScroll + msgViewH: break

  # ---------- 下部: メッセージ入力 ----------
  let barY = H - bottomBarH - scale(6)
  let sendW = scale(140)
  let inputW = rightW - sendW - scale(10)
  drawPanel(surf, msgX, barY, rightW, bottomBarH, colPanel)
  let msgInY = barY + scale(14)
  drawPanel(surf, innerX, msgInY, inputW, scale(42),
            (if gApp.focus == focusMsg: colPanel2 else: colPanel))
  gApp.msgField = (x: innerX, y: msgInY, w: inputW, h: scale(42))
  var msgDisp = gApp.msgInput
  if gApp.focus == focusMsg: msgDisp.add("_")
  drawWrapped(surf, base * 0.72, (if gApp.focus == focusMsg: colCyan else: colDim),
              (if msgDisp.len > 0: msgDisp else: "(メッセージを入力)"),
              innerX + scale(8), msgInY + scale(10), inputW - scale(16))

  let sendBtn = UiButton(id: btnSend,
    rect: rect(cint(msgX + rightW - sendW), cint(barY + scale(14)),
               cint(sendW), cint(scale(42))),
    label: "送信", enabled: true)
  gApp.buttons.add(sendBtn)
  drawButton(surf, sendBtn, hot = false)

# ---------------------------------------------------------------------------
# イベント処理
# ---------------------------------------------------------------------------

proc handleClick(x, y: int) =
  # ボタン
  for b in gApp.buttons:
    if x >= b.rect.x and x <= b.rect.x + b.rect.w and
       y >= b.rect.y and y <= b.rect.y + b.rect.h:
      if not b.enabled: return
      case b.id
      of btnAddPeer: addPeerFromInput()
      of btnInvite: issueInvite()
      of btnInviteLoad: loadInviteFromInput()
      of btnCopy:
        if setClipboardText(cstring(gApp.issuedInvite)) == 0:
          addLog("招待コードをクリップボードにコピーしました")
      of btnSend: sendChat()
      of btnQuit: gApp.quit = true
      return
  # 入力フィールド
  if inRectI(x, y, gApp.msgField):
    if gApp.focus != focusMsg:
      gApp.focus = focusMsg
      startTextInput()
    return
  if inRectI(x, y, gApp.addrField):
    if gApp.focus != focusAddr:
      gApp.focus = focusAddr
      startTextInput()
    return
  # メッセージ領域 → スクロール用ドラッグ開始
  if inRectI(x, y, gApp.msgView):
    gApp.dragging = true
    gApp.dragY = y
    gApp.dragScroll = gApp.msgScroll

proc handleKey(sym: cint) =
  case sym
  of K_ESCAPE:
    if gApp.focus != focusNone:
      stopTextInput()
      gApp.focus = focusNone
    else:
      gApp.quit = true
  of K_RETURN, K_KP_ENTER:
    case gApp.focus
    of focusMsg: sendChat()
    of focusAddr: addPeerFromInput()
    of focusNone: discard
  of K_BACKSPACE:
    if gApp.focus == focusMsg and gApp.msgInput.len > 0:
      gApp.msgInput = gApp.msgInput[0 .. ^2]
    elif gApp.focus == focusAddr and gApp.addrInput.len > 0:
      gApp.addrInput = gApp.addrInput[0 .. ^2]
  else:
    discard

proc handleWheel(x, y: int) =
  if y == 0: return
  gApp.msgScroll -= y * scale(40)
  if y > 0:
    gApp.msgFollow = false

proc handleMotion(x, y: int, state: uint32) =
  if gApp.dragging:
    if (state and uint32(BUTTON_LMASK)) != 0:
      gApp.msgScroll = gApp.dragScroll + (gApp.dragY - y)
      if gApp.msgScroll < gApp.dragScroll:
        gApp.msgFollow = false
    else:
      gApp.dragging = false

# ---------------------------------------------------------------------------
# メイン
# ---------------------------------------------------------------------------

proc runApp() =
  gApp.focus = focusNone
  gApp.msgFollow = true

  # --- 鍵 ---
  gApp.key = loadOrCreateKey()
  gApp.myPubShort = shortPub(gApp.key.publicKey)

  # --- ポート (Linux: 第1引数で変更可 / Android/iOS: 既定) ---
  gApp.myPort = DEFAULT_PORT
  when not defined(android) and not defined(ios):
    var i = 1
    if paramCount() >= 1:
      try:
        gApp.myPort = parseInt(paramStr(1))
        i = 2
      except CatchableError:
        discard
    # 追加オプション: --add <[ipv6]:port> / --say <text>
    while i <= paramCount():
      let a = paramStr(i)
      if a == "--add" and i < paramCount():
        gApp.pendingAdds.add(paramStr(i + 1))
        inc i, 2
      elif a == "--say" and i < paramCount():
        gApp.pendingSays.add(paramStr(i + 1))
        inc i, 2
      else:
        inc i

  # --- ネットワーク初期化 ---
  try:
    gApp.mesh = newMeshNode(gApp.key.privateKey, gApp.key.publicKey, gApp.myPort)
    gApp.meshOk = true
  except CatchableError as e:
    gApp.meshOk = false
    addLog("ネットワーク初期化失敗: " & e.msg)
    fodprLog("BIND FAIL: " & e.msg)

  # --- 永続化データの読み込み ---
  gMessages = loadHistory()
  if gApp.meshOk:
    for entry in loadPeers():
      let ep = parseEndpoint(entry)
      if ep.ok:
        discard addPeer(gApp.mesh, ep.host, ep.port)
    for entry in gApp.pendingAdds:
      let ep = parseEndpoint(entry)
      if ep.ok:
        discard addPeer(gApp.mesh, ep.host, ep.port)

  gApp.myIpv6 = getGlobalIpv6()

  # --- SDL 初期化 ---
  if sdl2.init(INIT_VIDEO) != SdlSuccess:
    quit(1)

  when defined(ios):
    # iOS: fullscreen window fills the screen regardless of size passed
    let win = createWindow("Fodpr Chat",
                           SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                           1280, 760,
                           SDL_WINDOW_FULLSCREEN)
  else:
    # macOS / Linux: windowed mode at a sensible default size
    let win = createWindow("Fodpr Chat",
                           SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                           1280, 760, 0)
  if win == nil:
    quit(1)
  when hostOS == "macosx":
    # SDL の NSApplication 初期化後にネイティブメニューバーを設定
    fodprInstallMenu()
  let ren = createRenderer(win, -1, 0)
  if ren == nil:
    quit(1)

  # On HiDPI displays (iOS Retina, Mac Retina), the backing store is at
  # pixel resolution, not point resolution. SDL_GL_GetDrawableSize returns
  # the real pixel dimensions of the window's backing store.
  var w: cint
  var h: cint
  glGetDrawableSize(win, w, h)
  if w <= 0 or h <= 0:
    discard getRendererOutputSize(ren, addr w, addr h)
  if w <= 0 or h <= 0:
    getSize(win, w, h)
  if w <= 0 or h <= 0:
    w = 1280
    h = 760
  gApp.winW = int(w)
  gApp.winH = int(h)

  # フォント
  gApp.font = loadAppFont()
  gApp.fontLatin = loadLatinFont()
  gApp.font.setFallback(addr gApp.fontLatin)
  let fontStatus = "フォント: CJK=" & (if gApp.font.loaded: "OK" else: "FAIL") &
                   " Latin=" & (if gApp.fontLatin.loaded: "OK" else: "FAIL")
  addLog(fontStatus)
  fodprLog("RES " & $gApp.winW & "x" & $gApp.winH)
  fodprLog(fontStatus)

  let frame = createRGBSurfaceWithFormat(0, cint(w), cint(h), 32,
                                         SDL_PIXELFORMAT_ARGB8888)
  if frame == nil:
    quit(1)
  let tex = createTexture(ren, SDL_PIXELFORMAT_ARGB8888,
                          SDL_TEXTUREACCESS_STREAMING, cint(w), cint(h))

  addLog("起動しました (ID: " & gApp.myPubShort & ")")
  addLog("port=" & $gApp.myPort & "  IPv6=" &
         (if gApp.myIpv6.len > 0: gApp.myIpv6.join(", ") else: "なし"))
  fodprLog("IPV6 " & gApp.myIpv6.join(","))
  fodprLog("START ok=" & $gApp.meshOk & " peers=" & $gApp.mesh.peers.len)

  # --- メインループ ---
  var e: Event
  var dumpPath = getEnv("CHAT_DUMP_FRAME", "")
  var frameDumped = false
  let t0 = epochTime()
  while not gApp.quit:
    # イベント処理
    while toBool(pollEvent(e)):
      case e.kind
      of QuitEvent:
        gApp.quit = true
      of MouseButtonDown:
        handleClick(int(e.button.x), int(e.button.y))
      of MouseButtonUp:
        gApp.dragging = false
      of MouseMotion:
        handleMotion(int(e.motion.x), int(e.motion.y), e.motion.state)
      of MouseWheel:
        handleWheel(int(e.wheel.x), int(e.wheel.y))
      of KeyDown:
        handleKey(e.key.keysym.sym)
      of TextInput:
        if gApp.focus == focusMsg:
          gApp.msgInput.add($cast[cstring](addr e.text.text[0]))
        elif gApp.focus == focusAddr:
          gApp.addrInput.add($cast[cstring](addr e.text.text[0]))
      else:
        discard

    # ネットワーク処理
    if gApp.meshOk:
      for ev in stepMesh(gApp.mesh, 50):
        case ev.kind
        of meMsg:
          if ev.sender.isSome and
             ev.sender.get.toRawCompressed() == gApp.mesh.myPub.toRawCompressed():
             continue
          let sender = (if ev.sender.isSome: shortPub(ev.sender.get) else: "(不明)")
          appendChat(sender, ev.payload, isMine = false)
        of meMsgSelf:
          discard  # 送信時に表示済み
        of mePeerAdded:
          if ev.autoLearned:
            addLog("自動学習: ピア [" & ev.srcHost & "]:" & $ev.srcPort)
            savePeers()
        of mePeerLost:
          addLog("ピア不達: [" & ev.srcHost & "]:" & $ev.srcPort)

    # CLI --say の自動送信 (3秒後)
    if gApp.pendingSays.len > 0 and epochTime() - t0 > 3.0:
      for s in gApp.pendingSays:
        gApp.msgInput = s
        sendChat()
      gApp.pendingSays = @[]

    # 描画
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
  stopTextInput()
  if gApp.meshOk:
    closeMesh(gApp.mesh)
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
      discard alog(ANDROID_LOG_ERROR, "FodprChat", "runApp returned normally (unexpected)")
    except CatchableError as e:
      discard alog(ANDROID_LOG_ERROR, "FodprChat", "runApp exception: %s", e.msg)
    except Defect as e:
      discard alog(ANDROID_LOG_ERROR, "FodprChat", "runApp defect: %s", e.msg)
    result = 0

# iOS: SDL の SDL_uikit_main が SDL_main を呼ぶ (静的リンクのため dynlib 不要)
when defined(ios):
  proc nimMain() {.importc: "NimMain".}
  proc sdlMain(argc: cint, argv: ptr cstring): cint {.exportc: "SDL_main".} =
    nimMain()
    try:
      runApp()
      stderr.writeLine("FodprChat: runApp returned normally (unexpected)")
    except CatchableError as e:
      stderr.writeLine("FodprChat exception: ", e.msg)
    except Defect as e:
      stderr.writeLine("FodprChat defect: ", e.msg)
    result = 0

when isMainModule and not defined(android) and not defined(ios):
  runApp()
