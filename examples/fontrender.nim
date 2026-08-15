## fontrender.nim
## stb_truetype ベースのテキスト描画 (SDL2 ソフトウェアレンダリング)
## Linux / Android 双方で動作する。フォントは APK assets または
## システムフォントから読み込む。

import os, strutils, math
import sdl2

const stbIncludeDir = currentSourcePath().parentDir().quoteShell

{.passC: "-I" & stbIncludeDir.}
{.compile: "stb_truetype.c".}

# ---------------------------------------------------------------------------
# stb_truetype C binding
# ---------------------------------------------------------------------------

type
  stbtt_fontinfo {.importc: "stbtt_fontinfo", header: "stb_truetype.h",
                   incompleteStruct.} = object

const STBTT_FONTINFO_BUF = 512

proc stbtt_GetFontOffsetForIndex(data: ptr byte; index: cint): cint {.
  importc: "stbtt_GetFontOffsetForIndex", header: "stb_truetype.h", cdecl.}
proc stbtt_GetNumberOfFonts(data: ptr byte): cint {.
  importc: "stbtt_GetNumberOfFonts", header: "stb_truetype.h", cdecl.}
proc stbtt_FindGlyphIndex(info: ptr stbtt_fontinfo; codepoint: cint): cint {.
  importc: "stbtt_FindGlyphIndex", header: "stb_truetype.h", cdecl.}
proc stbtt_InitFont(info: ptr stbtt_fontinfo; data: ptr byte; fontstart: cint): cint {.
  importc: "stbtt_InitFont", header: "stb_truetype.h", cdecl.}
proc stbtt_ScaleForPixelHeight(info: ptr stbtt_fontinfo; pixels: float32): float32 {.
  importc: "stbtt_ScaleForPixelHeight", header: "stb_truetype.h", cdecl.}
proc stbtt_GetFontVMetrics(info: ptr stbtt_fontinfo; ascent, descent, lineGap: ptr cint) {.
  importc: "stbtt_GetFontVMetrics", header: "stb_truetype.h", cdecl.}
proc stbtt_GetCodepointHMetrics(info: ptr stbtt_fontinfo; codepoint: cint;
                                advanceWidth, leftSideBearing: ptr cint) {.
  importc: "stbtt_GetCodepointHMetrics", header: "stb_truetype.h", cdecl.}
proc stbtt_GetCodepointKernAdvance(info: ptr stbtt_fontinfo; ch1, ch2: cint): cint {.
  importc: "stbtt_GetCodepointKernAdvance", header: "stb_truetype.h", cdecl.}
proc stbtt_GetCodepointBitmap(info: ptr stbtt_fontinfo; scaleX, scaleY: float32;
                              codepoint: cint; width, height, xoff, yoff: ptr cint): ptr byte {.
  importc: "stbtt_GetCodepointBitmap", header: "stb_truetype.h", cdecl.}
proc stbtt_FreeBitmap(bitmap: ptr byte; userdata: pointer) {.
  importc: "stbtt_FreeBitmap", header: "stb_truetype.h", cdecl.}

# ---------------------------------------------------------------------------
# Font
# ---------------------------------------------------------------------------

type
  Font* = object
    data: seq[byte]
    info: ptr stbtt_fontinfo
    ascent, descent, lineGap: cint
    loaded: bool
    fallback: ptr Font   # ラテン文字等のフォールバック (主フォントに無いグリフ用)

proc setFallback*(font: var Font, fallback: ptr Font) =
  ## フォールバックフォント (例: ASCII/ラテン文字) を設定する。
  ## 主フォント (CJK) にグリフが無い文字はこちらで描画される。
  font.fallback = fallback

proc initFont*(data: seq[byte], ttcIndex: int = 0): Font =
  ## フォントデータ (TTF/TTC) から Font を初期化する。
  if data.len == 0:
    return result
  result.data = data
  result.info = cast[ptr stbtt_fontinfo](alloc0(STBTT_FONTINFO_BUF))
  let offset = stbtt_GetFontOffsetForIndex(addr result.data[0], cint(ttcIndex))
  if stbtt_InitFont(result.info, addr result.data[0], offset) == 0:
    dealloc(result.info)
    result.info = nil
    return result
  stbtt_GetFontVMetrics(result.info, addr result.ascent, addr result.descent,
                        addr result.lineGap)
  result.loaded = true

proc deinitFont*(font: var Font) =
  if font.info != nil:
    dealloc(font.info)
    font.info = nil
  font.data = @[]
  font.loaded = false

proc loaded*(font: Font): bool = font.loaded

proc hasGlyph*(font: Font, ch: int): bool =
  ## 指定コードポイントのグリフが存在するか。
  if not font.loaded:
    return false
  return stbtt_FindGlyphIndex(font.info, cint(ch)) != 0

proc fontForCp*(font: Font, cp: int): Font =
  ## コードポイントを描画するのに適切なフォントを返す。
  ## 主フォントにグリフが無くフォールバックが持っている場合はフォールバックを使う。
  if hasGlyph(font, cp):
    return font
  if font.fallback != nil and hasGlyph(font.fallback[], cp):
    return font.fallback[]
  return font

proc loadFontBest*(data: seq[byte], testChar: int = 0x63a5): Font =
  ## TTC の場合、テスト文字 (既定 '接' U+63A5) を持つフォントインデックスを探す。
  if data.len == 0:
    return result
  let count = stbtt_GetNumberOfFonts(addr data[0])
  let n = max(count, 1)
  for i in 0 ..< n:
    result = initFont(data, i)
    if result.loaded and hasGlyph(result, testChar):
      return result

proc loadFontFromRw*(rw: ptr RWops): Font =
  ## SDL RWops (assets/ファイル) からフォントを読み込む。失敗時は loaded=false。
  if rw == nil:
    return result
  let total = size(rw)
  if total <= 0:
    discard close(rw)
    return result
  var data = newSeq[byte](int(total))
  let n = read(rw, addr data[0], 1, csize_t(total))
  discard close(rw)
  if n != csize_t(total):
    return result
  result = loadFontBest(data)

proc loadFontFromFile*(path: string): Font =
  ## 通常ファイルから読み込む。失敗時は loaded=false。
  if not fileExists(path):
    return result
  try:
    result = loadFontBest(cast[seq[byte]](readFile(path)))
  except CatchableError:
    result = Font()

# ---------------------------------------------------------------------------
# UTF-8 decode
# ---------------------------------------------------------------------------

proc utf8Decode(s: string, i: var int): int =
  ## s[i] の UTF-8 コードポイントをデコードし、i を進める。
  if i >= s.len:
    return -1
  let b0 = ord(s[i])
  if b0 < 0x80:
    inc i
    return b0
  elif (b0 and 0xE0) == 0xC0:
    if i + 1 < s.len:
      let c = ((b0 and 0x1F) shl 6) or (ord(s[i + 1]) and 0x3F)
      i += 2
      return c
  elif (b0 and 0xF0) == 0xE0:
    if i + 2 < s.len:
      let c = ((b0 and 0x0F) shl 12) or ((ord(s[i + 1]) and 0x3F) shl 6) or
              (ord(s[i + 2]) and 0x3F)
      i += 3
      return c
  elif (b0 and 0xF8) == 0xF0:
    if i + 3 < s.len:
      let c = ((b0 and 0x07) shl 18) or ((ord(s[i + 1]) and 0x3F) shl 12) or
              ((ord(s[i + 2]) and 0x3F) shl 6) or (ord(s[i + 3]) and 0x3F)
      i += 4
      return c
  inc i
  return 0xFFFD

# ---------------------------------------------------------------------------
# テキスト計測・描画
# ---------------------------------------------------------------------------

proc scaleForHeight(font: Font, size: float): float32 =
  stbtt_ScaleForPixelHeight(font.info, float32(size))

proc measureText*(font: Font, size: float, text: string): tuple[w, h: int] =
  ## テキストのピクセル寸法を返す。フォールバックフォントも考慮する。
  if not font.loaded:
    return (0, 0)
  var penX = 0.0
  var i = 0
  var prevCp = -1
  while i < text.len:
    let cp = utf8Decode(text, i)
    let cur = fontForCp(font, cp)
    let scale = scaleForHeight(cur, size)
    var adv, lsb: cint
    stbtt_GetCodepointHMetrics(cur.info, cint(cp), addr adv, addr lsb)
    var kern = 0
    if prevCp >= 0:
      kern = stbtt_GetCodepointKernAdvance(cur.info, cint(prevCp), cint(cp))
    penX += (adv.float + kern.float) * scale
    prevCp = cp
  result.w = max(int(ceil(penX)), 1)
  result.h = max(int(ceil((font.ascent - font.descent).float *
                scaleForHeight(font, size))), 1)

proc createRGBSurfaceWithFormat*(flags: cint; width, height, depth: cint;
                                 format: uint32): SurfacePtr {.
  importc: "SDL_CreateRGBSurfaceWithFormat", dynlib: LibName.}

proc renderLine*(font: Font, size: float, color: Color, text: string): SurfacePtr =
  ## 1行のテキストを ARGB8888 サーフェスに描画する。呼び出し側で freeSurface すること。
  ## 主フォントに無いグリフはフォールバックフォントで描画する。
  if not font.loaded:
    return nil
  let dims = measureText(font, size, text)
  let w = max(dims.w, 1)
  let h = max(dims.h, 1)
  result = createRGBSurfaceWithFormat(0, cint(w), cint(h), 32,
                                      SDL_PIXELFORMAT_ARGB8888)
  if result == nil:
    return nil
  var clearRect = rect(0, 0, cint(w), cint(h))
  discard fillRect(result, addr clearRect, 0x00000000)
  let scale = scaleForHeight(font, size)
  let baseline = font.ascent.float * scale
  let argb = (uint32(color.a) shl 24) or (uint32(color.r) shl 16) or
             (uint32(color.g) shl 8) or uint32(color.b)
  if lockSurface(result) != 0:
    return result
  var penX = 0.0
  var i = 0
  var prevCp = -1
  let pixels = cast[ptr UncheckedArray[uint32]](result.pixels)
  let pitch = int(result.pitch) div 4
  while i < text.len:
    let cp = utf8Decode(text, i)
    let cur = fontForCp(font, cp)
    let curScale = scaleForHeight(cur, size)
    var adv, lsb: cint
    stbtt_GetCodepointHMetrics(cur.info, cint(cp), addr adv, addr lsb)
    var kern = 0
    if prevCp >= 0:
      kern = stbtt_GetCodepointKernAdvance(cur.info, cint(prevCp), cint(cp))
    prevCp = cp
    var gw, gh, gox, goy: cint
    let bmp = stbtt_GetCodepointBitmap(cur.info, curScale, curScale, cint(cp),
                                       addr gw, addr gh, addr gox, addr goy)
    if bmp != nil:
      let startX = int(penX + gox.float)
      let startY = int(baseline + goy.float)
      for py in 0 ..< int(gh):
        let sy = startY + py
        if sy < 0 or sy >= h:
          continue
        for px in 0 ..< int(gw):
          let sx = startX + px
          if sx < 0 or sx >= w:
            continue
          let a = cast[ptr UncheckedArray[byte]](bmp)[py * int(gw) + px]
          if a > 0:
            pixels[sy * pitch + sx] = (argb and 0x00FFFFFF) or (uint32(a) shl 24)
      stbtt_FreeBitmap(bmp, nil)
    penX += (adv.float + kern.float) * curScale
  unlockSurface(result)

proc blitText*(dst: SurfacePtr, font: Font, size: float, color: Color,
               text: string, x, y: cint) =
  ## テキストをサーフェスに描画する。
  if not font.loaded or text.len == 0:
    return
  let surf = renderLine(font, size, color, text)
  if surf == nil:
    return
  discard setSurfaceBlendMode(surf, BlendMode_Blend)
  var dstRect = rect(x, y, surf.w, surf.h)
  discard blitSurface(surf, nil, dst, addr dstRect)
  freeSurface(surf)

proc wrapTextPx*(font: Font, size: float, text: string, maxW: int): seq[string] =
  ## 指定幅 (px) で折り返す。空白で分割、長すぎる単語は文字単位で分割。
  if not font.loaded:
    return @[text]
  result = @[]
  var line = ""
  var lineW = 0
  let spaceW = measureText(font, size, " ").w
  for token in text.splitWhitespace():
    let tokenW = measureText(font, size, token).w
    if lineW + tokenW > maxW and line.len > 0:
      result.add(line)
      line = token
      lineW = tokenW
    else:
      if line.len > 0:
        line.add(" ")
        lineW += spaceW
      line.add(token)
      lineW += tokenW
    if lineW > maxW:
      result.add(line)
      line = ""
      lineW = 0
  if line.len > 0:
    result.add(line)
  if result.len == 0:
    result.add("")
