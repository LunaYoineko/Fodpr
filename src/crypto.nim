## crypto.nim
## Fodpr プロトコルで使う暗号まわりの機能をまとめたモジュール。
##
## 提供する機能:
##   - Bech32 (BIP-173) によるバイナリデータの文字列化（fsec / fpub 形式）
##   - secp256k1 (ECDSA) を使った鍵ペア生成・署名・署名検証
##
## 依存ライブラリ:
##   - secp256k1 : 楕円曲線暗号の実装 (nim-secp256k1)
##   - nimSHA2   : SHA-256 ハッシュ関数
##   - nimcrypto : OS の乱数生成器 (sysrand) の利用

import secp256k1, nimSHA2, strutils, nimcrypto

# Bech32 で使用する 32 文字の文字集合 (BIP-173 準拠)。
# 視認性が悪い "0", "1", "b", "i", "o" などを意図的に除外している。
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ---------------------------------------------------------------------------
# Bech32 符号化の内部ヘルパー (BIP-173 で定義されたアルゴリズム)
# ---------------------------------------------------------------------------

# Bech32 のチェックサム計算に使う多項式剰余 (polymod)。
# データ部分とチェックサム全体に対して計算し、結果が 1 になれば正当とみなす。
proc polymod(values: openArray[byte]): uint32 =
  var chk: uint32 = 1
  # BIP-173 で定められた生成多項式の係数
  const generator = [0x3b6a57b2.uint32, 0x26508e6d.uint32, 0x1ea119fa.uint32, 0x3d4233dd.uint32, 0x2a1462b3.uint32]
  for v in values:
    # 上位 25bit を退避し、5bit シフト + 入力バイトを加算してから
    # 生成多項式で XOR 縮約していく
    let top = chk shr 25
    chk = ((chk and 0x1ffffff) shl 5) xor uint32(v)
    for i in 0..<5:
      if ((top shr i) and 1) != 0:
        chk = chk xor generator[i]
  return chk

# HRP (Human Readable Part) を polymod 用の値へ変換する。
# 各文字を「上位3bit」と「下位5bit」に分解して、間に区切り(0)を挟んで並べる。
proc expandHrp(hrp: string): seq[byte] =
  result = newSeq[byte](hrp.len * 2 + 1)
  for i, c in hrp:
    result[i] = byte(ord(c) shr 5)
    result[i + hrp.len + 1] = byte(ord(c) and 31)
  result[hrp.len] = 0

# データのビット幅を変換する (例: 8bit → 5bit, 5bit → 8bit)。
# pad=true のときは端数をゼロで埋めて出力し、pad=false のときは
# 余ったビットが不正なら ValueError を投げる。
proc convertBits(data: openArray[byte], fromBits, toBits: int, pad: bool): seq[byte] =
  var acc = 0
  var bits = 0
  let maxv = (1 shl toBits) - 1
  for b in data:
    acc = (acc shl fromBits) or int(b)
    bits += fromBits
    while bits >= toBits:
      bits -= toBits
      result.add(byte((acc shr bits) and maxv))
  if pad:
    # 端数を左詰めしてゼロ埋めし、最後の 1 要素として出力
    if bits > 0:
      result.add(byte((acc shl (toBits - bits)) and maxv))
  elif bits >= fromBits or ((acc shl (toBits - bits)) and maxv) != 0:
    raise newException(ValueError, "Invalid padding in convertBits")

# 8bit バイト列を Bech32 文字列 (hrp + "1" + データ + 6文字チェックサム) に変換する。
proc bech32Encode(hrp: string, data: openArray[byte]): string =
  # まず 8bit → 5bit に変換する (Bech32 は 5bit 単位で文字に割り当てるため)
  let converted = convertBits(data, 8, 5, true)
  # チェックサム計算のために HRP 展開値 + データ + チェックサム用ゼロ6文字分を連結
  var combined = expandHrp(hrp) & converted
  for i in 0..<6: combined.add(0)
  let pm = polymod(combined) xor 1
  # polymod の結果から 6 文字分のチェックサムを下位ビットから取り出す
  var checksum = newSeq[byte](6)
  for i in 0..<6:
    checksum[5 - i] = byte((pm shr (i * 5)) and 31)

  result = hrp & "1"
  # 5bit 値を CHARSET の文字に変換して連結する
  for b in converted & checksum:
    result.add(CHARSET[int(b)])

# Bech32 文字列を検証しつつ、データ部分を 8bit バイト列へ復元する。
# HRP が一致しない場合や不正な文字が含まれる場合は ValueError を投げる。
proc bech32Decode(bechStr: string, expectedHrp: string): seq[byte] =
  if bechStr.len < 8:
    raise newException(ValueError, "Bech32 string too short")

  # "1" の位置を探す ("1" 以降がデータ部分とチェックサム)
  let pos = bechStr.rfind('1')
  if pos == -1 or pos < 1 or pos + 7 > bechStr.len:
    raise newException(ValueError, "Invalid Bech32 format")

  # HRP 部分を取り出して大文字小文字を無視して比較
  let hrp = bechStr[0..<pos].toLowerAscii()
  if hrp != expectedHrp.toLowerAscii():
    raise newException(ValueError, "HRP mismatch: expected " & expectedHrp)

  # 各文字を CHARSET のインデックス (5bit 値) に逆変換
  var data = newSeq[byte](bechStr.len - pos - 1)
  for i in 0..<data.len:
    let c = bechStr[pos + 1 + i]
    let idx = CHARSET.find(c)
    if idx == -1:
      raise newException(ValueError, "Invalid character in Bech32 string")
    data[i] = byte(idx)

  # 末尾 6 文字はチェックサムなので除外し、5bit → 8bit に戻す
  # (pad=false なので余分なビットがあればエラーになる)
  let decoded5bit = data[0 .. ^7]
  return convertBits(decoded5bit, 5, 8, false)

# ---------------------------------------------------------------------------
# Fodpr 固有の鍵・署名インターフェース
# ---------------------------------------------------------------------------

type
  # 公開鍵と秘密鍵のペア。secp256k1 の SkSecretKey / SkPublicKey を保持する。
  FodprKeyPair* = object
    privateKey*: SkSecretKey
    publicKey*: SkPublicKey

  # Fodpr の署名をラップする型。中身は secp256k1 の SkSignature。
  FodprSignature* = object
    sig*: SkSignature

# 暗号学的に安全な乱数を OS から取得するための RNG。
# nimcrypto の sysrand (/dev/urandom など) を利用している。
# この関数は「絶対に失敗しない」前提の FoolproofRng として使う。
proc secureRng(data: var openArray[byte]) {.gcsafe, raises: [].} =
  discard randomBytes(data)

# 新しい鍵ペアを生成する。
# SkSecretKey.random は RNG が必要なため、上記の secureRng を渡している。
# ライブラリの仕様上、SkSecretKey 等は requireInit 型であり、
# デフォルト初期化できない点に注意する。
proc generateFodprKey*(): FodprKeyPair =
  # SkSecretKey.random(FoolproofRng) は Result を返さず直接 SkSecretKey を返す
  let priv = SkSecretKey.random(secureRng)
  # 公開鍵は秘密鍵から必ず一意に導出できる
  result = FodprKeyPair(privateKey: priv, publicKey: priv.toPublicKey())

# 秘密鍵 (32 バイト) を "fsec1..." 形式の Bech32 文字列へエンコードする。
proc fsecEncode*(priv: SkSecretKey): string =
  bech32Encode("fsec", priv.toRaw())

# 公開鍵 (圧縮形式 33 バイト) を "fpub1..." 形式の Bech32 文字列へエンコードする。
proc fpubEncode*(pub: SkPublicKey): string =
  bech32Encode("fpub", pub.toRawCompressed())

# "fsec1..." 形式の Bech32 文字列を復号して秘密鍵オブジェクトに戻す。
proc fsecDecode*(fsecStr: string): SkSecretKey =
  let bytes = bech32Decode(fsecStr, "fsec")
  # fromRaw は Result 型を返すため、isErr を確認してから中身を取り出す
  let parsed = SkSecretKey.fromRaw(bytes)
  if parsed.isErr:
    raise newException(ValueError, "Invalid private key bytes: " & $parsed.error)
  return parsed.get()

# "fpub1..." 形式の Bech32 文字列を復号して公開鍵オブジェクトに戻す。
proc fpubDecode*(fpubStr: string): SkPublicKey =
  let bytes = bech32Decode(fpubStr, "fpub")
  let parsed = SkPublicKey.fromRaw(bytes)
  if parsed.isErr:
    raise newException(ValueError, "Invalid public key bytes: " & $parsed.error)
  return parsed.get()

# ネットワークから受け取った生バイト列から公開鍵を生成する。
# 形式が不正な場合は ValueError を投げる。
proc parsePublicKey*(bytes: openArray[byte]): SkPublicKey =
  let parsed = SkPublicKey.fromRaw(bytes)
  if parsed.isErr:
    raise newException(ValueError, "Invalid public key bytes: " & $parsed.error)
  return parsed.get()

# ネットワークから受け取った生バイト列から署名を生成する。
# 形式が不正な場合は ValueError を投げる。
proc parseSignature*(bytes: openArray[byte]): SkSignature =
  let parsed = SkSignature.fromRaw(bytes)
  if parsed.isErr:
    raise newException(ValueError, "Invalid signature bytes: " & $parsed.error)
  return parsed.get()

# コンテンツ文字列を SHA-256 でハッシュし、秘密鍵で ECDSA 署名を生成する。
# secp256k1 の sign は 32 バイトのダイジェスト (SkMessage) を必要とする。
proc signContent*(priv: SkSecretKey, content: string): FodprSignature =
  # ① 内容を SHA-256 で 32 バイトのダイジェストに変換
  #    (SHA256Digest は array[32, byte] なので SkMessage に直接変換できる)
  let msg = SkMessage(computeSHA256(content))
  # ② ECDSA で署名を生成
  result = FodprSignature(sig: priv.sign(msg))

# 公開鍵を使い、コンテンツに対する署名が正しいかどうかを検証する。
# 署名時に使ったのと同じハッシュ化を行い、一致すれば true を返す。
proc verifyContent*(pub: SkPublicKey, content: string, sig: FodprSignature): bool =
  let msg = SkMessage(computeSHA256(content))
  return sig.sig.verify(msg, pub)
