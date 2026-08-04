import secp256k1, nimSHA2, strutils, sequtils, nimcrypto

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

proc polymod(values: openArray[byte]): uint32 =
  var chk: uint32 = 1
  const generator = [0x3b6a57b2'u32, 0x26508e6d'u32, 0x1ea119fa'u32, 0x3d4233dd'u32, 0x2a1462b3'u32]
  for v in values:
    let top = chk shr 25
    chk = ((chk and 0x1ffffff) shl 5) xor uint32(v)
    for i in 0..<5:
      if ((top shr i) and 1) != 0:
        chk = chk xor generator[i]
  return chk

proc expandHrp(hrp: string): seq[byte] =
  result = newSeq[byte](hrp.len * 2 + 1)
  for i, c in hrp:
    result[i] = byte(ord(c) shr 5)
    result[i + hrp.len + 1] = byte(ord(c) and 31)
  result[hrp.len] = 0

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
    if bits > 0:
      result.add(byte((acc shl (toBits - bits)) and maxv))
  elif bits >= fromBits or ((acc shl (toBits - bits)) and maxv) != 0:
    raise newException(ValueError, "Invalid padding in convertBits")

proc bech32Encode(hrp: string, data: openArray[byte]): string =
  let converted = convertBits(data, 8, 5, true)
  var combined = expandHrp(hrp) & converted
  for i in 0..<6: combined.add(0)
  let pm = polymod(combined) xor 1
  var checksum = newSeq[byte](6)
  for i in 0..<6:
    checksum[5 - i] = byte((pm shr (i * 5)) and 31)
  
  result = hrp & "1"
  for b in converted & checksum:
    result.add(CHARSET[b])

proc bech32Decode(bechStr: string, expectedHrp: string): seq[byte] =
  if bechStr.len < 8:
    raise newException(ValueError, "Bech32 string too short")
  
  let pos = bechStr.rfind('1')
  if pos == -1 or pos < 1 or pos + 7 > bechStr.len:
    raise newException(ValueError, "Invalid Bech32 format")
  
  let hrp = bechStr[0..<pos].toLowerAscii()
  if hrp != expectedHrp.toLowerAscii():
    raise newException(ValueError, "HRP mismatch: expected " & expectedHrp)
  
  var data = newSeq[byte](bechStr.len - pos - 1)
  for i in 0..<data.len:
    let c = bechStr[pos + 1 + i]
    let idx = CHARSET.find(c)
    if idx == -1:
      raise newException(ValueError, "Invalid character in Bech32 string")
    data[i] = byte(idx)
  
  let decoded5bit = data[0 .. ^7]
  return convertBits(decoded5bit, 5, 8, false)

# --- Fodpr 固有の鍵・署名インターフェース ---

type
  FodprKeyPair* = object
    privateKey*: SkSecretKey
    publicKey*: SkPublicKey

  FodprSignature* = object
    sig*: SkSignature

proc generateFodprKey*(): FodprKeyPair =
  # 宣言と同時に randomize() を呼ぶことはできないため、
  # 一度生成用の関数を使うか、あるいはライブラリの仕様に合わせます。
  # nim-secp256k1 では通常以下のように書けますが、もしエラーになる場合は
  # 以下のようにコンストラクタ形式で記述します。
  result = FodprKeyPair()
  result.privateKey.randomize()
  result.publicKey = result.privateKey.toPublicKey()

proc fsecEncode*(priv: SkSecretKey): string =
  bech32Encode("fsec", priv.toRaw())

proc fpubEncode*(pub: SkPublicKey): string =
  bech32Encode("fpub", pub.toRawCompressed())

proc fsecDecode*(fsecStr: string): SkSecretKey =
  let bytes = bech32Decode(fsecStr, "fsec")
  # 未初期化エラーを避けるため、結果変数に直接 fromRaw を適用する
  if result.fromRaw(bytes) != 1:
    raise newException(ValueError, "Invalid private key bytes")

proc fpubDecode*(fpubStr: string): SkPublicKey =
  let bytes = bech32Decode(fpubStr, "fpub")
  if result.fromRaw(bytes) != 1:
    raise newException(ValueError, "Invalid public key bytes")

proc parsePublicKey*(bytes: openArray[byte]): SkPublicKey =
  if result.fromRaw(bytes) != 1:
    raise newException(ValueError, "Invalid public key bytes")

proc parseSignature*(bytes: openArray[byte]): SkSignature =
  if result.fromRaw(bytes) != 1:
    raise newException(ValueError, "Invalid signature bytes")

proc signContent*(priv: SkSecretKey, content: string): FodprSignature =
  let hashHex = sha256(content)
  var msgBytes: array[32, byte]
  for i in 0..<32:
    let hexByte = hashHex[i*2 .. i*2+1]
    msgBytes[i] = parseHexInt(hexByte).byte
  
  var sig: SkSignature
  discard priv.sign(msgBytes, sig)
  return FodprSignature(sig: sig)

proc verifyContent*(pub: SkPublicKey, content: string, sig: FodprSignature): bool =
  let hashHex = sha256(content)
  var msgBytes: array[32, byte]
  for i in 0..<32:
    let hexByte = hashHex[i*2 .. i*2+1]
    msgBytes[i] = parseHexInt(hexByte).byte
    
  return pub.verify(sig.sig, msgBytes)