import streams, endians
import crypto, secp256k1

const
  MsgTypeEvent* = char(0x01)
  MsgTypeReq*   = char(0x02)
  MsgTypePush*  = char(0x81)

type
  FodprEvent* = object
    kind*      : uint16
    createdAt* : uint64
    pubkey*    : SkPublicKey
    tags*      : seq[string]
    content*   : string
    signature* : FodprSignature

  FodprReq* = object
    subId*  : string
    kind*   : uint16
    tagKey* : string
    tagVal* : string

# Event のエンコード
proc encodeEvent*(ev: FodprEvent): string =
  result = ""
  
  var kNet: uint16
  bigEndian16(addr kNet, unsafeAddr ev.kind)
  var kBytes: array[2, byte]
  copyMem(addr kBytes[0], addr kNet, 2)
  result.add(char(kBytes[0]))
  result.add(char(kBytes[1]))
  
  var caNet: uint64
  bigEndian64(addr caNet, unsafeAddr ev.createdAt)
  var caBytes: array[8, byte]
  copyMem(addr caBytes[0], addr caNet, 8)
  for b in caBytes: result.add(char(b))
  
  let pubRaw = ev.pubkey.toRawCompressed()
  for b in pubRaw: result.add(char(b))
  
  let tagCount = uint16(ev.tags.len)
  var tcNet: uint16
  bigEndian16(addr tcNet, unsafeAddr tagCount)
  var tcBytes: array[2, byte]
  copyMem(addr tcBytes[0], addr tcNet, 2)
  result.add(char(tcBytes[0]))
  result.add(char(tcBytes[1]))
  
  for t in ev.tags:
    let tLen = uint16(t.len)
    var tlNet: uint16
    bigEndian16(addr tlNet, unsafeAddr tLen)
    var tlBytes: array[2, byte]
    copyMem(addr tlBytes[0], addr tlNet, 2)
    result.add(char(tlBytes[0]))
    result.add(char(tlBytes[1]))
    result.add(t)
    
  let cLen = uint32(ev.content.len)
  var clNet: uint32
  bigEndian32(addr clNet, unsafeAddr cLen)
  var clBytes: array[4, byte]
  copyMem(addr clBytes[0], addr clNet, 4)
  for b in clBytes: result.add(char(b))
  result.add(ev.content)
  
  let sigRaw = ev.signature.sig.toRaw()
  for b in sigRaw: result.add(char(b))

# Event のデコード（ヘルパー関数を使用）
proc decodeEvent*(stream: Stream): FodprEvent =
  let kBytes = stream.readStr(2)
  var kNet, kindVal: uint16
  copyMem(addr kNet, unsafeAddr kBytes[0], 2)
  bigEndian16(addr kindVal, addr kNet)
  
  let caBytes = stream.readStr(8)
  var caNet, caVal: uint64
  copyMem(addr caNet, unsafeAddr caBytes[0], 8)
  bigEndian64(addr caVal, addr caNet)
  
  # Pubkey (33 bytes)
  let pubBytes = stream.readStr(33)
  var pubBytesArr: array[33, byte]
  for i in 0..<33: pubBytesArr[i] = byte(pubBytes[i])
  let pubkey = parsePublicKey(pubBytesArr)
  
  let tcBytes = stream.readStr(2)
  var tcNet, tagCount: uint16
  copyMem(addr tcNet, unsafeAddr tcBytes[0], 2)
  bigEndian16(addr tagCount, addr tcNet)
  
  var tags = newSeq[string]()
  for i in 0..<tagCount:
    let tlBytes = stream.readStr(2)
    var tlNet, tLen: uint16
    copyMem(addr tlNet, unsafeAddr tlBytes[0], 2)
    bigEndian16(addr tLen, addr tlNet)
    tags.add(stream.readStr(int(tLen)))
    
  let clBytes = stream.readStr(4)
  var clNet, cLen: uint32
  copyMem(addr clNet, unsafeAddr clBytes[0], 4)
  bigEndian32(addr cLen, addr clNet)
  let content = stream.readStr(int(cLen))
  
  # Signature (64 bytes)
  let sigBytes = stream.readStr(64)
  var sigBytesArr: array[64, byte]
  for i in 0..<64: sigBytesArr[i] = byte(sigBytes[i])
  let skSig = parseSignature(sigBytesArr)
  
  return FodprEvent(
    kind: kindVal,
    createdAt: caVal,
    pubkey: pubkey,
    tags: tags,
    content: content,
    signature: FodprSignature(sig: skSig)
  )

# REQ のエンコード・デコード
proc encodeReq*(r: FodprReq): string =
  result = ""
  result.add(MsgTypeReq)
  
  let idLen = uint16(r.subId.len)
  var idNet: uint16
  bigEndian16(addr idNet, unsafeAddr idLen)
  var idBytes: array[2, byte]
  copyMem(addr idBytes[0], addr idNet, 2)
  result.add(char(idBytes[0]))
  result.add(char(idBytes[1]))
  result.add(r.subId)
  
  var kNet: uint16
  bigEndian16(addr kNet, unsafeAddr r.kind)
  var kBytes: array[2, byte]
  copyMem(addr kBytes[0], addr kNet, 2)
  result.add(char(kBytes[0]))
  result.add(char(kBytes[1]))
  
  let tkLen = uint16(r.tagKey.len)
  var tkNet: uint16
  bigEndian16(addr tkNet, unsafeAddr tkLen)
  var tkBytes: array[2, byte]
  copyMem(addr tkBytes[0], addr tkNet, 2)
  result.add(char(tkBytes[0]))
  result.add(char(tkBytes[1]))
  result.add(r.tagKey)
  
  let tvLen = uint16(r.tagVal.len)
  var tvNet: uint16
  bigEndian16(addr tvNet, unsafeAddr tvLen)
  var tvBytes: array[2, byte]
  copyMem(addr tvBytes[0], addr tvNet, 2)
  result.add(char(tvBytes[0]))
  result.add(char(tvBytes[1]))
  result.add(r.tagVal)

proc decodeReq*(stream: Stream): FodprReq =
  let idLenBytes = stream.readStr(2)
  var idNet, idLen: uint16
  copyMem(addr idNet, unsafeAddr idLenBytes[0], 2)
  bigEndian16(addr idLen, addr idNet)
  let subId = stream.readStr(int(idLen))
  
  let kBytes = stream.readStr(2)
  var kNet, kindVal: uint16
  copyMem(addr kNet, unsafeAddr kBytes[0], 2)
  bigEndian16(addr kindVal, addr kNet)
  
  let tkLenBytes = stream.readStr(2)
  var tkNet, tkLen: uint16
  copyMem(addr tkNet, unsafeAddr tkLenBytes[0], 2)
  bigEndian16(addr tkLen, addr tkNet)
  let tagKey = stream.readStr(int(tkLen))
  
  let tvLenBytes = stream.readStr(2)
  var tvNet, tvLen: uint16
  copyMem(addr tvNet, unsafeAddr tvLenBytes[0], 2)
  bigEndian16(addr tvLen, addr tvNet)
  let tagVal = stream.readStr(int(tvLen))
  
  return FodprReq(subId: subId, kind: kindVal, tagKey: tagKey, tagVal: tagVal)