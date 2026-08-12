## group.nim
## F2F: グループ管理モジュール (ホスト-ゲスト星形トポロジ・自動ホスト昇格)
##
## ホスト-ゲスト星形トポロジを管理し、ホスト切断時に最古のゲストを
## 自動的にホストに昇格させる機能を提供する。

import asyncdispatch, times, json, strutils, tables, sets, sequtils, endians, options
import protocol, crypto

const
  GROUP_TIMEOUT_MS = 30000
  MAX_GROUP_SIZE = 50

type
  GroupState* = enum
    GroupIdle,        # 未参加/空
    GroupActive,      # 活動中
    GroupPromoting,   # ホスト昇格中
    GroupDisbanded    # 解散

  # グループ管理セッション (ホスト側)
  GroupSession* = object
    group*          : F2FGroup
    state*          : GroupState
    hostPriv*       : SkSecretKey          # ホストの秘密鍵 (ホストのみ保持)
    pendingJoins*   : seq[GroupJoinReq]    # 保留中の参加要求
    pendingLeaves*  : seq[GroupLeaveReq]   # 保留中の脱退要求
    lastActivity*   : uint64
    onHostChange*   : proc(newHost: SkPublicKey) {.async.}  # ホスト昇格コールバック

  # ゲスト側のグループ情報
  GroupGuestInfo* = object
    groupId*        : string
    hostPubkey*     : SkPublicKey
    members*        : seq[GroupMember]
    myMember*       : GroupMember
    state*          : GroupState
    lastHeartbeat*  : uint64

# カスタム例外
type
  GroupError* = object of CatchableError

# ---------------------------------------------------------------------------
# 内部ヘルパー
# ---------------------------------------------------------------------------

proc groupMemberToJson(m: GroupMember): JsonNode =
  var j = newJObject()
  j["pubkey"] = %* fpubEncode(m.pubkey)
  var addrArr = newJArray()
  for a in m.addresses: addrArr.add(%* a)
  j["addresses"] = addrArr
  j["joinedAt"] = %* m.joinedAt
  j["isHost"] = %* m.isHost
  j["isConnected"] = %* m.isConnected
  return j

proc jsonToGroupMember(node: JsonNode): GroupMember =
  GroupMember(
    pubkey: fpubDecode(node["pubkey"].getStr()),
    addresses: node["addresses"].mapIt(it.getStr()),
    joinedAt: node["joinedAt"].getBiggestInt().uint64,
    isHost: node["isHost"].getBool(),
    isConnected: node["isConnected"].getBool()
  )

proc groupToJson*(g: F2FGroup): JsonNode =
  var j = newJObject()
  j["groupId"] = %* g.groupId
  j["hostPubkey"] = %* fpubEncode(g.hostPubkey)
  var membersArr = newJArray()
  for m in g.members:
    membersArr.add(groupMemberToJson(m))
  j["members"] = membersArr
  j["version"] = %* g.version
  j["createdAt"] = %* g.createdAt
  # 署名は raw バイト列を hex でエンコード
  var sigHex = ""
  for b in g.signature.sig.toRaw():
    sigHex.add($b.toHex(2))
  j["signature"] = %* sigHex
  return j

proc jsonToGroup(node: JsonNode): F2FGroup =
  var members = newSeq[GroupMember]()
  for m in node["members"]:
    members.add(jsonToGroupMember(m))
  F2FGroup(
    groupId: node["groupId"].getStr(),
    hostPubkey: fpubDecode(node["hostPubkey"].getStr()),
    members: members,
    version: node["version"].getBiggestInt().uint64,
    createdAt: node["createdAt"].getBiggestInt().uint64,
    signature: emptySignature()  # 実際は検証時に設定
  )

# ---------------------------------------------------------------------------
# 公開 API: グループ作成・管理 (ホスト側)
# ---------------------------------------------------------------------------

# 新しいグループを作成 (自分がホストになる)
proc signGroupData*(group: F2FGroup, priv: SkSecretKey): FodprSignature =
  # 簡易実装: groupId + hostPubkey + version + createdAt + members count を署名
  var data = ""
  data.add(group.groupId)
  let hostRaw = group.hostPubkey.toRawCompressed()
  for b in hostRaw: data.add(char(b))
  var vNet: uint64
  bigEndian64(addr vNet, unsafeAddr group.version)
  var vBytes: array[8, byte]
  copyMem(addr vBytes[0], addr vNet, 8)
  for b in vBytes: data.add(char(b))
  var cNet: uint64
  bigEndian64(addr cNet, unsafeAddr group.createdAt)
  var cBytes: array[8, byte]
  copyMem(addr cBytes[0], addr cNet, 8)
  for b in cBytes: data.add(char(b))
  data.add(char(byte(group.members.len)))
  signBytes(priv, data)

proc createGroup*(
  hostPriv: SkSecretKey,
  groupId: string = "",
  maxSize: int = MAX_GROUP_SIZE
): GroupSession =
  let hostPub = hostPriv.toPublicKey()
  let gid = if groupId.len > 0: groupId else: fpubEncode(hostPub)
  
  let now = uint64(epochTime())
  let member = GroupMember(
    pubkey: hostPub,
    addresses: @[],
    joinedAt: now,
    isHost: true,
    isConnected: true
  )
  
  var group = F2FGroup(
    groupId: gid,
    hostPubkey: hostPub,
    members: @[member],
    version: 1,
    createdAt: now,
    signature: emptySignature()
  )
  
  group.signature = signGroupData(group, hostPriv)
  
  result = GroupSession(
    group: group,
    state: GroupActive,
    hostPriv: hostPriv,
    pendingJoins: @[],
    pendingLeaves: @[],
    lastActivity: now,
    onHostChange: nil
  )

# グループに署名
# グループ署名検証
proc verifyGroup*(group: F2FGroup): bool =
  # 簡易検証: hostPubkey で署名検証
  var data = ""
  data.add(group.groupId)
  let hostRaw = group.hostPubkey.toRawCompressed()
  for b in hostRaw: data.add(char(b))
  var vNet: uint64
  bigEndian64(addr vNet, unsafeAddr group.version)
  var vBytes: array[8, byte]
  copyMem(addr vBytes[0], addr vNet, 8)
  for b in vBytes: data.add(char(b))
  var cNet: uint64
  bigEndian64(addr cNet, unsafeAddr group.createdAt)
  var cBytes: array[8, byte]
  copyMem(addr cBytes[0], addr cNet, 8)
  for b in cBytes: data.add(char(b))
  data.add(char(byte(group.members.len)))
  verifyBytes(group.hostPubkey, data, group.signature)

# メンバー追加 (ホスト側)
proc addMember*(
  session: var GroupSession,
  member: GroupMember
): bool =
  if session.group.members.len >= MAX_GROUP_SIZE:
    return false
  
  # 重複チェック
  for m in session.group.members:
    if m.pubkey == member.pubkey:
      return false
  
  session.group.members.add(member)
  session.group.version += 1
  session.group.signature = signGroupData(session.group, session.hostPriv)
  session.lastActivity = uint64(epochTime())
  return true

# メンバー削除 (ホスト側)
proc removeMember*(
  session: var GroupSession,
  memberPubkey: SkPublicKey,
  isHostChange: bool = false
): bool =
  var idx = -1
  for i, m in session.group.members:
    if m.pubkey == memberPubkey:
      idx = i
      break
  
  if idx == -1:
    return false
  
  session.group.members.delete(idx)
  session.group.version += 1
  
  if not isHostChange:
    session.group.signature = signGroupData(session.group, session.hostPriv)
  
  session.lastActivity = uint64(epochTime())
  return true

# ホスト昇格処理 (最古の接続中ゲストを新ホストに)
proc promoteNewHost*(
  session: var GroupSession
): Option[SkPublicKey] =
  # 現在のホスト以外で接続中のメンバーを探す (最古順)
  var candidates = newSeq[GroupMember]()
  for m in session.group.members:
    if not m.isHost and m.isConnected:
      candidates.add(m)
  
  if candidates.len == 0:
    return none(SkPublicKey)
  
  # joinedAt でソート (最古が先頭)
  # 簡易バブルソート
  for i in 0..<candidates.len:
    for j in i+1..<candidates.len:
      if candidates[j].joinedAt < candidates[i].joinedAt:
        swap(candidates[i], candidates[j])
  
  let newHost = candidates[0]
  
  # 古いホストを非ホストに
  for i, m in session.group.members:
    if m.isHost:
      session.group.members[i].isHost = false
      break
  
  # 新ホストを設定
  for i, m in session.group.members:
    if m.pubkey == newHost.pubkey:
      session.group.members[i].isHost = true
      session.group.members[i].isConnected = true
      break
  
  session.group.hostPubkey = newHost.pubkey
  session.group.version += 1
  # 署名は新ホストの秘密鍵で行う必要があるが、ここではホスト側の秘密鍵がないため
  # 実際の昇格時には新ホスト側で再署名する
  
  session.state = GroupPromoting
  session.lastActivity = uint64(epochTime())
  
  return some(newHost.pubkey)

# グループ解散
proc disbandGroup*(
  session: var GroupSession
): bool =
  session.state = GroupDisbanded
  session.group.members = @[]
  session.group.version += 1
  return true

# ---------------------------------------------------------------------------
# ゲスト側: グループ参加・脱退・ハートビート
# ---------------------------------------------------------------------------

# グループ参加要求作成
proc createGroupJoinReq*(
  priv: SkSecretKey,
  groupId: string,
  member: GroupMember
): GroupJoinReq =
  var req = GroupJoinReq(
    groupId: groupId,
    member: member,
    signature: emptySignature()
  )
  # 署名対象: groupId + member.pubkey + member.joinedAt
  var data = groupId
  let pubRaw = member.pubkey.toRawCompressed()
  for b in pubRaw: data.add(char(b))
  var jNet: uint64
  bigEndian64(addr jNet, unsafeAddr member.joinedAt)
  var jBytes: array[8, byte]
  copyMem(addr jBytes[0], addr jNet, 8)
  for b in jBytes: data.add(char(b))
  req.signature = signBytes(priv, data)
  return req

# 参加要求検証 (ホスト側)
proc verifyGroupJoinReq*(req: GroupJoinReq): bool =
  var data = req.groupId
  let pubRaw = req.member.pubkey.toRawCompressed()
  for b in pubRaw: data.add(char(b))
  var jNet: uint64
  bigEndian64(addr jNet, unsafeAddr req.member.joinedAt)
  var jBytes: array[8, byte]
  copyMem(addr jBytes[0], addr jNet, 8)
  for b in jBytes: data.add(char(b))
  verifyBytes(req.member.pubkey, data, req.signature)

# グループ脱退要求作成
proc createGroupLeaveReq*(
  priv: SkSecretKey,
  groupId: string,
  memberPubkey: SkPublicKey
): GroupLeaveReq =
  var req = GroupLeaveReq(
    groupId: groupId,
    memberPubkey: memberPubkey,
    signature: emptySignature()
  )
  var data = groupId
  let pubRaw = memberPubkey.toRawCompressed()
  for b in pubRaw: data.add(char(b))
  req.signature = signBytes(priv, data)
  return req

# 脱退要求検証
proc verifyGroupLeaveReq*(req: GroupLeaveReq): bool =
  var data = req.groupId
  let pubRaw = req.memberPubkey.toRawCompressed()
  for b in pubRaw: data.add(char(b))
  verifyBytes(req.memberPubkey, data, req.signature)

# ゲスト側: グループ情報更新
proc updateGuestGroupInfo*(
  guest: var GroupGuestInfo,
  group: F2FGroup
): bool =
  # ホスト変更検知
  if guest.hostPubkey != group.hostPubkey:
    guest.hostPubkey = group.hostPubkey
    guest.state = GroupPromoting
  
  guest.members = group.members
  guest.groupId = group.groupId
  
  # 自分の情報更新
  for m in group.members:
    if m.pubkey == guest.myMember.pubkey:
      guest.myMember = m
      break
  
  guest.lastHeartbeat = uint64(epochTime())
  return true

# ハートビート送信 (ゲスト → ホスト)
proc sendHeartbeat*(
  guestPriv: SkSecretKey,
  guestInfo: GroupGuestInfo,
  toHost: SkPublicKey
): string =
  let now = uint64(epochTime())
  var data = guestInfo.groupId
  let pubRaw = guestPriv.toPublicKey().toRawCompressed()
  for b in pubRaw: data.add(char(b))
  var tNet: uint64
  bigEndian64(addr tNet, unsafeAddr now)
  var tBytes: array[8, byte]
  copyMem(addr tBytes[0], addr tNet, 8)
  for b in tBytes: data.add(char(b))
  let sig = signBytes(guestPriv, data)
  
  # 署名は raw バイト列を hex でエンコード
  var sigHex = ""
  for b in sig.sig.toRaw():
    sigHex.add($b.toHex(2))
  
  return $(%*{
      "type": "heartbeat",
      "groupId": guestInfo.groupId,
      "member": fpubEncode(guestPriv.toPublicKey()),
      "timestamp": now,
      "signature": %* sigHex
    })

# ---------------------------------------------------------------------------
# シグナリング統合: SignalHostChange 処理
# ---------------------------------------------------------------------------

# SignalHostChange コンテンツ作成
proc createHostChangeSignal*(
  newHost: SkPublicKey,
  groupId: string
): string =
  $(%*{
    "newHost": fpubEncode(newHost),
    "groupId": groupId
  })

# SignalHostChange 解析
proc parseHostChangeSignal*(content: string): tuple[newHost: SkPublicKey, groupId: string] =
  let doc = parseJson(content)
  let newHost = fpubDecode(doc["newHost"].getStr())
  let groupId = doc["groupId"].getStr()
  return (newHost: newHost, groupId: groupId)

# SignalGroupJoin コンテンツ作成
proc createGroupJoinSignal*(req: GroupJoinReq): string =
  $(%*{
    "groupId": req.groupId,
    "member": groupMemberToJson(req.member)
  })

# SignalGroupLeave コンテンツ作成
proc createGroupLeaveSignal*(req: GroupLeaveReq): string =
  $(%*{
    "groupId": req.groupId,
    "memberPubkey": fpubEncode(req.memberPubkey)
  })

# グループ状態をJSONで取得 (デバッグ用)
proc groupToDebugString*(session: GroupSession): string =
  var membersStr = ""
  for i, m in session.group.members:
    if i > 0: membersStr.add(", ")
    membersStr.add(fpubEncode(m.pubkey))
    if m.isHost: membersStr.add(" (HOST)")
  
  var j = %*{
    "groupId": session.group.groupId,
    "host": fpubEncode(session.group.hostPubkey),
    "state": $session.state,
    "version": session.group.version,
    "members": %* membersStr,
    "memberCount": session.group.members.len
  }
  return pretty(j)