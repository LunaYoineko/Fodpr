## Fodpr.nim
## Fodpr ライブラリのメインモジュール。
##
## ワイヤプロトコル (protocol.nim) と暗号まわり (crypto.nim)、
## 宛先別暗号化エンベロープ (envelope.nim)、
## F2Fネットワーク (f2f/*) をまとめて再エクスポートする。
##
## 利用例:
##   import Fodpr          # すべてのモジュールを利用できる
##   import Fodpr/protocol # 個別のモジュールも直接 import できる
##   import Fodpr/f2f      # F2Fモジュール群
##
## クライアントのサンプル実装は examples/fodpr_client.nim を参照。

import protocol, crypto, envelope
import f2f/peer_cache, f2f/discovery, f2f/bootstrap, f2f/wot, f2f/invitation, f2f/signaling, f2f/transport, f2f/group

export protocol, crypto, envelope, peer_cache, discovery, bootstrap, wot, invitation, signaling, transport, group
