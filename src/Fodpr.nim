## Fodpr.nim
## Fodpr ライブラリのメインモジュール。
##
## ワイヤプロトコル (protocol.nim) と暗号まわり (crypto.nim)、
## 宛先別暗号化エンベロープ (envelope.nim) をまとめて再エクスポートする。
##
## 利用例:
##   import Fodpr          # protocol / crypto / envelope をまとめて利用できる
##   import Fodpr/protocol # 個別のモジュールも直接 import できる
##
## クライアントのサンプル実装は examples/fodpr_client.nim を参照。

import protocol, crypto, envelope
export protocol, crypto, envelope
