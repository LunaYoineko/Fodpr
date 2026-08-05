## Fodpr.nim
## Fodpr ライブラリのメインモジュール。
##
## ワイヤプロトコル (protocol.nim) と暗号まわり (crypto.nim) を
## まとめて再エクスポートする。
##
## 利用例:
##   import Fodpr          # protocol と crypto をまとめて利用できる
##   import Fodpr/protocol # 個別のモジュールも直接 import できる
##
## クライアントのサンプル実装は examples/fodpr_client.nim を参照。

import protocol, crypto
export protocol, crypto
