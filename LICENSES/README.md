# 使用ライブラリのライセンス一覧

このドキュメントは Fodpr が依存しているサードパーティライブラリのライセンス情報をまとめたものです。
各ライセンスの全文は本ディレクトリ内の対応するファイルを参照してください。

| ライセンス | ライセンス全文 |
|------------|----------------|
| MIT ライセンス | [MIT.txt](MIT.txt) |
| Apache License 2.0 | [Apache-2.0.txt](Apache-2.0.txt) |
| OpenLDAP Public License 2.8 | [OpenLDAP-Public-License-2.8.txt](OpenLDAP-Public-License-2.8.txt) |

## 直接依存ライブラリ

`Fodpr.nimble` の `requires` で宣言されているライブラリです。

| ライブラリ | バージョン | ライセンス | 著作権表示 | リポジトリ |
|------------|-----------|------------|------------|------------|
| ws | 0.6.0 | MIT | Andre von Houck | https://github.com/treeform/ws |
| nim-secp256k1 | 0.6.0.3.2 | Apache License 2.0 | Status Research & Development GmbH | https://github.com/status-im/nim-secp256k1 |
| nimcrypto | 0.7.3 | MIT | Copyright (c) 2018 Eugene Kabanov | https://github.com/cheatfate/nimcrypto |
| nimSHA2 | 0.1.1 | MIT | Copyright (c) 2015 Andri Lim | https://github.com/jangko/nimSHA2 |
| nim-lmdb | 0.1.2 | OpenLDAP Public License 2.8 | Federico Ceratto | https://github.com/FedericoCeratto/nim-lmdb |

### nim-secp256k1 に同梱される C ライブラリ

`nim-secp256k1` は `vendor/` ディレクトリに
[bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1) のフォークを同梱しています。

| ライブラリ | ライセンス | 著作権表示 | リポジトリ |
|------------|------------|------------|------------|
| bitcoin-core/secp256k1（同梱版） | MIT | Copyright (c) 2013 Pieter Wuille | https://github.com/bitcoin-core/secp256k1 |

### nim-lmdb がラップする C ライブラリ

`nim-lmdb` はシステムの LMDB（Lightning Memory-Mapped Database）C ライブラリを
ラップしています。

| ライブラリ | ライセンス | 著作権表示 | リポジトリ |
|------------|------------|------------|------------|
| LMDB | OpenLDAP Public License 2.8 | Copyright (c) 2011-2013 Howard Chu, Symas Corp. | http://symas.com/mdb/ |

## 推移的依存ライブラリ

直接依存ライブラリがさらに依存しているライブラリです。

| ライブラリ | バージョン | ライセンス | 著作権表示 | リポジトリ |
|------------|-----------|------------|------------|------------|
| stew | 0.5.0 | MIT または Apache License 2.0 | Status Research & Development GmbH | https://github.com/status-im/nim-stew |
| results | 0.5.1 | MIT または Apache License 2.0 | Copyright (c) 2019 Jacek Sieka | https://github.com/arnetheduck/nim-results |
| unittest2 | 0.2.5 | MIT | Nim Contributors, Ștefan Talpalaru, Status Research and Development（テスト専用） | https://github.com/status-im/nim-unittest2 |

## メモ

- `results` / `stew` は「MIT または Apache License 2.0」のデュアルライセンスです。どちらかを選択できます。
- `unittest2` はテスト時のみに使用されます（`nim-secp256k1` のテスト依存関係）。
- この一覧はインストール時点（2026-08-05）の `nimble` パッケージ情報に基づいています。バージョン更新時は各ライブラリのライセンスも再確認してください。
