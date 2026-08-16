# Package

version       = "0.7.0"
author        = "LunaYoineko"
description   = "Fully Open Decentralized Protocol"
license       = "MIT"
srcDir        = "src"

# Dependencies

requires "nim >= 2.2.10"
requires "secp256k1"
requires "nimcrypto"
requires "nimSHA2"
requires "ws"

# ipv6test.nim (examples/) 用 TUI ライブラリ
  requires "illwill"
  # sdl2 is required for examples/chat_client.nim (iOS / macOS / Linux builds)
  requires "sdl2"
