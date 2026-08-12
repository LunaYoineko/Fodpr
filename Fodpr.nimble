# Package

version       = "0.5.0"
author        = "LunaYoineko"
description   = "Fully Open Decentralized Protocol"
license       = "MIT"
srcDir        = "src"

bin           = @["server"]

# Dependencies

requires "nim >= 2.2.10"
requires "ws"
requires "secp256k1"
requires "nimcrypto"
requires "nimSHA2"
