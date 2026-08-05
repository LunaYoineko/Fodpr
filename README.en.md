# Fodpr

**Fully Open Decentralized Protocol**

Fodpr is a lightweight event-delivery protocol that runs over WebSocket.
Clients post signed events to a relay server and receive matching events in
real time by sending subscription requests (REQ).

> 日本語版は [README.md](README.md) をご覧ください。

## Features

- **Signed events** — Every event is signed with secp256k1 (ECDSA); the relay verifies authenticity and rejects tampered events
- **Simple binary protocol** — Fixed-size integers (big-endian) plus length-prefixed fields
- **Bech32 encoding** — Private keys can be exchanged as `fsec1...` and public keys as `fpub1...`
- **In-memory storage** — The relay keeps received events in memory and pushes them on subscription (demo implementation)
- **Graceful shutdown** — Pressing Ctrl+C (SIGINT) closes the listening socket and shuts the server down cleanly

## Directory Layout

```
Fodpr/
├── Fodpr.nimble        # Nimble package definition
├── config.nims         # Build configuration
├── nimble.paths        # Dependency paths
├── src/
│   ├── Fodpr.nim       # Client (sender) demo
│   ├── server.nim      # Relay server
│   ├── protocol.nim    # Wire protocol encode / decode
│   └── crypto.nim      # Bech32 and secp256k1 (keygen, signing, verification)
└── examples/
    └── protocol_demo.nim  # Sample using protocol.nim
```

## Requirements

- [Nim](https://nim-lang.org/) 2.2.10 or later
- [Nimble](https://github.com/nim-lang/nimble) (used to install dependencies)

## Build

Install dependencies:

```bash
nimble install -d
```

Build the relay server:

```bash
nim c src/server.nim
```

Build the client (or use `nimble build`):

```bash
nim c src/Fodpr.nim
```

## Usage

### 1. Start the relay server

```bash
./src/server
```

```
================================================
 Fodpr Relay Server running on ws://0.0.0.0:8000/ws
 (Ctrl+C で安全に終了できます)
================================================
```

Press **Ctrl+C** to shut the server down gracefully.

### 2. Start the client

In another terminal:

```bash
./src/Fodpr
```

The client performs the following:

1. Connects to `ws://localhost:8000/ws`
2. Generates a key pair, signs a test event, and posts it as an EVENT
3. The server verifies the signature, stores the event, and replies `OK: Event accepted`
4. Sends a REQ (subscription request)
5. The server returns stored events as PUSH messages
6. Receives the end-of-events notification (`EOE: ...`) and closes the connection

### 3. Run the sample (no server needed)

To try the protocol encode / decode without a network:

```bash
nim c -r examples/protocol_demo.nim
```

It demonstrates key-pair generation, creating and signing an event,
encode → decode round-trip, signature verification, and REQ encode / decode —
all offline.

## Protocol Specification

### Message types (first byte)

| Value | Type  | Direction                | Description                  |
|-------|-------|--------------------------|------------------------------|
| 0x01  | EVENT | client → server          | Post a signed event          |
| 0x02  | REQ   | client → server          | Subscription request         |
| 0x81  | PUSH  | server → client          | Event delivery               |

All integers are encoded in **big-endian** byte order.

### EVENT binary layout

```
kind(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `kind` — event type (uint16)
- `createdAt` — Unix timestamp in seconds (uint64)
- `pubkey` — sender's public key (compressed, 33 bytes)
- `tags` — list of tag strings
- `content` — body (UTF-8)
- `signature` — ECDSA signature over the SHA-256 digest of `content` (64 bytes)

### REQ binary layout

```
MsgTypeReq(1) | subIdLen(2) | subId | kind(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `kind` of `0` subscribes to all event types
- `tagKey` / `tagVal` filter events by tag (empty string means no filter)

### PUSH binary layout

```
MsgTypePush(1) | subIdLen(2) | subId | EVENT payload
```

## Cryptography (crypto.nim)

- Key pairs: secp256k1 elliptic curve (`nim-secp256k1`)
- Hash: SHA-256 (`nimSHA2`)
- Randomness: OS-provided cryptographically secure random bytes (`nimcrypto/sysrand`)
- Bech32: BIP-173 compliant. HRP is `fsec` for private keys and `fpub` for public keys

```nim
let kp = generateFodprKey()                    # generate a key pair
let sig = signContent(kp.privateKey, content)  # sign content
let ok   = verifyContent(kp.publicKey, content, sig)  # verify
let priv = fsecEncode(kp.privateKey)           # encode as fsec1...
```

## License

Fodpr itself is licensed under the MIT License.

License information for the third-party libraries in use is documented in
[LICENSES/](LICENSES/README.md).
