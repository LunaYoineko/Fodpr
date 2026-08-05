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
- **Persistent LMDB storage** — Received events are split into per-type DBs (JSON / String / Binary) and survive restarts (a relay-server feature)
- **Transmission types (TransType)** — Each user freely picks a transmission method from JSON / String / Binary. The server never interprets `content` semantics; it only stores and delivers based on the transmission type (all semantic interpretation such as profile management is the client's responsibility)
- **Standalone relay server (FodprRelay)** — The relay server lives in the separate [FodprRelay](https://github.com/LunaYoineko/FodprRelay) repository (Docker support / graceful shutdown)

## Directory Layout

```
Fodpr/
├── Fodpr.nimble        # Nimble package definition (Library type)
├── src/
│   ├── Fodpr.nim       # Library main module (re-exports protocol / crypto)
│   ├── protocol.nim    # Wire protocol encode / decode
│   └── crypto.nim      # Bech32 and secp256k1 (keygen, signing, verification)
├── examples/
│   ├── fodpr_client.nim    # Sample client that talks to the relay server
│   └── protocol_demo.nim   # Sample using protocol.nim (no server needed)
├── LICENSES/           # Third-party library license information
├── README.md           # 日本語版 README
└── data/               # LMDB database (used by the relay server, git-ignored)
```

The relay server (FodprRelay) is maintained in a separate repository:

```
FodprRelay/
├── FodprRelay.nimble   # Nimble package definition (requires "https://github.com/LunaYoineko/Fodpr")
├── Dockerfile          # Docker image definition for the relay server
├── docker-compose.yml  # Docker Compose config (port 8000 / data volume)
└── src/
    └── server.nim      # Relay server
```

## Requirements

- [Nim](https://nim-lang.org/) 2.2.10 or later
- [Nimble](https://github.com/nim-lang/nimble) (used to install dependencies)
- For a native relay server run, the LMDB runtime library is required (on Debian/Ubuntu: `liblmdb0`), see FodprRelay
- For Docker relay runs, [Docker Engine](https://docs.docker.com/engine/) and [Docker Compose](https://docs.docker.com/compose/)

## Build

Install dependencies:

```bash
nimble install -d
```

Run the sample client (while the relay server is up, in another terminal):

```bash
nim c -r examples/fodpr_client.nim
```

Run the protocol encode / decode sample:

```bash
nim c -r examples/protocol_demo.nim
```

## Usage

### 1. Start the relay server (FodprRelay)

The relay server lives in the separate [FodprRelay](https://github.com/LunaYoineko/FodprRelay)
repository. Clone it and run:

```bash
git clone https://github.com/LunaYoineko/FodprRelay
cd FodprRelay
nimble build -y
./src/server
```

```
================================================
 Fodpr Relay Server running on ws://0.0.0.0:8000/
 (Ctrl+C で安全に終了できます)
================================================
```

Press **Ctrl+C** to shut the server down gracefully.

Run with Docker:

```bash
cd FodprRelay
docker compose up -d --build
```

After it starts, visiting `http://localhost:8000/` returns a small
placeholder text for verification. Follow logs with `docker compose logs -f`.

### 2. Start the client

In another terminal:

```bash
nim c -r examples/fodpr_client.nim
```

The client performs the following:

1. Connects to `ws://localhost:8000/`
2. Generates a key pair and posts three events as EVENTs: JSON, String, and Binary (each gets `OK: Event accepted`)
3. Sends a REQ (subscription request, TransType: All) to subscribe to every type
4. The server returns stored events as PUSH messages
5. The client renders each event using its type's delivery method (JSON is parsed and pretty-printed, String is shown as-is, Binary shows size only)
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

### Transmission types (TransType) and delivery methods

Defined as constants in `protocol.nim`. `transType` is a **transmission method**
("how to send") that each user can pick freely. The server never interprets the
semantics of `content` (profile / note / media, etc.); it only stores and
delivers based on the transmission type. All semantic interpretation and profile
management is the client's responsibility (e.g., if `content` is JSON, the client
may treat a specific key/value as a profile).

| Constant         | Value | Description                                          | Delivery method                                      |
|------------------|-------|------------------------------------------------------|------------------------------------------------------|
| `TransTypeJSON`  | 1     | Structured data (`content` is UTF-8 JSON)            | Server validates JSON syntax on receive; client parses and pretty-prints on receive |
| `TransTypeString`| 2     | String (`content` is UTF-8)                          | Delivered and displayed as a plain string            |
| `TransTypeBinary`| 3     | Binary data (`content` is arbitrary bytes)           | Delivered as-is; client shows the size only          |
| `TransTypeAll`   | 0     | All types (REQ only)                                 | Server delivers stored events of every type          |

### EVENT binary layout

```
transType(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `transType` — transmission type (uint16: 1 = JSON, 2 = String, 3 = Binary)
- `createdAt` — Unix timestamp in seconds (uint64)
- `pubkey` — sender's public key (compressed, 33 bytes)
- `tags` — list of tag strings
- `content` — body (JSON, string, or binary depending on the type)
- `signature` — ECDSA signature over the SHA-256 digest of `content` (64 bytes)

### REQ binary layout

```
MsgTypeReq(1) | subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `transType` of `0` (`TransTypeAll`) subscribes to every type
- `transType` of `1` / `2` / `3` subscribes to the matching type (JSON / String / Binary)
- `tagKey` / `tagVal` filter events by tag (currently `tagKey = "pubkey"` filters by public key; empty string means no filter)

### PUSH binary layout

```
MsgTypePush(1) | subIdLen(2) | subId | EVENT payload
```

## Storage (server.nim in FodprRelay)

The relay server (FodprRelay) persists events in LMDB, split into per-type DBIs
(in the `./data/` directory, created automatically at startup).

| DBI         | Stored events    | Key                    |
|-------------|------------------|------------------------|
| `json`      | TransTypeJSON    | Current time + random  |
| `string`    | TransTypeString  | Current time + random  |
| `binary`    | TransTypeBinary  | Current time + random  |

- The server never interprets `content`, so every type is stored by appending under a unique key
- On shutdown (Ctrl+C) the environment is closed; data survives restarts

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
