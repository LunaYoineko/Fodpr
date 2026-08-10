# Fodpr（ふぉどぷる）

**Fully Open Decentralized Protocol**

Fodpr (pronounced "fodopuru" in Japanese, written ふぉどぷる) is a **protocol**
— a set of communication rules — for exchanging social-media-style posts
(**events**) without depending on any specific company or service. Posts are
sent and received through a **relay server**, a kind of relay station.

> 日本語版は [README.md](README.md) をご覧ください。

---

## What Fodpr lets you do

- **Open to everyone**
  It runs on open rules, so no single company or service is in charge.

- **No impersonation or tampering**
  Every post carries an **electronic signature**, so anyone can verify that it
  was written by the real author and has not been altered.

- **Not tied to a single server**
  Anyone can run a relay server. Even if one server goes down, communication
  continues as long as other servers exist.

- **Free choice of post format**
  The sender freely picks one of three formats: JSON (structured data),
  String (plain text), or Binary (e.g. image data).

- **Metadata protection (full-event signing)**
  With a **Signed** event (TransTypeSigned), the timestamp, public key, and
  tags are signed along with the content, so relays cannot tamper with
  metadata undetected. The SHA-256 of the signed bytes becomes an
  **event ID**, allowing a specific event to be referenced uniquely
  (the basis for mail thread references).

- **Per-recipient encryption (E2EE envelope)**
  With an **Encrypted** event (TransTypeEncrypted), the content is an
  **envelope** whose body is AES-256-GCM encrypted and whose key is wrapped
  per recipient (gift-wrap equivalent). Only the intended recipients can
  decrypt the body. The relay verifies the structure but cannot read it.

  - **Reader authentication (read auth)**
    Recipient-limited events (`to:<fpub>` tag) are only delivered to
    subscriptions authenticated as that recipient via a challenge (AUTH,
    the equivalent of NIP-42).

  - **WebRTC signaling**
    `TransTypeWebRTC` (6) opens a signaling-only channel via SIGNAL (0x05) /
    SIGNAL_PUSH (0x83) messages, relaying SDP/ICE candidates (including IPv6
    temporary addresses) with secp256k1 signatures. Signaling messages are not
    stored — forwarded immediately. Supports host-guest star topology with
    automatic host failover.

## How it works in one glance

Think of it like the postal system: the **relay server** is the post office,
an **event** is a letter, and the **electronic signature** is the sender's seal.

1. **Post** — the sender attaches an electronic signature and sends the event to a relay server
2. **Store** — the relay server checks the signature and keeps the event
3. **Request** — a reader asks the relay server, "Please send me events of this type"
4. **Receive** — the relay server delivers the matching events in real time

## Key terms

| Term                | Meaning                                                    |
|---------------------|------------------------------------------------------------|
| Protocol            | The rules computers follow to communicate                  |
| Event               | One post's worth of data                                   |
| Relay server        | The "post office" that stores and delivers events          |
| Client              | An app or tool that uses Fodpr                             |
| Public/private key  | A key pair that proves who you are                         |
| Electronic signature| A digital seal that only the real author can create        |
| Subscription (REQ)  | Asking the relay server, "Please send me events"           |

---

## Getting started (for developers)

### Requirements

- [Nim](https://nim-lang.org/) 2.2.10 or later
- [Nimble](https://github.com/nim-lang/nimble) (used to install dependencies)
- For a native relay server run, the LMDB runtime library is required
  (on Debian/Ubuntu: `liblmdb0`), see FodprRelay
- For Docker relay runs, [Docker Engine](https://docs.docker.com/engine/) and
  [Docker Compose](https://docs.docker.com/compose/)

### Big picture

1. Start the relay server (the "post office")
2. Run the client (the posting / reading tool)

### 1. Start the relay server (FodprRelay)

The relay server lives in the separate
[FodprRelay](https://github.com/LunaYoineko/FodprRelay) repository.
Clone it and run:

```bash
git clone https://github.com/LunaYoineko/FodprRelay
cd FodprRelay
nimble build -y
./src/server
```

On startup you will see:

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

After it starts, visiting `http://localhost:8000/` returns a small placeholder
text for verification. Follow the logs with `docker compose logs -f`.

### 2. Run the client

In another terminal:

```bash
nim c -r examples/fodpr_client.nim
```

The client performs the following:

1. Connects to `ws://localhost:8000/`
2. Generates a key pair and posts three events as EVENTs: JSON, String, and Binary
   (each gets `OK: Event accepted`)
3. Sends a REQ (subscription request, TransType: All) to subscribe to every type
4. The server returns stored events as PUSH messages
5. The client renders each event using its type's delivery method
   (JSON is parsed and pretty-printed, String is shown as-is, Binary shows size only)
6. Receives the end-of-events notification (`EOE: ...`) and closes the connection

### 3. Run the sample (no server needed)

To try the protocol encode / decode without a network:

```bash
nim c -r examples/protocol_demo.nim
```

It demonstrates key-pair generation, creating and signing an event,
encode → decode round-trip, signature verification, and REQ encode / decode —
all offline.

---

## Technical specification (for developers)

### Directory layout

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
├── README.en.md        # English README
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

### Message types (first byte)

| Value | Type  | Direction                | Description                  |
|-------|-------|--------------------------|------------------------------|
| 0x01  | EVENT | client → server          | Post a signed event          |
| 0x02  | REQ   | client → server          | Subscription request         |
| 0x03  | DEL   | client → server          | Delete-events request (signed)|
| 0x04  | AUTH  | client → server          | Read-authentication signature response (NIP-42 equivalent) |
| 0x05  | SIGNAL | client → server         | WebRTC signaling message     |
| 0x81  | PUSH  | server → client          | Event delivery               |
| 0x82  | CHALLENGE | server → client       | Authentication challenge (32-byte nonce) |
| 0x83  | SIGNAL_PUSH | server → client     | WebRTC signaling relay       |

All integers are encoded in **big-endian** byte order.

### Transmission types (TransType) and delivery methods

`transType` is a **transmission method** ("how to send") that the sender picks
freely. The server never interprets the semantics of `content`
(profile / note / media, etc.); it only stores and delivers based on the
transmission type. All semantic interpretation and profile management is the
client's responsibility (e.g., if `content` is JSON, the client may treat a
specific key/value as a profile).

| Constant           | Value | Description                                          | Delivery method                                      |
|--------------------|-------|------------------------------------------------------|------------------------------------------------------|
| `TransTypeJSON`    | 1     | Structured data (`content` is UTF-8 JSON)            | Server validates JSON syntax on receive; client parses and pretty-prints on receive |
| `TransTypeString`  | 2     | String (`content` is UTF-8)                          | Delivered and displayed as a plain string            |
| `TransTypeBinary`  | 3     | Binary data (`content` is arbitrary bytes)           | Delivered as-is; client shows the size only          |
| `TransTypeSigned`  | 4     | Full-event signing (`content` is arbitrary)          | All fields are signed; SHA-256 of the signed bytes is the event ID |
| `TransTypeEncrypted` | 5   | Encrypted event (`content` is an envelope)          | `content` is a per-recipient envelope from `envelope.nim`. Validates full signature + `to:` tag match |
| `TransTypeWebRTC`  | 6     | WebRTC signaling (signaling-only channel)            | Uses SIGNAL (0x05) / SIGNAL_PUSH (0x83). Never stored; forwarded with secp256k1 signatures |
| `TransTypeAll`     | 0     | All types (REQ only)                                 | Server delivers stored events of every type          |

### EVENT binary layout

```
transType(2) | createdAt(8) | pubkey(33) | tagCount(2)
| (tagLen(2) | tag) × tagCount | contentLen(4) | content | signature(64)
```

- `transType` — transmission type (uint16: 0=All (REQ only), 1=JSON, 2=String, 3=Binary, 4=Signed, 5=Encrypted, 6=WebRTC)
- `createdAt` — Unix timestamp in seconds (uint64)
- `pubkey` — sender's public key (compressed, 33 bytes)
- `tags` — list of tag strings
- `content` — body (JSON, string, binary, or envelope depending on the type)
- `signature` — ECDSA signature (64 bytes)
  - TransType 1–3 (JSON / String / Binary): over the SHA-256 digest of `content`
  - TransType 4–5 (Signed / Encrypted): over **all fields** including `createdAt`,
    `pubkey`, and `tags` (the bytes from `encodeEventSignedData()`)

### Full-event signing (TransTypeSigned) and event ID

`TransTypeSigned` signs every field except `signature` itself
(`transType | createdAt | pubkey | tags | content`). The **SHA-256** of these
signed bytes (`encodeEventSignedData(ev)`) is the **event ID** (`eventId`).

```nim
let evId = eventIdHex(ev)      # 64-hex-digit string
let ok   = verifyEvent(ev.pubkey, ev, ev.signature)  # verify full-event signature
```

Event IDs can be referenced through the `e:<eventId>` tag, so
**reply-to / thread references** can be expressed precisely.

### Per-recipient encryption (TransTypeEncrypted) and the envelope

The `content` of `TransTypeEncrypted` is a **per-recipient encrypted envelope**
(gift-wrap / seal equivalent) built by `envelope.nim`.

Envelope layout (all big-endian):

```
version(1) | recipientCount(2) |
(recipientPubkey(33) | wrapNonce(12) | wrappedKey(32) | wrappedKeyTag(16)) × recipientCount |
bodyNonce(12) | bodyTag(16) | bodyCiphertext
```

Key scheme:

- A message key **K** (32 random bytes) AES-256-GCM encrypts the body
- K is wrapped for each recipient with a wrapping key **W** derived from ECDH
  - `W = SHA-256(ECDH(senderPriv, recipientPub) || "FodprEnvelopeV1" || recipientPub)`
- A recipient recomputes the same W from `ECDH(theirPriv, senderPub)`, unwraps K,
  and decrypts the body

```nim
# sender: encrypt for multiple recipients
let envelope = encryptEnvelope(body, senderPriv, @[recip1.publicKey, recip2.publicKey])
# recipient: decrypt with your private key and the event's pubkey (the sender)
let body = decryptEnvelope(ev.content, myPriv, ev.pubkey)
```

Relay-side API (structure-only; no decryption):

```nim
let ok     = isValidEnvelope(ev.content)         # structure validation
let recips = envelopeRecipients(ev.content)      # recipient public keys (matched against `to:` tags)
```

An Encrypted event requires at least one `to:<fpub>` tag, and the relay verifies
that the tags match the recipients inside the envelope (preventing delivery to
someone not on the recipient list).

### Read authentication (AUTH, NIP-42 equivalent)

`to:<fpub>` recipient-limited events require the recipient to authenticate so
only that person can receive them. The relay runs a **challenge → signed
response** flow.

```
1. client   → REQ(subId, tagKey="to", tagVal=fpub)
2. server   → CHALLENGE (0x82) with nonce(32)
3. client   → AUTH (0x04): nonce(32) | pubkey(33) | signature(64)
   (the signed bytes are: nonce | pubkey)
4. server   → after verification, resumes the REQ for that recipient
```

```nim
var auth = FodprAuth(nonce: nonce, pubkey: kp.publicKey, signature: placeholder)
auth.signature = signContent(kp.privateKey, encodeAuthSignedData(auth))
await ws.send(encodeAuth(auth), Binary)
```

Only subscriptions that pass authentication receive `to:` recipient-limited
events. Public events remain available without authentication.

### Tag conventions

Tags are strings in `"<key>:<value>"` form.

| Tag           | Description                                        |
|---------------|----------------------------------------------------|
| `to:<fpub>`   | Recipient's public key (fpub form, lowercase). Required for recipient-limited events |
| `p:<fpub>`    | Participant's public key (for reference)           |
| `e:<eventId>` | Referenced event (used for reply-to / thread linking) |

### REQ binary layout

```
MsgTypeReq(1) | subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

- `transType` of `0` (`TransTypeAll`) subscribes to every type
- `transType` of `1` through `5` subscribes to the matching type (JSON / String / Binary / Signed / Encrypted)
- `transType` of `6` (`TransTypeWebRTC`) subscribes to WebRTC signaling only.
  The `to:` tag (recipient fpub) is required. No stored events are returned (EOE
  only); subsequent SIGNAL messages are relayed in real time
- `tagKey` / `tagVal` filter events by tag (`tagKey = "pubkey"` filters by public key, `tagKey = "to"` filters by recipient)

### PUSH binary layout

```
MsgTypePush(1) | subIdLen(2) | subId | EVENT payload
```

### DEL binary layout (event delete API)

Authors can delete their own events. Because the whole request is signed,
**only the author of an event can delete it**.

```
MsgTypeDel(1) | transType(2) | targetType(1) | pubkey(33)
| [createdAt(8) | contentHash(32)] | [eventId(32)] | signature(64)
```

**Signed data** (the bytes below, excluding `signature`):

```
transType(2) | targetType(1) | pubkey(33) | [createdAt(8) | contentHash(32)] | [eventId(32)]
```

- `transType` — transmission type of the events to delete (`0` = all, `1` = JSON, `2` = String, `3` = Binary, `4` = Signed, `5` = Encrypted)
- `targetType` — how to select the target events
  - `0` (`DelTargetPubkey`): delete all events of that public key within the given `transType`
  - `1` (`DelTargetEvent`): delete the specific event whose `createdAt` and `contentHash` (SHA-256 of `content`) match
  - `2` (`DelTargetEventId`): delete the specific event whose `eventId` matches (recommended for full-event-signed events)
- `pubkey` — public key of the events to delete (your own public key only)
- `signature` — ECDSA signature (64 bytes) over the signed data above, made with the author's private key

The server verifies the signature and deletes only events whose public key
matches the request (others' events cannot be deleted).

API provided by the library:

```nim
var req = FodprDelReq(
  transType: TransTypeJSON,    # transmission type to delete
  targetType: DelTargetPubkey, # delete by pubkey / DelTargetEvent for a specific event
  pubkey: kp.publicKey,        # your public key
  createdAt: ev.createdAt,     # only for DelTargetEvent
  contentHash: hash,           # only for DelTargetEvent (SHA-256 of content)
  signature: sig)              # value signed below
let packet = encodeDel(req)    # full DEL packet (leading 0x03 + signature)
```

Sign the bytes returned by `encodeDelSignedData(req)`:

```nim
let signed = encodeDelSignedData(req)
req.signature = signContent(kp.privateKey, signed)
```

On the server side, restore the packet with `decodeDelReq(stream)` and verify
the signature with `verifyContent`.

### WebRTC Signaling (TransTypeWebRTC)

`TransTypeWebRTC` (6) is for WebRTC P2P signaling. The relay acts as a
**signaling server only** — it never stores signaling messages and forwards them
immediately after signature verification. After the P2P connection is
established, the relay is no longer involved.

#### Signaling messages (SIGNAL / SIGNAL_PUSH)

**SIGNAL packet (0x05, client → server):**

```
MsgTypeSignal(1) | signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content | signature(64)
```

**SIGNAL_PUSH packet (0x83, server → client):**

```
MsgTypeSignalPush(1) | subIdLen(2) | subId | signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content | signature(64)
```

**Signed data:**

```
signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content
```

| Field | Description |
|-------|-------------|
| `signalType` | `1`=Offer, `2`=Answer, `3`=Candidate, `4`=HostChange |
| `senderPubkey` | Sender's public key (compressed, 33 bytes) |
| `targetPubkey` | Recipient's public key (compressed, 33 bytes) |
| `content` | SDP offer/answer JSON or ICE candidate JSON (IPv6 temporary addresses included) |
| `signature` | secp256k1 ECDSA signature over all the above (64 bytes) |

Library API:

```nim
# Create and sign a signaling message
var sig = FodprSignal(
  signalType: SignalOffer,
  sender: kp.publicKey,
  target: targetPub,
  content: """{"sdp":"...","candidates":[...],"ipv6TempAddr":"2001:db8::1"}""")
sig.signature = signSignal(kp.privateKey, sig)
let packet = $MsgTypeSignal & encodeSignal(sig)

# Receive and verify
let received = decodeSignal(strm)
if verifySignal(received):
  # signature OK — trust the sender
  echo signalTypeName(received.signalType), ": ", received.content
```

#### Host-guest star topology & automatic host failover

Supports a star topology where multiple guests connect to one host via WebRTC.

- **Group ID** = the host's fpub (lowercase)
- Clients join a host's group by subscribing with
  `REQ(TransTypeWebRTC, tagKey="to", tagVal=<host_fpub>)` (AUTH required)
- When the host disconnects, the **oldest guest** (earliest `joinedAt`) is
  automatically promoted to host
- The relay sends a text notification `HOST_CHANGE: <new_host_fpub>` to all
  remaining members
- Members re-subscribe with the new host's fpub

```
Host (B) ── signal ──→  Relay  ←── signal ──  Guest (A)
Host (B) ── signal ──→  Relay  ←── signal ──  Guest (C)

B disconnects → A (oldest guest) promoted → HOST_CHANGE → everyone reconnects
```

- P2P communication uses **IPv6 temporary addresses** (SDP/ICE candidates in
  `content` as JSON)
- The relay never interprets or decrypts `content`; only signature verification
  and recipient matching are performed
- Both peers verify each other's secp256k1 signatures on received signals
- After P2P establishment, direct data channel communication bypasses the relay

### Storage (server.nim in FodprRelay)

The relay server (FodprRelay) persists events in LMDB, split into per-type DBIs
(in the `./data/` directory, created automatically at startup).

| DBI         | Stored events    | Key                    |
|-------------|------------------|------------------------|
| `json`      | TransTypeJSON    | Current time + random  |
| `string`    | TransTypeString  | Current time + random  |
| `binary`    | TransTypeBinary  | Current time + random  |
| `signed`    | TransTypeSigned  | Current time + random  |
| `encrypted` | TransTypeEncrypted | Current time + random |

- The server never interprets `content`, so every type is stored by appending under a unique key
- On shutdown (Ctrl+C) the environment is closed; data survives restarts

### Cryptography (crypto.nim)

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

---

## License

Fodpr itself is licensed under the MIT License.

License information for the third-party libraries in use is documented in
[LICENSES/](LICENSES/README.md).
