# BvfKit

Swift library for personal encryption. Built on HPKE (RFC 9180) + XChaCha20-Poly1305 secretstream + Argon2id. Minimization of crypto surface and amenability to plaintext never touching disk were primary in design. Sensitive material is mlocked and zeroized on dealloc.

Compatible with the canonical implementation [bvf](https://github.com/openbvf/bvf) (Rust), which provides a [library](https://github.com/openbvf/bvf/tree/main/bvf) and [CLI](https://github.com/openbvf/bvf/tree/main/bvf-cli) with key management, batch operations, and long-term format stability independent of this library. See that repo for [SECURITY.md](https://github.com/openbvf/bvf/blob/main/SECURITY.md) and [file format](https://github.com/openbvf/bvf/blob/main/SPEC.md).

Canonical implementation was written by hand. BvfKit's development was AI-assisted and reviewed by a human line-by-line, with a particular eye on C-interop.

## Install

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/openbvf/BvfKit.git", from: "<version>")
]
```

Requires Swift 6.1+. macOS 15+, iOS 17+, or watchOS 10+.

## Two-tier API

**Stream**: `Encrypter.encrypt` / `Decrypter.decrypt` — chunking handled automatically.

**Push** — one chunk at a time:
- `Encrypter.start()` + `EncryptionState.encryptChunk`
- `Decrypter.start(header:)` + `DecryptionState.decryptChunk`

## Examples

### Stream

```swift
let keypair = try Keypair.generate()
let passphrase = "my passphrase"
let encryptedKey = try keypair.exportEncryptedPrivateKey(passphrase: passphrase)

// Encrypt from Data
let encrypter = try Encrypter(recipientPublicKey: keypair.publicKey)
var ciphertext = Data()
try encrypter.encrypt(Data("hello world".utf8)) { ciphertext.append($0) }

// Encrypt from closures (streaming, constant memory)
let encrypter = try Encrypter(recipientPublicKey: keypair.publicKey)
try encrypter.encrypt(from: read, to: write)

// Decrypt
let decrypter = try Decrypter(encryptedPrivateKey: encryptedKey, passphrase: passphrase)
try decrypter.decrypt(from: read, to: write)
```

### Push

```swift
let keypair = try Keypair.generate()
let passphrase = "my passphrase"
let encryptedKey = try keypair.exportEncryptedPrivateKey(passphrase: passphrase)

let secret = Data(repeating: 1, count: BvfConfig.plaintextChunkSize)

// Encrypt
let encrypter = try Encrypter(recipientPublicKey: keypair.publicKey)
let (header, encState) = try encrypter.start()
var ciphertext = header
ciphertext.append(try encState.encryptChunk(secret, isLast: false))
ciphertext.append(try encState.encryptChunk(secret, isLast: true))

// Decrypt
let decrypter = try Decrypter(encryptedPrivateKey: encryptedKey, passphrase: passphrase)
let decState = try decrypter.start(header: ciphertext.prefix(BvfConfig.headerSize))
let body = ciphertext.suffix(from: BvfConfig.headerSize)
let chunk1 = try decState.decryptChunk(Data(body.prefix(BvfConfig.ciphertextChunkSize)))
let chunk2 = try decState.decryptChunk(Data(body.dropFirst(BvfConfig.ciphertextChunkSize)))
try decState.validateComplete()
// chunk1! + chunk2! == secret + secret
```

