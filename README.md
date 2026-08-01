# BvfKit

Swift library for personal encryption. Built on HPKE (RFC 9180) + XChaCha20-Poly1305 secretstream + Argon2id. Minimization of crypto surface and amenability to plaintext never touching disk were primary in design. Sensitive material is zeroized on dealloc; keys and passphrases are additionally mlocked.

Compatible with the canonical implementation [bvf](https://github.com/openbvf/bvf) (Rust), which provides a [library](https://github.com/openbvf/bvf/tree/main/bvf) and [CLI](https://github.com/openbvf/bvf/tree/main/bvf-cli) with key management, batch operations, and long-term format stability independent of this library. See that repo for [SECURITY.md](https://github.com/openbvf/bvf/blob/main/SECURITY.md) and [file format](https://github.com/openbvf/bvf/blob/main/SPEC.md).

Canonical implementation was written by hand. BvfKit's development is reviewed by a human line-by-line, with a particular eye on C-interop.

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

Chunking is handled automatically; memory stays constant regardless of size.

```swift
// Generate a keypair and export the private key protected by a passphrase
let keypair = try Keypair.generate()
let passphrase = "my passphrase"
let encryptedKey = try keypair.exportEncryptedPrivateKey(passphrase: passphrase)

// Encrypt
let plaintext = Data("hello world".utf8)
var ciphertext = Data()
let encrypter = try Encrypter(recipientPublicKey: keypair.publicKey)
try encrypter.encrypt(from: reading(plaintext), to: { ciphertext.append($0) })

// Decrypt
var recovered = Data()
let decrypter = try Decrypter(encryptedPrivateKey: encryptedKey, passphrase: passphrase)
try decrypter.decrypt(from: reading(ciphertext), to: { recovered.append($0) })

assert(recovered == plaintext)  // "hello world"
```

The API can read and write through closures, so any source or sink works. This example's helper reads a `Data` in memory; writing is a plain `append`:

```swift
func reading(_ data: Data) -> (Int) -> Data? {
    var offset = 0
    return { count in
        guard offset < data.count else { return nil }   // nil at EOF
        let end = min(offset + count, data.count)
        defer { offset = end }
        return data.subdata(in: offset..<end)
    }
}
```

To stream files instead of buffering in memory, pass file-backed closures: a read that returns `FileHandle.read(upToCount:)` and a write that calls `FileHandle.write(contentsOf:)`.

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
var recovered = try decState.decryptChunk(body.prefix(BvfConfig.ciphertextChunkSize))!
recovered += try decState.decryptChunk(body.dropFirst(BvfConfig.ciphertextChunkSize))!
try decState.validateComplete()
assert(recovered == secret + secret)
```

## More examples

The snippets above are illustrative. For runnable, end-to-end usage see the test suite in `Tests/BvfKitTests/` and the open-source apps built on BvfKit.

