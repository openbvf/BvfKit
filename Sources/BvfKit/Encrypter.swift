import Foundation
import CryptoKit
import Clibsodium

/// Streaming encryption state. Created by `start()`.
///
/// Marked `@unchecked Sendable` with an internal lock so the type can cross
/// isolation boundaries (required by Swift concurrency). Callers must still
/// invoke `encryptChunk` sequentially for secretstream.
public final class EncryptionState: @unchecked Sendable {
    internal var secretstreamState: crypto_secretstream_xchacha20poly1305_state
    internal var finalized: Bool = false
    private let lock = NSLock()

    internal init(secretstreamState: crypto_secretstream_xchacha20poly1305_state) {
        self.secretstreamState = secretstreamState
    }

    internal func withExclusiveAccess<R>(_ body: () throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }

    /// Encrypt a plaintext chunk.
    ///
    /// Non-final chunks MUST be exactly `BvfConfig.plaintextChunkSize`. Final chunk can be any size.
    ///
    /// - Throws: `BvfError.encryptionFailed` if encryption fails or state already finalized
    public func encryptChunk(_ plaintext: Data, isLast: Bool) throws -> Data {
        return try withExclusiveAccess {
            guard !finalized else {
                throw BvfError.encryptionFailed
            }

            if !isLast && plaintext.count != BvfConfig.plaintextChunkSize {
                throw BvfError.encryptionFailed
            }

            let tag = isLast ?
                UInt8(crypto_secretstream_xchacha20poly1305_TAG_FINAL) :
                UInt8(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)

            let ciphertextLen = plaintext.count + Int(crypto_secretstream_xchacha20poly1305_ABYTES)
            var ciphertext = [UInt8](repeating: 0, count: ciphertextLen)
            var ciphertextLenOut: UInt64 = 0

            let result: Int32
            var dummy: UInt8 = 0
            if plaintext.isEmpty {
                result = crypto_secretstream_xchacha20poly1305_push(
                    &secretstreamState,
                    &ciphertext, &ciphertextLenOut,
                    &dummy, 0,
                    &dummy, 0,
                    tag
                )
            } else {
                result = plaintext.withUnsafeBytes { plaintextBytes in
                    guard let plaintextBase = plaintextBytes.baseAddress else {
                        return -1
                    }
                    return crypto_secretstream_xchacha20poly1305_push(
                        &secretstreamState,
                        &ciphertext,
                        &ciphertextLenOut,
                        plaintextBase.assumingMemoryBound(to: UInt8.self),
                        UInt64(plaintext.count),
                        &dummy, 0,
                        tag
                    )
                }
            }

            guard result == 0 else {
                throw BvfError.encryptionFailed
            }

            if isLast {
                finalized = true
            }

            return Data(ciphertext.prefix(Int(ciphertextLenOut)))
        }
    }

    deinit {
        withUnsafeMutablePointer(to: &secretstreamState) { ptr in
            sodium_memzero(ptr, MemoryLayout<crypto_secretstream_xchacha20poly1305_state>.size)
        }
    }
}

/// HPKE-based streaming encryption.
///
/// Thread-safe: recipientPublicKey is immutable, EncryptionState serializes via NSLock.
/// Non-final chunks MUST be exactly `BvfConfig.plaintextChunkSize` for cross-client interoperability.
/// Multiple encryption sessions can be started independently via start().
public final class Encrypter: @unchecked Sendable {
    private let recipientPublicKey: Curve25519.KeyAgreement.PublicKey

    /// - Parameter recipientPublicKey: `bvf-pub:` format string encoding the X25519 public key
    public init(recipientPublicKey: String) throws {
        let rawKeyData = try PublicKeyFormat.decode(recipientPublicKey)
        try ensureSodiumInitialized()

        self.recipientPublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: rawKeyData
        )
    }

    /// Generate ephemeral HPKE keys and initialize secretstream.
    ///
    /// - Throws: `BvfError.encryptionFailed` if HPKE or secretstream initialization fails
    public func start() throws -> (header: Data, state: EncryptionState) {
        let hpkeSender = try HPKESender(recipientPublicKey: recipientPublicKey)
        let masterKey = try hpkeSender.deriveMasterKey()

        var masterKeyBytes = try extractSymmetricKeyBytes(masterKey)
        defer { sodium_memzero(&masterKeyBytes, masterKeyBytes.count) }

        var secretstreamState = crypto_secretstream_xchacha20poly1305_state()
        var secretstreamHeader = [UInt8](repeating: 0, count: Int(crypto_secretstream_xchacha20poly1305_HEADERBYTES))

        let initResult = crypto_secretstream_xchacha20poly1305_init_push(
            &secretstreamState,
            &secretstreamHeader,
            &masterKeyBytes
        )

        guard initResult == 0 else {
            throw BvfError.encryptionFailed
        }

        var header = Data()

        guard let versionHeaderData = BvfConfig.versionHeader.data(using: .utf8) else {
            throw BvfError.encryptionFailed
        }

        header.append(versionHeaderData)
        header.append(hpkeSender.encapsulatedKey)
        header.append(Data(secretstreamHeader))

        let state = EncryptionState(secretstreamState: secretstreamState)

        return (header, state)
    }

    /// Stream-level encryption from in-memory data. Handles chunking and TAG_FINAL.
    ///
    /// - Parameters:
    ///   - plaintext: Plaintext to encrypt.
    ///   - write: Closure that receives header then encrypted chunks.
    /// - Throws: `BvfError.encryptionFailed` on crypto failure.
    public func encrypt(_ plaintext: Data, to write: (Data) throws -> Void) throws {
        var offset = 0
        try encrypt(
            from: { size in
                guard offset < plaintext.count else { return nil }
                let end = min(offset + size, plaintext.count)
                let chunk = plaintext[offset..<end]
                offset = end
                return Data(chunk)
            },
            to: write
        )
    }

    /// Stream-level encryption from a read closure. Handles chunking and TAG_FINAL.
    ///
    /// - Parameters:
    ///   - read: Closure that returns up to N bytes, or nil/empty at EOF.
    ///   - write: Closure that receives header then encrypted chunks.
    /// - Throws: `BvfError.encryptionFailed` on crypto failure.
    public func encrypt(
        from read: (Int) throws -> Data?,
        to write: (Data) throws -> Void
    ) throws {
        let (header, state) = try start()
        try write(header)

        guard var current = try readExact(BvfConfig.plaintextChunkSize, from: read) else {
            let encrypted = try state.encryptChunk(Data(), isLast: true)
            try write(encrypted)
            return
        }

        if current.isEmpty {
            let encrypted = try state.encryptChunk(Data(), isLast: true)
            try write(encrypted)
            return
        }

        while true {
            guard let next = try readExact(BvfConfig.plaintextChunkSize, from: read), !next.isEmpty else {
                let encrypted = try state.encryptChunk(current, isLast: true)
                try write(encrypted)
                break
            }
            let encrypted = try state.encryptChunk(current, isLast: false)
            try write(encrypted)
            current = next
        }
    }
}
