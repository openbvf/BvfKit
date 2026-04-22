import Foundation
import CryptoKit
import Clibsodium

/// Streaming decryption state. Created by `start(header:)`.
///
/// Marked `@unchecked Sendable` with an internal lock so the type can cross
/// isolation boundaries (required by Swift concurrency). Callers must still
/// invoke `decryptChunk` sequentially for secretstream.
public final class DecryptionState: @unchecked Sendable {
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

    /// Validates that TAG_FINAL was received. Call after decryption loop completes.
    /// - Throws: `BvfError.truncated` if TAG_FINAL not received
    public func validateComplete() throws {
        try withExclusiveAccess {
            guard finalized else {
                throw BvfError.truncated
            }
        }
    }

    /// Decrypt a ciphertext chunk.
    ///
    /// Call `validateComplete()` after the loop to detect truncation.
    ///
    /// - Throws: `BvfError.decryptionFailed` on state misuse (already finalized, empty input)
    /// - Throws: `BvfError.authenticationFailed` if authentication fails
    public func decryptChunk(_ ciphertext: Data) throws -> Data? {
        return try withExclusiveAccess {
            guard !finalized else {
                throw BvfError.decryptionFailed
            }

            if ciphertext.isEmpty {
                throw BvfError.decryptionFailed
            }

            let plaintextMaxLen = ciphertext.count - Int(crypto_secretstream_xchacha20poly1305_ABYTES)
            guard plaintextMaxLen >= 0 else {
                throw BvfError.decryptionFailed
            }

            var plaintext = [UInt8](repeating: 0, count: plaintextMaxLen)
            var plaintextLenOut: UInt64 = 0
            var tag: UInt8 = 0

            let result: Int32
            var dummy: UInt8 = 0
            result = ciphertext.withUnsafeBytes { ciphertextBytes in
                guard let ciphertextBase = ciphertextBytes.baseAddress else {
                    return -1
                }
                return crypto_secretstream_xchacha20poly1305_pull(
                    &secretstreamState,
                    &plaintext,
                    &plaintextLenOut,
                    &tag,
                    ciphertextBase.assumingMemoryBound(to: UInt8.self),
                    UInt64(ciphertext.count),
                    &dummy, 0
                )
            }

            guard result == 0 else {
                sodium_memzero(&plaintext, plaintext.count)
                throw BvfError.authenticationFailed
            }

            if tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL {
                finalized = true
            }

            if plaintextLenOut == 0 {
                sodium_memzero(&plaintext, plaintext.count)
                return nil
            }

            let plaintextData = Data(plaintext.prefix(Int(plaintextLenOut)))
            sodium_memzero(&plaintext, plaintext.count)

            return plaintextData
        }
    }

    deinit {
        withUnsafeMutablePointer(to: &secretstreamState) { ptr in
            sodium_memzero(ptr, MemoryLayout<crypto_secretstream_xchacha20poly1305_state>.size)
        }
    }
}

/// HPKE-based streaming decryption.
///
/// Thread-safe: Decrypter is immutable after init, DecryptionState serializes via NSLock.
/// A single Decrypter can decrypt multiple files by calling start(header:) multiple times
/// (runs expensive Argon2id only once).
public final class Decrypter: @unchecked Sendable {
    private let keyManager: KeyManager

    /// - Parameters:
    ///   - encryptedPrivateKey: JSON Data containing the encrypted private key
    ///   - passphrase: Passphrase string
    public init(encryptedPrivateKey: Data, passphrase: String) throws {
        self.keyManager = try KeyManager(
            encryptedPrivateKey: encryptedPrivateKey,
            passphrase: passphrase
        )
    }

    /// The public key derived from the decrypted private key, in `bvf-pub:` format.
    public var publicKey: String {
        keyManager.publicKey
    }

    /// Parse file header and initialize decryption state.
    ///
    /// - Parameter headerData: File header (version + encapsulated key + secretstream header)
    /// - Throws: `BvfError.invalidFormat` if header invalid
    /// - Throws: `BvfError.decryptionFailed` if HPKE or secretstream initialization fails
    public func start(header headerData: Data) throws -> DecryptionState {
        guard headerData.count == BvfConfig.headerSize else {
            throw BvfError.invalidFormat
        }

        let versionHeaderBytes = headerData[0..<BvfConfig.versionHeader.count]
        guard let versionHeader = String(data: versionHeaderBytes, encoding: .utf8),
              versionHeader == BvfConfig.versionHeader else {
            throw BvfError.invalidFormat
        }

        let encKeyStart = BvfConfig.versionHeader.count
        let encKeyEnd = encKeyStart + Int(crypto_scalarmult_bytes())
        let encapsulatedKey = headerData[encKeyStart..<encKeyEnd]
        let secretstreamHeader = headerData[encKeyEnd..<BvfConfig.headerSize]

        let ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .exportOnly
        )

        let recipient = try keyManager.withPrivateKey { privateKey in
            try HPKE.Recipient(
                privateKey: privateKey,
                ciphersuite: ciphersuite,
                info: Data(BvfConfig.hpkeInfo.utf8),
                encapsulatedKey: encapsulatedKey
            )
        }

        let masterKey = try recipient.exportSecret(
            context: Data(BvfConfig.hpkeExportContext.utf8),
            outputByteCount: Int(crypto_secretstream_xchacha20poly1305_keybytes())
        )

        var masterKeyBytes = try extractSymmetricKeyBytes(masterKey)
        defer { sodium_memzero(&masterKeyBytes, masterKeyBytes.count) }

        var secretstreamState = crypto_secretstream_xchacha20poly1305_state()

        let initResult = secretstreamHeader.withUnsafeBytes { headerBytes in
            guard let headerBase = headerBytes.baseAddress else {
                return Int32(-1)
            }
            return crypto_secretstream_xchacha20poly1305_init_pull(
                &secretstreamState,
                headerBase.assumingMemoryBound(to: UInt8.self),
                &masterKeyBytes
            )
        }

        guard initResult == 0 else {
            throw BvfError.decryptionFailed
        }

        return DecryptionState(secretstreamState: secretstreamState)
    }

    /// Stream-level decryption to in-memory data.
    ///
    /// Catches `.truncated` and returns partial data with flag. All other errors propagate.
    ///
    /// - Parameter read: Closure that returns up to N bytes, or nil/empty at EOF.
    /// - Throws: `BvfError.invalidFormat` if header invalid or trailing data present.
    /// - Throws: `BvfError.authenticationFailed` on tampered ciphertext.
    public func decrypt(from read: (Int) throws -> Data?) throws -> (plaintext: Data, truncated: Bool) {
        var result = Data()
        do {
            try decrypt(
                from: read,
                to: { result.append($0) }
            )
            return (plaintext: result, truncated: false)
        } catch BvfError.truncated {
            return (plaintext: result, truncated: true)
        }
    }

    /// Stream-level decryption to a write closure. Handles chunking and truncation detection.
    ///
    /// - Parameters:
    ///   - read: Closure that returns up to N bytes, or nil/empty at EOF.
    ///   - write: Closure that receives decrypted plaintext chunks.
    /// - Throws: `BvfError.truncated` if TAG_FINAL not received.
    /// - Throws: `BvfError.invalidFormat` if header invalid or trailing data present.
    /// - Throws: `BvfError.authenticationFailed` on tampered ciphertext.
    public func decrypt(
        from read: (Int) throws -> Data?,
        to write: (Data) throws -> Void
    ) throws {
        guard let headerData = try readExact(BvfConfig.headerSize, from: read) else {
            throw BvfError.invalidFormat
        }

        guard headerData.count == BvfConfig.headerSize else {
            throw BvfError.invalidFormat
        }

        let state = try start(header: headerData)
        let ctChunkSize = BvfConfig.ciphertextChunkSize

        while true {
            guard let chunk = try readExact(ctChunkSize, from: read) else {
                break
            }

            if chunk.isEmpty {
                break
            }

            if let plaintext = try state.decryptChunk(chunk) {
                try write(plaintext)
            }

            if state.finalized {
                if let trailing = try read(1), !trailing.isEmpty {
                    throw BvfError.invalidFormat
                }
                return
            }
        }

        throw BvfError.truncated
    }
}
