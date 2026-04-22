import Foundation
import CryptoKit
import Clibsodium

/// Decrypts and holds private key for HPKE operations.
/// Private key stored in sodium_malloc'd memory (mlocked, zeroed on free).
/// Immutable after init; thread-safe for concurrent access.
final class KeyManager: @unchecked Sendable {
    private let rawKeyPtr: UnsafeMutableRawPointer
    let publicKey: String

    /// - Throws: `BvfError` for any initialization failure
    init(encryptedPrivateKey: Data, passphrase: String) throws {

        try ensureSodiumInitialized()

        let (saltData, nonceData, ctData) = try PrivateKeyFormat.validate(encryptedPrivateKey)

        let keyLen = Int(crypto_secretbox_keybytes())
        var key = [UInt8](repeating: 0, count: keyLen)

        var passphraseChars = try convertPassphraseToChars(passphrase)
        defer { sodium_memzero(&passphraseChars, passphraseChars.count) }

        let saltBytes = [UInt8](saltData)

        let argon2idSuccess = try key.withUnsafeMutableBufferPointer { keyPtr in
            try passphraseChars.withUnsafeBufferPointer { passphrasePtr in
                try saltBytes.withUnsafeBufferPointer { saltPtr in
                    try safeArgon2id(key: keyPtr, passphrase: passphrasePtr, salt: saltPtr)
                }
            }
        }

        guard argon2idSuccess else {
            throw BvfError.decryptionFailed
        }

        var privateKeyLocal = [UInt8](repeating: 0, count: ctData.count - Int(crypto_secretbox_macbytes()))

        let nonceBytes = [UInt8](nonceData)
        let ctBytes = [UInt8](ctData)

        let decryptSuccess = try privateKeyLocal.withUnsafeMutableBufferPointer { skPtr in
            try nonceBytes.withUnsafeBufferPointer { noncePtr in
                try ctBytes.withUnsafeBufferPointer { ctPtr in
                    try key.withUnsafeBufferPointer { keyPtr in
                        try safeSecretboxDecrypt(plaintext: skPtr, ciphertext: ctPtr, nonce: noncePtr, key: keyPtr)
                    }
                }
            }
        }

        guard decryptSuccess else {
            throw BvfError.wrongPassphrase
        }

        sodium_memzero(&key, key.count)

        guard privateKeyLocal.count == Int(crypto_scalarmult_bytes()) else {
            throw BvfError.invalidKey
        }

        guard let rawKeyPtr = sodium_malloc(Int(crypto_scalarmult_bytes())) else {
            sodium_memzero(&privateKeyLocal, privateKeyLocal.count)
            throw BvfError.invalidKey
        }
        privateKeyLocal.withUnsafeBytes {
            // baseAddress is guaranteed non-nil: count == crypto_scalarmult_bytes(), verified above
            rawKeyPtr.copyMemory(from: $0.baseAddress!, byteCount: Int(crypto_scalarmult_bytes()))
        }
        sodium_memzero(&privateKeyLocal, privateKeyLocal.count)

        // Derives via libsodium directly; no CryptoKit key constructed
        var publicKeyBytes = [UInt8](repeating: 0, count: Int(crypto_scalarmult_bytes()))
        guard crypto_scalarmult_base(&publicKeyBytes, rawKeyPtr.assumingMemoryBound(to: UInt8.self)) == 0 else {
            sodium_free(rawKeyPtr)
            throw BvfError.invalidKey
        }
        self.rawKeyPtr = rawKeyPtr
        self.publicKey = try PublicKeyFormat.encode(Data(publicKeyBytes))
    }

    /// Reconstruct a CryptoKit PrivateKey from mlocked storage, call body, then release.
    /// The key exists only for the duration of the closure.
    func withPrivateKey<R>(_ body: (Curve25519.KeyAgreement.PrivateKey) throws -> R) throws -> R {
        let key = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: UnsafeBufferPointer(
                start: rawKeyPtr.assumingMemoryBound(to: UInt8.self),
                count: Int(crypto_scalarmult_bytes())
            )
        )
        return try body(key)
    }

    deinit {
        sodium_free(rawKeyPtr)
    }
}
