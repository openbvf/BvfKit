import Foundation
import CryptoKit
import Clibsodium

/// Memory-locked X25519 keypair with automatic cleanup.
/// Private key is locked with sodium_mlock and zeroed+unlocked in deinit.
public final class Keypair: @unchecked Sendable {
    /// Public key in `bvf-pub:` format string
    public let publicKey: String

    private var privateKeyBytes: [UInt8]
    private var isLocked: Bool = false
    private var isDeallocated: Bool = false

    /// Generate a new X25519 keypair with memory-locked private key.
    /// - Throws: BvfError if generation or memory locking fails
    public static func generate() throws -> Keypair {
        try ensureSodiumInitialized()

        var publicKey = [UInt8](repeating: 0, count: Int(crypto_scalarmult_bytes()))
        var privateKey = [UInt8](repeating: 0, count: Int(crypto_scalarmult_bytes()))

        guard crypto_box_keypair(&publicKey, &privateKey) == 0 else {
            sodium_memzero(&privateKey, privateKey.count)
            throw BvfError.invalidKey
        }

        return try Keypair(publicKeyBytes: publicKey, privateKeyBytes: privateKey)
    }

    private init(publicKeyBytes: [UInt8], privateKeyBytes: [UInt8]) throws {
        self.publicKey = try PublicKeyFormat.encode(Data(publicKeyBytes))
        self.privateKeyBytes = privateKeyBytes

        let lockResult = self.privateKeyBytes.withUnsafeMutableBytes { ptr in
            guard let baseAddress = ptr.baseAddress else { return Int32(-1) }
            return sodium_mlock(baseAddress, ptr.count)
        }
        if lockResult != 0 {
            sodium_memzero(&self.privateKeyBytes, self.privateKeyBytes.count)
            throw BvfError.memoryLockFailed
        }
        self.isLocked = true
    }

    /// Encrypt private key for storage using Argon2id + XSalsa20-Poly1305 secretbox.
    /// Returns JSON Data: `{"salt": base64, "nonce": base64, "ct": base64}`
    ///
    /// - Returns: JSON Data ready to write to .key.enc file
    /// - Throws: BvfError if encryption fails
    public func exportEncryptedPrivateKey(passphrase: String) throws -> Data {
        guard !isDeallocated else {
            throw BvfError.invalidKey
        }

        return try privateKeyBytes.withUnsafeBufferPointer { pkPtr in
            try PrivateKeyStore.export(privateKey: pkPtr, passphrase: passphrase)
        }
    }

    deinit {
        isDeallocated = true
        if isLocked {
            privateKeyBytes.withUnsafeMutableBytes { ptr in
                guard let baseAddress = ptr.baseAddress else { return }
                sodium_munlock(baseAddress, ptr.count)  // zeros AND unlocks
            }
        } else {
            sodium_memzero(&privateKeyBytes, privateKeyBytes.count)
        }
    }
}
