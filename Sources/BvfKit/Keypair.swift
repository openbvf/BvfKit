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

        let saltSize = Int(crypto_pwhash_SALTBYTES)
        var salt = [UInt8](repeating: 0, count: saltSize)
        guard SecRandomCopyBytes(kSecRandomDefault, saltSize, &salt) == errSecSuccess else {
            throw BvfError.encryptionFailed
        }

        let keyLen = Int(crypto_secretbox_keybytes())
        var key = [UInt8](repeating: 0, count: keyLen)

        var passphraseChars = try convertPassphraseToChars(passphrase)
        defer { sodium_memzero(&passphraseChars, passphraseChars.count) }

        let pwhashSuccess = try key.withUnsafeMutableBufferPointer { keyPtr in
            try passphraseChars.withUnsafeBufferPointer { passphrasePtr in
                try salt.withUnsafeBufferPointer { saltPtr in
                    try safeArgon2id(key: keyPtr, passphrase: passphrasePtr, salt: saltPtr)
                }
            }
        }

        guard pwhashSuccess else {
            sodium_memzero(&key, key.count)
            throw BvfError.encryptionFailed
        }

        defer { sodium_memzero(&key, key.count) }

        let nonceSize = Int(crypto_secretbox_NONCEBYTES)
        var nonce = [UInt8](repeating: 0, count: nonceSize)
        guard SecRandomCopyBytes(kSecRandomDefault, nonceSize, &nonce) == errSecSuccess else {
            throw BvfError.encryptionFailed
        }

        let macSize = Int(crypto_secretbox_MACBYTES)
        var ciphertext = [UInt8](repeating: 0, count: privateKeyBytes.count + macSize)

        let encryptSuccess = try ciphertext.withUnsafeMutableBufferPointer { ctPtr in
            try privateKeyBytes.withUnsafeBufferPointer { pkPtr in
                try nonce.withUnsafeBufferPointer { noncePtr in
                    try key.withUnsafeBufferPointer { keyPtr in
                        try safeSecretboxEncrypt(ciphertext: ctPtr, plaintext: pkPtr, nonce: noncePtr, key: keyPtr)
                    }
                }
            }
        }

        guard encryptSuccess else {
            throw BvfError.encryptionFailed
        }

        let jsonDict: [String: String] = [
            "salt": Data(salt).base64EncodedString(),
            "nonce": Data(nonce).base64EncodedString(),
            "ct": Data(ciphertext).base64EncodedString()
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: jsonDict, options: [.prettyPrinted, .sortedKeys]) else {
            throw BvfError.encryptionFailed
        }

        return jsonData
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
