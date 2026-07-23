import Foundation
import Clibsodium

/// Namespace for reading and writing the encrypted private key format.
public enum PrivateKeyStore {

    /// Encrypts a raw private key for storage using Argon2id + XSalsa20-Poly1305 secretbox.
    /// Returns JSON Data: `{"salt": base64, "nonce": base64, "ct": base64}`.
    ///
    /// The private key is borrowed for the call and never copied into a Swift value.
    ///
    /// - Returns: JSON Data ready to write to a `.key.enc` file
    /// - Throws: `BvfError.encryptionFailed` if key derivation or encryption fails
    static func export(privateKey: UnsafeBufferPointer<UInt8>, passphrase: String) throws -> Data {
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
        var ciphertext = [UInt8](repeating: 0, count: privateKey.count + macSize)

        let encryptSuccess = try ciphertext.withUnsafeMutableBufferPointer { ctPtr in
            try nonce.withUnsafeBufferPointer { noncePtr in
                try key.withUnsafeBufferPointer { keyPtr in
                    try safeSecretboxEncrypt(ciphertext: ctPtr, plaintext: privateKey, nonce: noncePtr, key: keyPtr)
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

    /// Parses and validates an encrypted private key JSON blob.
    ///
    /// - Throws: `BvfError.invalidPrivateKeyFormat` on any parse or validation failure
    public static func validate(_ data: Data) throws -> (salt: Data, nonce: Data, ct: Data) {
        guard
            let obj = try? JSONSerialization.jsonObject(with: data),
            let dict = obj as? [String: Any],
            let saltB64 = dict["salt"] as? String,
            let nonceB64 = dict["nonce"] as? String,
            let ctB64 = dict["ct"] as? String,
            let saltData = Data(base64Encoded: saltB64),
            let nonceData = Data(base64Encoded: nonceB64),
            let ctData = Data(base64Encoded: ctB64)
        else {
            throw BvfError.invalidPrivateKeyFormat
        }

        guard saltData.count == Int(crypto_pwhash_saltbytes()) else {
            throw BvfError.invalidPrivateKeyFormat
        }

        guard nonceData.count == Int(crypto_secretbox_noncebytes()) else {
            throw BvfError.invalidPrivateKeyFormat
        }

        guard ctData.count > Int(crypto_secretbox_macbytes()) else {
            throw BvfError.invalidPrivateKeyFormat
        }

        return (salt: saltData, nonce: nonceData, ct: ctData)
    }
}
