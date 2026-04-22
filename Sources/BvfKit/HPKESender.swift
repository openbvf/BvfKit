import Foundation
import CryptoKit
import Clibsodium

/// Manages HPKE ephemeral key generation and master key derivation.
/// Immutable after init — thread-safe for concurrent access.
final class HPKESender: @unchecked Sendable {
    private let sender: HPKE.Sender

    /// HPKE encapsulated public key (ephemeral, written to file header)
    let encapsulatedKey: Data

    /// Create HPKE sender with ephemeral keypair for forward secrecy.
    /// - Throws: `BvfError.encryptionFailed` if HPKE sender creation fails
    init(recipientPublicKey: Curve25519.KeyAgreement.PublicKey) throws {
        let ciphersuite = HPKE.Ciphersuite(
            kem: .Curve25519_HKDF_SHA256,
            kdf: .HKDF_SHA256,
            aead: .exportOnly
        )

        do {
            self.sender = try HPKE.Sender(
                recipientKey: recipientPublicKey,
                ciphersuite: ciphersuite,
                info: Data(BvfConfig.hpkeInfo.utf8)
            )
            self.encapsulatedKey = sender.encapsulatedKey
        } catch {
            throw BvfError.encryptionFailed
        }
    }

    /// Derive master key via HPKE export for secretstream encryption.
    /// - Throws: `BvfError.encryptionFailed` if HPKE export fails
    func deriveMasterKey() throws -> SymmetricKey {
        do {
            let masterKey = try sender.exportSecret(
                context: Data(BvfConfig.hpkeExportContext.utf8),
                outputByteCount: Int(crypto_secretstream_xchacha20poly1305_keybytes())
            )
            return masterKey
        } catch {
            throw BvfError.encryptionFailed
        }
    }
}
