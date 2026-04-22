import Foundation

/// Unified error type for all BvfKit operations.
public enum BvfError: Error, Equatable {
    /// HPKE setup, secretstream init/push, secretbox, random generation, or JSON serialization failed.
    case encryptionFailed
    /// Argon2id key derivation, secretstream init/pull, or state misuse (e.g. decrypt after TAG_FINAL).
    case decryptionFailed
    /// Secretstream authentication tag verification failed (tampered or corrupted ciphertext).
    case authenticationFailed
    /// Secretbox decryption of private key failed (wrong passphrase).
    case wrongPassphrase
    /// Header too short, version mismatch, or trailing data after TAG_FINAL.
    case invalidFormat
    /// Invalid encrypted private key format (bad JSON, missing fields, bad base64, or ct too short).
    case invalidPrivateKeyFormat
    /// Stream ended without TAG_FINAL (truncated file).
    case truncated
    /// Public or private key has wrong length or failed to construct.
    case invalidKey
    /// sodium_mlock failed (system memory locking unavailable).
    case memoryLockFailed
    /// Nil pointer in C interop (should never happen).
    case internalError
    /// libsodium sodium_init() failed.
    case sodiumInitializationFailed
    /// Invalid public key format string (missing prefix, bad base64, wrong length, or checksum mismatch).
    case invalidPublicKeyFormat
}

extension BvfError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .encryptionFailed:
            return "Encryption failed"
        case .decryptionFailed:
            return "Decryption failed"
        case .authenticationFailed:
            return "Authentication failed"
        case .wrongPassphrase:
            return "Incorrect passphrase"
        case .invalidFormat:
            return "Invalid file format"
        case .truncated:
            return "Stream truncated - TAG_FINAL not received"
        case .invalidKey:
            return "Invalid key"
        case .memoryLockFailed:
            return "Failed to lock memory - system memory locking unavailable"
        case .internalError:
            return "Internal error"
        case .sodiumInitializationFailed:
            return "Failed to initialize cryptographic library"
        case .invalidPublicKeyFormat:
            return "Invalid public key format"
        case .invalidPrivateKeyFormat:
            return "Invalid private key format"
        }
    }
}
