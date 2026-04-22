import Foundation
import Clibsodium

/// Constants for bvf-v1 file format.
public enum BvfConfig {
    static let versionHeader = "bvf-v1\n"
    static let hpkeInfo = "bvf.hpke.x25519-sha256-exportonly"
    static let hpkeExportContext = "bvf-master"

    /// Fixed plaintext chunk size for cross-client interoperability.
    /// All non-final chunks MUST be exactly this size.
    public static let plaintextChunkSize = 64 * 1024

    /// Ciphertext chunk size: plaintext chunk + secretstream overhead.
    public static var ciphertextChunkSize: Int {
        plaintextChunkSize + Int(crypto_secretstream_xchacha20poly1305_abytes())
    }

    public static var headerSize: Int {
        versionHeader.count
            + Int(crypto_scalarmult_bytes())
            + Int(crypto_secretstream_xchacha20poly1305_headerbytes())
    }
}
