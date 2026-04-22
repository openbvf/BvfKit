import Foundation
import CryptoKit
import Clibsodium

private let publicKeyPrefix = "bvf-pub:"
private let expectedTotalLength = 61
private let base64KeyLength = 44
private let base64ChecksumLength = 8
private let checksumByteCount = 4

/// Namespace for bvf-pub: public key format encoding/decoding.
enum PublicKeyFormat {

    /// Encodes a raw public key into the `bvf-pub:` format string.
    ///
    /// - Throws: `BvfError.invalidPublicKeyFormat` if rawKey is not correct len for X25519
    static func encode(_ rawKey: Data) throws -> String {
        guard rawKey.count == Int(crypto_scalarmult_bytes()) else {
            throw BvfError.invalidPublicKeyFormat
        }

        let base64Key = rawKey.base64EncodedString()

        let hash = SHA256.hash(data: rawKey)
        let checksumBytes = Data(hash.prefix(checksumByteCount))
        let base64Checksum = checksumBytes.base64EncodedString()

        return "\(publicKeyPrefix)\(base64Key).\(base64Checksum)"
    }

    /// Decodes a `bvf-pub:` format string into raw  public key Data.
    ///
    /// - Throws: `BvfError.invalidPublicKeyFormat` on any validation failure
    static func decode(_ formatted: String) throws -> Data {
        guard formatted.hasPrefix(publicKeyPrefix) else {
            throw BvfError.invalidPublicKeyFormat
        }

        let remainder = String(formatted.dropFirst(publicKeyPrefix.count))

        let parts = remainder.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2 else {
            throw BvfError.invalidPublicKeyFormat
        }

        let keyPart = String(parts[0])
        let checksumPart = String(parts[1])

        guard let rawKey = Data(base64Encoded: keyPart) else {
            throw BvfError.invalidPublicKeyFormat
        }

        guard rawKey.count == Int(crypto_scalarmult_bytes()) else {
            throw BvfError.invalidPublicKeyFormat
        }

        guard let storedChecksum = Data(base64Encoded: checksumPart) else {
            throw BvfError.invalidPublicKeyFormat
        }

        guard storedChecksum.count == checksumByteCount else {
            throw BvfError.invalidPublicKeyFormat
        }

        let hash = SHA256.hash(data: rawKey)
        let computedChecksum = Data(hash.prefix(checksumByteCount))

        guard computedChecksum == storedChecksum else {
            throw BvfError.invalidPublicKeyFormat
        }

        return rawKey
    }
}
