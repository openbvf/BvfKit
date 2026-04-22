import Foundation
import Clibsodium

/// Namespace for encrypted private key format validation.
public enum PrivateKeyFormat {

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
