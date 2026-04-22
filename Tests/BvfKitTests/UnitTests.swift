import Testing
import Foundation
import Clibsodium
@testable import BvfKit

struct UnitTests {

    // MARK: - Public key format

    @Test func testEncodeDecodeRoundTrip() throws {
        let rawKey = Data((0..<32).map { UInt8($0) })
        let encoded = try PublicKeyFormat.encode(rawKey)
        #expect(encoded.hasPrefix("bvf-pub:"), "Encoded key should start with bvf-pub:")
        #expect(encoded.count == 61, "Encoded key should be exactly 61 characters")
        let decoded = try PublicKeyFormat.decode(encoded)
        #expect(decoded == rawKey, "Round-trip should preserve raw key bytes")
    }

    @Test func testDecodePublicKeyBadChecksum() {
        let badChecksum = "bvf-pub:5Us1XxImIAbWtzF90+f6jt1SoHNkP21QgXQq/DTXLGU=.AAAAAAAA"
        #expect(throws: BvfError.invalidPublicKeyFormat) {
            _ = try PublicKeyFormat.decode(badChecksum)
        }
    }

    // MARK: - Private key format

    @Test func testValidJSONReturnsComponents() throws {
        let salt = Data(repeating: 0xAA, count: 16)
        let nonce = Data(repeating: 0xBB, count: 24)
        let ct = Data(repeating: 0xCC, count: 48)

        let json: [String: String] = [
            "salt": salt.base64EncodedString(),
            "nonce": nonce.base64EncodedString(),
            "ct": ct.base64EncodedString()
        ]
        let data = try JSONSerialization.data(withJSONObject: json)

        let (saltOut, nonceOut, ctOut) = try PrivateKeyFormat.validate(data)

        #expect(saltOut == salt)
        #expect(nonceOut == nonce)
        #expect(ctOut == ct)
    }

    @Test func testNotJSONThrowsInvalidFormat() {
        let data = "not valid json".data(using: .utf8)!

        #expect(throws: BvfError.invalidPrivateKeyFormat) {
            _ = try PrivateKeyFormat.validate(data)
        }
    }

    @Test func testBadSaltLength() throws {
        let salt = Data(repeating: 0xAA, count: Int(crypto_pwhash_saltbytes()) - 1)
        let nonce = Data(repeating: 0xBB, count: Int(crypto_secretbox_noncebytes()))
        let ct = Data(repeating: 0xCC, count: Int(crypto_secretbox_macbytes()) + 32)

        let json: [String: String] = [
            "salt": salt.base64EncodedString(),
            "nonce": nonce.base64EncodedString(),
            "ct": ct.base64EncodedString()
        ]
        let data = try JSONSerialization.data(withJSONObject: json)

        #expect(throws: BvfError.invalidPrivateKeyFormat) {
            _ = try PrivateKeyFormat.validate(data)
        }
    }

    @Test func testBadNonceLength() throws {
        let salt = Data(repeating: 0xAA, count: Int(crypto_pwhash_saltbytes()))
        let nonce = Data(repeating: 0xBB, count: Int(crypto_secretbox_noncebytes()) - 1)
        let ct = Data(repeating: 0xCC, count: Int(crypto_secretbox_macbytes()) + 32)

        let json: [String: String] = [
            "salt": salt.base64EncodedString(),
            "nonce": nonce.base64EncodedString(),
            "ct": ct.base64EncodedString()
        ]
        let data = try JSONSerialization.data(withJSONObject: json)

        #expect(throws: BvfError.invalidPrivateKeyFormat) {
            _ = try PrivateKeyFormat.validate(data)
        }
    }

    @Test func testBadCtLength() throws {
        let salt = Data(repeating: 0xAA, count: Int(crypto_pwhash_saltbytes()))
        let nonce = Data(repeating: 0xBB, count: Int(crypto_secretbox_noncebytes()))
        let ct = Data(repeating: 0xCC, count: Int(crypto_secretbox_macbytes()))

        let json: [String: String] = [
            "salt": salt.base64EncodedString(),
            "nonce": nonce.base64EncodedString(),
            "ct": ct.base64EncodedString()
        ]
        let data = try JSONSerialization.data(withJSONObject: json)

        #expect(throws: BvfError.invalidPrivateKeyFormat) {
            _ = try PrivateKeyFormat.validate(data)
        }
    }
}
