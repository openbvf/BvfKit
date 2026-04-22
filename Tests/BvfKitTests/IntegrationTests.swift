import Testing
import Foundation
import Clibsodium
@testable import BvfKit

@Suite(.serialized)
struct IntegrationTests {

    // MARK: - Error cases

    @Test func testTruncatedCiphertext() throws {
        let fixture = TestKeyFixture.shared()
        let plaintext = Data(repeating: 0xAB, count: BvfConfig.plaintextChunkSize + 1024)

        let encrypter = try Encrypter(recipientPublicKey: fixture.publicKey)
        var ciphertext = Data()
        try encrypter.encrypt(plaintext) { ciphertext.append($0) }

        let keepCount = BvfConfig.headerSize + BvfConfig.ciphertextChunkSize
        let truncatedCiphertext = ciphertext.prefix(keepCount)

        var offset = 0
        let decrypter = try Decrypter(
            encryptedPrivateKey: fixture.encryptedPrivateKey,
            passphrase: fixture.passphrase
        )
        let (partialData, truncated) = try decrypter.decrypt { size in
            guard offset < truncatedCiphertext.count else { return nil }
            let end = min(offset + size, truncatedCiphertext.count)
            let chunk = truncatedCiphertext[offset..<end]
            offset = end
            return Data(chunk)
        }

        #expect(truncated, "truncated ciphertext should set truncated flag")
        #expect(!partialData.isEmpty, "partial data should be non-empty")
    }

    @Test func testWrongPassphrase() throws {
        let fixture = TestKeyFixture.shared()

        #expect(throws: BvfError.wrongPassphrase) {
            _ = try Decrypter(
                encryptedPrivateKey: fixture.encryptedPrivateKey,
                passphrase: "wrong"
            )
        }
    }

    @Test func testInvalidVersionHeader() throws {
        let fixture = TestKeyFixture.shared()
        let encrypter = try Encrypter(recipientPublicKey: fixture.publicKey)
        let (header, _) = try encrypter.start()

        var badHeader = header
        badHeader[1] = UInt8(ascii: "X")

        let decrypter = try Decrypter(
            encryptedPrivateKey: fixture.encryptedPrivateKey,
            passphrase: fixture.passphrase
        )

        #expect(throws: BvfError.invalidFormat) {
            _ = try decrypter.start(header: badHeader)
        }
    }

    // MARK: - Security properties

    @Test func testEncryptAfterFinalized() throws {
        let fixture = TestKeyFixture.shared()
        let encrypter = try Encrypter(recipientPublicKey: fixture.publicKey)
        let (_, state) = try encrypter.start()

        let chunk = Data("final".utf8)
        _ = try state.encryptChunk(chunk, isLast: true)
        #expect(state.finalized)

        #expect(throws: BvfError.self) {
            _ = try state.encryptChunk(chunk, isLast: false)
        }
    }

    @Test func testDecryptAfterFinalized() throws {
        let fixture = TestKeyFixture.shared()
        let plaintext = Data("test".utf8)
        let encrypter = try Encrypter(recipientPublicKey: fixture.publicKey)
        let ciphertext = try encryptComplete(plaintext: plaintext, encrypter: encrypter)

        let decrypter = try Decrypter(
            encryptedPrivateKey: fixture.encryptedPrivateKey,
            passphrase: fixture.passphrase
        )
        let headerBytes = ciphertext.prefix(BvfConfig.headerSize)
        let state = try decrypter.start(header: headerBytes)

        let ciphertextBody = ciphertext.dropFirst(BvfConfig.headerSize)
        _ = try state.decryptChunk(Data(ciphertextBody))

        #expect(state.finalized)

        #expect(throws: BvfError.self) {
            _ = try state.decryptChunk(Data(ciphertextBody))
        }
    }

    @Test func testEphemeralUniqueness() throws {
        let fixture = TestKeyFixture.shared()
        let plaintext = Data("deterministic".utf8)

        let encrypter = try Encrypter(recipientPublicKey: fixture.publicKey)

        var ciphertext1 = Data()
        try encrypter.encrypt(plaintext) { ciphertext1.append($0) }

        var ciphertext2 = Data()
        try encrypter.encrypt(plaintext) { ciphertext2.append($0) }

        #expect(ciphertext1 != ciphertext2, "two encryptions of the same plaintext should differ")
    }

    @Test func testMemoryZeroing() throws {
        let fixture = TestKeyFixture.shared()

        weak var weakDecrypter: Decrypter?

        try autoreleasepool {
            let decrypter = try Decrypter(encryptedPrivateKey: fixture.encryptedPrivateKey, passphrase: fixture.passphrase)
            weakDecrypter = decrypter

            #expect(weakDecrypter != nil, "Decrypter should be allocated")
        }

        #expect(weakDecrypter == nil, "Decrypter was not deallocated - keys may not be zeroed")
    }

}
