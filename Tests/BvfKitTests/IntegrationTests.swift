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

        let decrypter = try Decrypter(
            encryptedPrivateKey: fixture.encryptedPrivateKey,
            passphrase: fixture.passphrase
        )
        let (partialData, truncated) = try decryptComplete(ciphertext: Data(truncatedCiphertext), decrypter: decrypter)

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

    @Test func testRotatePassphraseRoundtrip() throws {
        let oldPassphrase = "old-passphrase"
        let newPassphrase = "new-passphrase"

        let keypair = try Keypair.generate()
        let originalBlob = try keypair.exportEncryptedPrivateKey(passphrase: oldPassphrase)

        // Re-seal under the new passphrase via the old-passphrase Decrypter.
        let oldDecrypter = try Decrypter(encryptedPrivateKey: originalBlob, passphrase: oldPassphrase)
        let rotatedBlob = try oldDecrypter.exportEncryptedPrivateKey(passphrase: newPassphrase)

        // Old passphrase no longer opens the rotated blob.
        #expect(throws: BvfError.wrongPassphrase) {
            _ = try Decrypter(encryptedPrivateKey: rotatedBlob, passphrase: oldPassphrase)
        }

        // New passphrase opens it and yields the same keypair.
        let newDecrypter = try Decrypter(encryptedPrivateKey: rotatedBlob, passphrase: newPassphrase)
        #expect(newDecrypter.publicKey == keypair.publicKey)

        // A file encrypted to the public key decrypts with the rotated key.
        let plaintext = Data("rotation survives".utf8)
        let encrypter = try Encrypter(recipientPublicKey: keypair.publicKey)
        let ciphertext = try encryptComplete(plaintext: plaintext, encrypter: encrypter)

        let (decrypted, truncated) = try decryptComplete(ciphertext: ciphertext, decrypter: newDecrypter)

        #expect(!truncated)
        #expect(decrypted == plaintext)
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
