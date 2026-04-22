import Foundation
@testable import BvfKit

func createTestPassphrase() -> String {
    return "hi"
}

struct TestKeyFixture {
    let encryptedPrivateKey: Data
    let publicKey: String
    let passphrase: String

    private static let _shared: TestKeyFixture = {
        let passphrase = createTestPassphrase()
        let keypair = try! Keypair.generate()
        let encryptedPrivateKey = try! keypair.exportEncryptedPrivateKey(passphrase: passphrase)
        return TestKeyFixture(
            encryptedPrivateKey: encryptedPrivateKey,
            publicKey: keypair.publicKey,
            passphrase: passphrase
        )
    }()

    static func shared() -> TestKeyFixture { _shared }
}

func encryptComplete(plaintext: Data, encrypter: Encrypter) throws -> Data {
    var result = Data()
    var offset = 0

    try encrypter.encrypt(
        from: { size in
            guard offset < plaintext.count else { return nil }
            let end = min(offset + size, plaintext.count)
            let chunk = plaintext[offset..<end]
            offset = end
            return Data(chunk)
        },
        to: { data in
            result.append(data)
        }
    )

    return result
}
