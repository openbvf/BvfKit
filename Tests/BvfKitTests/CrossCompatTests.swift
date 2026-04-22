import Testing
import Foundation
@testable import BvfKit

// MARK: - Process helper

@discardableResult
func runBvf(_ args: [String], stdin: Data? = nil, env: [String: String] = [:]) throws -> (stdout: Data, stderr: String, exitCode: Int32) {
    let bvfPath: String
    if FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/bvf") {
        bvfPath = "/opt/homebrew/bin/bvf"
    } else if FileManager.default.isExecutableFile(atPath: "/usr/local/bin/bvf") {
        bvfPath = "/usr/local/bin/bvf"
    } else {
        let whichProcess = Process()
        whichProcess.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        whichProcess.arguments = ["bvf"]
        let whichOut = Pipe()
        whichProcess.standardOutput = whichOut
        whichProcess.standardError = Pipe()
        try whichProcess.run()
        whichProcess.waitUntilExit()
        let found = String(data: whichOut.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !found.isEmpty && FileManager.default.isExecutableFile(atPath: found) else {
            throw BvfNotFoundError()
        }
        bvfPath = found
    }

    let process = Process()
    process.executableURL = URL(fileURLWithPath: bvfPath)
    process.arguments = args

    var environment = ProcessInfo.processInfo.environment
    for (key, value) in env {
        environment[key] = value
    }
    process.environment = environment

    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    process.standardOutput = stdoutPipe
    process.standardError = stderrPipe

    if let stdinData = stdin {
        let stdinPipe = Pipe()
        process.standardInput = stdinPipe
        stdinPipe.fileHandleForWriting.write(stdinData)
        stdinPipe.fileHandleForWriting.closeFile()
    }

    try process.run()

    // Read pipes before waitUntilExit to avoid deadlock when output exceeds pipe buffer
    let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
    let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

    process.waitUntilExit()

    let stderrString = String(data: stderrData, encoding: .utf8) ?? ""
    let exitCode = process.terminationStatus

    return (stdout: stdoutData, stderr: stderrString, exitCode: exitCode)
}

struct BvfNotFoundError: Error {}

// MARK: - Suite

final class CrossCompatTests {

    let tmpDir: URL
    let publicKeyPath: URL
    let privateKeyPath: URL
    let encryptedPrivateKey: Data
    let publicKey: String

    init() throws {
        let fm = FileManager.default

        let tmp = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: tmp, withIntermediateDirectories: true)
        self.tmpDir = tmp
        self.publicKeyPath = tmp.appendingPathComponent("public.key")
        self.privateKeyPath = tmp.appendingPathComponent("private.key.enc")

        let result = try runBvf(
            ["keygen", "--output", tmp.path],
            env: ["BVF_PASSPHRASE": "hi"]
        )
        guard result.exitCode == 0 else {
            throw BvfError.invalidFormat
        }

        self.encryptedPrivateKey = try Data(contentsOf: privateKeyPath)
        self.publicKey = try String(contentsOf: publicKeyPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    deinit {
        try? FileManager.default.removeItem(at: tmpDir)
    }

    // MARK: - Swift encrypts → Rust decrypts

    @Test func testSwiftToRust() throws {
        let plaintext = Data(repeating: 0x42, count: 2 * BvfConfig.plaintextChunkSize + 1000)

        let encrypter = try Encrypter(recipientPublicKey: publicKey)
        var ciphertext = Data()
        try encrypter.encrypt(plaintext) { ciphertext.append($0) }

        let ciphertextFile = tmpDir.appendingPathComponent("swift_to_rust.bvf")
        try ciphertext.write(to: ciphertextFile)

        let result = try runBvf(
            ["decrypt", ciphertextFile.path, "-o", "-"],
            env: ["BVF_KEY_DIR": tmpDir.path, "BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode == 0, "bvf decrypt should succeed")
        #expect(result.stdout == plaintext, "Decrypted output should match original plaintext")
    }

    @Test func testSwiftToRustEmpty() throws {
        let plaintext = Data()

        let encrypter = try Encrypter(recipientPublicKey: publicKey)
        var ciphertext = Data()
        try encrypter.encrypt(plaintext) { ciphertext.append($0) }

        let ciphertextFile = tmpDir.appendingPathComponent("swift_to_rust_empty.bvf")
        try ciphertext.write(to: ciphertextFile)

        let result = try runBvf(
            ["decrypt", ciphertextFile.path, "-o", "-"],
            env: ["BVF_KEY_DIR": tmpDir.path, "BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode == 0, "bvf decrypt of empty plaintext should succeed")
        #expect(result.stdout == plaintext, "Decrypted output should be empty")
    }

    // MARK: - Rust encrypts → Swift decrypts

    @Test func testRustToSwift() throws {
        let plaintext = Data(repeating: 0xAB, count: 2 * BvfConfig.plaintextChunkSize + 1000)

        let plaintextFile = tmpDir.appendingPathComponent("rust_plaintext.bin")
        let ciphertextFile = tmpDir.appendingPathComponent("rust_to_swift.bvf")
        try plaintext.write(to: plaintextFile)

        let result = try runBvf(
            ["encrypt", plaintextFile.path, "-o", ciphertextFile.path, "-k", publicKeyPath.path],
            env: ["BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode == 0, "bvf encrypt should succeed")

        let ciphertext = try Data(contentsOf: ciphertextFile)
        let decrypter = try Decrypter(encryptedPrivateKey: encryptedPrivateKey, passphrase: "hi")

        var offset = 0
        let (decrypted, truncated) = try decrypter.decrypt { size in
            guard offset < ciphertext.count else { return nil }
            let end = min(offset + size, ciphertext.count)
            let chunk = ciphertext[offset..<end]
            offset = end
            return Data(chunk)
        }

        #expect(!truncated, "Ciphertext should not be truncated")
        #expect(decrypted == plaintext, "Decrypted data should match original plaintext")
    }

    @Test func testRustToSwiftEmpty() throws {
        let plaintext = Data()

        let plaintextFile = tmpDir.appendingPathComponent("rust_plaintext_empty.bin")
        let ciphertextFile = tmpDir.appendingPathComponent("rust_to_swift_empty.bvf")
        try plaintext.write(to: plaintextFile)

        let result = try runBvf(
            ["encrypt", plaintextFile.path, "-o", ciphertextFile.path, "-k", publicKeyPath.path],
            env: ["BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode == 0, "bvf encrypt of empty plaintext should succeed")

        let ciphertext = try Data(contentsOf: ciphertextFile)
        let decrypter = try Decrypter(encryptedPrivateKey: encryptedPrivateKey, passphrase: "hi")

        var offset = 0
        let (decrypted, truncated) = try decrypter.decrypt { size in
            guard offset < ciphertext.count else { return nil }
            let end = min(offset + size, ciphertext.count)
            let chunk = ciphertext[offset..<end]
            offset = end
            return Data(chunk)
        }

        #expect(!truncated, "Ciphertext should not be truncated")
        #expect(decrypted == plaintext, "Decrypted empty data should be empty")
    }

    // MARK: - Swift encrypts (closure API) → Rust decrypts

    @Test func testSwiftToRustClosure() throws {
        let plaintext = Data(repeating: 0x42, count: 2 * BvfConfig.plaintextChunkSize + 1000)

        let encrypter = try Encrypter(recipientPublicKey: publicKey)
        var ciphertext = Data()
        var offset = 0
        try encrypter.encrypt(
            from: { size in
                guard offset < plaintext.count else { return nil }
                let end = min(offset + size, plaintext.count)
                let chunk = plaintext[offset..<end]
                offset = end
                return Data(chunk)
            },
            to: { ciphertext.append($0) }
        )

        let ciphertextFile = tmpDir.appendingPathComponent("swift_closure_to_rust.bvf")
        try ciphertext.write(to: ciphertextFile)

        let result = try runBvf(
            ["decrypt", ciphertextFile.path, "-o", "-"],
            env: ["BVF_KEY_DIR": tmpDir.path, "BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode == 0, "bvf decrypt should succeed")
        #expect(result.stdout == plaintext, "Decrypted output should match original plaintext")
    }

    @Test func testSwiftToRustClosureEmpty() throws {
        let plaintext = Data()

        let encrypter = try Encrypter(recipientPublicKey: publicKey)
        var ciphertext = Data()
        try encrypter.encrypt(
            from: { _ in nil },
            to: { ciphertext.append($0) }
        )

        let ciphertextFile = tmpDir.appendingPathComponent("swift_closure_to_rust_empty.bvf")
        try ciphertext.write(to: ciphertextFile)

        let result = try runBvf(
            ["decrypt", ciphertextFile.path, "-o", "-"],
            env: ["BVF_KEY_DIR": tmpDir.path, "BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode == 0, "bvf decrypt of empty plaintext should succeed")
        #expect(result.stdout == plaintext, "Decrypted output should be empty")
    }

    // MARK: - Rust encrypts → Swift decrypts (closure API)

    @Test func testRustToSwiftClosure() throws {
        let plaintext = Data(repeating: 0xAB, count: 2 * BvfConfig.plaintextChunkSize + 1000)

        let plaintextFile = tmpDir.appendingPathComponent("rust_plaintext_closure.bin")
        let ciphertextFile = tmpDir.appendingPathComponent("rust_to_swift_closure.bvf")
        try plaintext.write(to: plaintextFile)

        let result = try runBvf(
            ["encrypt", plaintextFile.path, "-o", ciphertextFile.path, "-k", publicKeyPath.path],
            env: ["BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode == 0, "bvf encrypt should succeed")

        let ciphertext = try Data(contentsOf: ciphertextFile)
        let decrypter = try Decrypter(encryptedPrivateKey: encryptedPrivateKey, passphrase: "hi")

        var readOffset = 0
        var decrypted = Data()
        try decrypter.decrypt(
            from: { size in
                guard readOffset < ciphertext.count else { return nil }
                let end = min(readOffset + size, ciphertext.count)
                let chunk = ciphertext[readOffset..<end]
                readOffset = end
                return Data(chunk)
            },
            to: { decrypted.append($0) }
        )

        #expect(decrypted == plaintext, "Decrypted data should match original plaintext")
    }

    @Test func testRustToSwiftClosureEmpty() throws {
        let plaintext = Data()

        let plaintextFile = tmpDir.appendingPathComponent("rust_plaintext_closure_empty.bin")
        let ciphertextFile = tmpDir.appendingPathComponent("rust_to_swift_closure_empty.bvf")
        try plaintext.write(to: plaintextFile)

        let result = try runBvf(
            ["encrypt", plaintextFile.path, "-o", ciphertextFile.path, "-k", publicKeyPath.path],
            env: ["BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode == 0, "bvf encrypt of empty plaintext should succeed")

        let ciphertext = try Data(contentsOf: ciphertextFile)
        let decrypter = try Decrypter(encryptedPrivateKey: encryptedPrivateKey, passphrase: "hi")

        var readOffset = 0
        var decrypted = Data()
        try decrypter.decrypt(
            from: { size in
                guard readOffset < ciphertext.count else { return nil }
                let end = min(readOffset + size, ciphertext.count)
                let chunk = ciphertext[readOffset..<end]
                readOffset = end
                return Data(chunk)
            },
            to: { decrypted.append($0) }
        )

        #expect(decrypted == plaintext, "Decrypted empty data should be empty")
    }

    // MARK: - Key format interop

    @Test func testRustKeypairSwiftDecrypt() throws {
        // Keys in tmpDir were generated by Rust keygen. Encrypt with Swift using the
        // Rust-generated public key, then decrypt with Swift using the Rust-generated
        // private key — and also verify Rust can decrypt what Rust encrypted.
        let plaintext = Data(repeating: 0xCD, count: 2 * BvfConfig.plaintextChunkSize + 1000)

        // Swift encrypts with Rust public key
        let encrypter = try Encrypter(recipientPublicKey: publicKey)
        var ciphertext = Data()
        try encrypter.encrypt(plaintext) { ciphertext.append($0) }

        // Swift decrypts with Rust private key
        let decrypter = try Decrypter(encryptedPrivateKey: encryptedPrivateKey, passphrase: "hi")
        var offset = 0
        let (decrypted, truncated) = try decrypter.decrypt { size in
            guard offset < ciphertext.count else { return nil }
            let end = min(offset + size, ciphertext.count)
            let chunk = ciphertext[offset..<end]
            offset = end
            return Data(chunk)
        }

        #expect(!truncated)
        #expect(decrypted == plaintext, "Swift should decrypt with Rust-generated key")

        // Rust encrypts, Rust decrypts (validates key dir round-trip)
        let plaintextFile = tmpDir.appendingPathComponent("rust_keypair_plaintext.bin")
        let ciphertextFile = tmpDir.appendingPathComponent("rust_keypair_cipher.bvf")
        try plaintext.write(to: plaintextFile)

        let encResult = try runBvf(
            ["encrypt", plaintextFile.path, "-o", ciphertextFile.path, "-k", publicKeyPath.path],
            env: ["BVF_PASSPHRASE": "hi"]
        )
        #expect(encResult.exitCode == 0)

        let decResult = try runBvf(
            ["decrypt", ciphertextFile.path, "-o", "-"],
            env: ["BVF_KEY_DIR": tmpDir.path, "BVF_PASSPHRASE": "hi"]
        )
        #expect(decResult.exitCode == 0)
        #expect(decResult.stdout == plaintext)
    }

    // MARK: - Error cases

    @Test func testSwiftCorruptedRustRejects() throws {
        let plaintext = Data(repeating: 0x55, count: 2 * BvfConfig.plaintextChunkSize + 1000)

        let encrypter = try Encrypter(recipientPublicKey: publicKey)
        var ciphertext = Data()
        try encrypter.encrypt(plaintext) { ciphertext.append($0) }

        // Corrupt a byte in the middle of the ciphertext body
        let corruptOffset = BvfConfig.headerSize + 100
        ciphertext[corruptOffset] ^= 0xFF

        let corruptedFile = tmpDir.appendingPathComponent("corrupted.bvf")
        try ciphertext.write(to: corruptedFile)

        let result = try runBvf(
            ["decrypt", corruptedFile.path, "-o", "-"],
            env: ["BVF_KEY_DIR": tmpDir.path, "BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode != 0, "bvf decrypt should fail on corrupted ciphertext")
    }

    @Test func testTrailingBytesRustRejects() throws {
        let plaintext = Data(repeating: 0x77, count: 2 * BvfConfig.plaintextChunkSize + 1000)

        let encrypter = try Encrypter(recipientPublicKey: publicKey)
        var ciphertext = Data()
        try encrypter.encrypt(plaintext) { ciphertext.append($0) }

        ciphertext.append(Data([0x00, 0x01, 0x02, 0x03]))

        let trailingFile = tmpDir.appendingPathComponent("trailing.bvf")
        try ciphertext.write(to: trailingFile)

        let result = try runBvf(
            ["decrypt", trailingFile.path, "-o", "-"],
            env: ["BVF_KEY_DIR": tmpDir.path, "BVF_PASSPHRASE": "hi"]
        )
        #expect(result.exitCode != 0, "bvf decrypt should fail on ciphertext with trailing bytes")
    }
}
