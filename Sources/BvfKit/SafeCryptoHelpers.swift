// SafeCryptoHelpers.swift
// Safe wrappers for libsodium C calls. All baseAddress access is guarded.
// against nil (undefined behavior when Data/Array is empty).
// One-offs done in-line instead.

import Foundation
import CryptoKit
import Clibsodium

/// Safe Argon2id wrapper with nil pointer validation.
func safeArgon2id(
    key: UnsafeMutableBufferPointer<UInt8>,
    passphrase: UnsafeBufferPointer<CChar>,
    salt: UnsafeBufferPointer<UInt8>
) throws -> Bool {
    guard let keyPtr = key.baseAddress else {
        throw BvfError.internalError
    }

    guard let passphrasePtr = passphrase.baseAddress else {
        throw BvfError.internalError
    }

    guard let saltPtr = salt.baseAddress else {
        throw BvfError.internalError
    }

    let result = crypto_pwhash(
        keyPtr,
        UInt64(key.count),
        passphrasePtr,
        UInt64(passphrase.count),
        saltPtr,
        UInt64(crypto_pwhash_opslimit_sensitive()),
        crypto_pwhash_memlimit_sensitive(),
        Int32(crypto_pwhash_ALG_ARGON2ID13)
    )

    if result != 0 {
        return false
    }

    return true
}

/// Safe secretbox encryption wrapper with nil pointer validation.
func safeSecretboxEncrypt(
    ciphertext: UnsafeMutableBufferPointer<UInt8>,
    plaintext: UnsafeBufferPointer<UInt8>,
    nonce: UnsafeBufferPointer<UInt8>,
    key: UnsafeBufferPointer<UInt8>
) throws -> Bool {
    guard let ctPtr = ciphertext.baseAddress else {
        throw BvfError.internalError
    }

    guard let ptPtr = plaintext.baseAddress else {
        throw BvfError.internalError
    }

    guard let noncePtr = nonce.baseAddress else {
        throw BvfError.internalError
    }

    guard let keyPtr = key.baseAddress else {
        throw BvfError.internalError
    }

    let result = crypto_secretbox_easy(
        ctPtr,
        ptPtr,
        UInt64(plaintext.count),
        noncePtr,
        keyPtr
    )

    if result != 0 {
        return false
    }

    return true
}

/// Safe secretbox decryption wrapper with nil pointer validation.
func safeSecretboxDecrypt(
    plaintext: UnsafeMutableBufferPointer<UInt8>,
    ciphertext: UnsafeBufferPointer<UInt8>,
    nonce: UnsafeBufferPointer<UInt8>,
    key: UnsafeBufferPointer<UInt8>
) throws -> Bool {
    guard let ptPtr = plaintext.baseAddress else {
        throw BvfError.internalError
    }

    guard let ctPtr = ciphertext.baseAddress else {
        throw BvfError.internalError
    }

    guard let noncePtr = nonce.baseAddress else {
        throw BvfError.internalError
    }

    guard let keyPtr = key.baseAddress else {
        throw BvfError.internalError
    }

    let result = crypto_secretbox_open_easy(
        ptPtr,
        ctPtr,
        UInt64(ciphertext.count),
        noncePtr,
        keyPtr
    )

    if result != 0 {
        return false
    }

    return true
}

/// Converts String passphrase to CChar array for libsodium compatibility.
func convertPassphraseToChars(_ passphrase: String) throws -> [CChar] {
    let utf8Data = Data(passphrase.utf8)
    if utf8Data.isEmpty { return [] }
    return try utf8Data.withUnsafeBytes { passphraseBytes -> [CChar] in
        guard let baseAddress = passphraseBytes.baseAddress else {
            throw BvfError.internalError
        }
        return baseAddress.assumingMemoryBound(to: UInt8.self)
            .withMemoryRebound(to: CChar.self, capacity: passphraseBytes.count) { ptr in
                Array(UnsafeBufferPointer(start: ptr, count: passphraseBytes.count))
            }
    }
}

/// Extract SymmetricKey bytes into byte array for libsodium operations.
/// Caller MUST zero the returned array with sodium_memzero after use.
func extractSymmetricKeyBytes(_ key: SymmetricKey) throws -> [UInt8] {
    var keyBytes = [UInt8](repeating: 0, count: Int(crypto_secretstream_xchacha20poly1305_keybytes()))

    guard key.bitCount / 8 == Int(crypto_secretstream_xchacha20poly1305_keybytes()) else {
        throw BvfError.invalidKey
    }

    key.withUnsafeBytes { keyPtr in
        keyBytes.withUnsafeMutableBytes { destPtr in
            destPtr.copyBytes(from: keyPtr)
        }
    }
    return keyBytes
}
