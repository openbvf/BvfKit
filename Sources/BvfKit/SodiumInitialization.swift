import Foundation
import Clibsodium

/// Module-level libsodium initialization, called once at module load time.
private let sodiumInitializationResult: Result<Void, BvfError> = {
    let result = sodium_init()
    if result < 0 {
        return .failure(.sodiumInitializationFailed)
    }
    return .success(())
}()

/// Ensure libsodium has been successfully initialized.
/// - Throws: BvfError.sodiumInitializationFailed if initialization failed
func ensureSodiumInitialized() throws {
    try sodiumInitializationResult.get()
}
