import Foundation

/// Reads exactly `count` bytes by looping the `read` closure until full or EOF.
/// Returns nil only if the first read returns nil/empty (true EOF).
/// Returns partial data (< count) only at end of stream.
func readExact(_ count: Int, from read: (Int) throws -> Data?) throws -> Data? {
    guard let first = try read(count), !first.isEmpty else {
        return nil
    }
    if first.count >= count {
        return first
    }
    var buf = first
    while buf.count < count {
        guard let next = try read(count - buf.count), !next.isEmpty else {
            break
        }
        buf.append(next)
    }
    return buf
}
