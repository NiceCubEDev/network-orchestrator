import Foundation
import NativeCore

struct CoreError: LocalizedError, Sendable {
  let message: String
  var errorDescription: String? { message }
}
private struct CoreRequest: Encodable {
  let root: String
  let method: String
  let args: [String: String]
}
private struct CoreResponse<T: Decodable>: Decodable {
  let ok: Bool
  let data: T?
  let error: String?
}

// Actor serializes requests and keeps all blocking Rust work off the UI actor.
actor CoreBridge {
  let root: URL
  init(root: URL) { self.root = root }
  func call<T: Decodable & Sendable>(_ method: String, args: [String: String] = [:]) throws -> T {
    try Self.perform(root: root, method, args: args)
  }
  /// Runs off the actor so several slow calls (delay probes) proceed in
  /// parallel; only for bridge methods that do not take the store lock.
  nonisolated func callConcurrently<T: Decodable & Sendable>(
    _ method: String, args: [String: String] = [:]
  ) async throws -> T {
    let root = root
    return try await Task.detached { try Self.perform(root: root, method, args: args) }.value
  }
  private static func perform<T: Decodable>(root: URL, _ method: String, args: [String: String])
    throws -> T
  {
    let request = try JSONEncoder().encode(CoreRequest(root: root.path, method: method, args: args))
    let pointer = request.withUnsafeBytes { bytes in
      netorch_call(bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    }
    guard let pointer else { throw CoreError(message: "The native core could not respond") }
    defer { netorch_free(pointer) }
    let response = try JSONDecoder().decode(
      CoreResponse<T>.self, from: Data(String(cString: pointer).utf8))
    guard response.ok, let result = response.data else {
      throw CoreError(message: response.error ?? "The operation could not be completed")
    }
    return result
  }
}
