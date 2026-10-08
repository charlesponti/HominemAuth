import Foundation

/// Typed Keychain failures. Never surfaced as HTTP errors.
public enum KeychainError: Error, LocalizedError, Sendable {
    case writeFailed(status: Int)
    case readFailed(status: Int)
    case unexpectedData
    case interactionNotAllowed

    public var errorDescription: String? {
        switch self {
        case .writeFailed(let status):
            return "Keychain write failed (\(status))."
        case .readFailed(let status):
            return "Keychain read failed (\(status))."
        case .unexpectedData:
            return "Keychain returned unexpected data."
        case .interactionNotAllowed:
            return "Keychain unavailable in this context (device locked?)."
        }
    }
}
