import Foundation

/// Errors surfaced by the Hominem auth client.
public enum HominemAuthError: Error, LocalizedError, Sendable {
    case invalidURL
    case notAuthenticated
    case missingSessionToken
    case invalidOTP(message: String?)
    case rateLimited(retryAfter: TimeInterval?)
    case server(status: Int, message: String?)
    case network(underlying: String)
    case keychain(KeychainError)
    /// Backwards compat for `badResponse(status:message:)`.
    case badResponse(status: Int, message: String?)

    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "The API URL is invalid."
        case .notAuthenticated:
            return "You are not signed in."
        case .missingSessionToken:
            return "The server did not return a session token."
        case .invalidOTP(let message):
            return message ?? "That code didn't work. Check it and try again."
        case .rateLimited(let retryAfter):
            if let retryAfter, retryAfter > 0 {
                return "Too many attempts. Try again in \(Int(retryAfter))s."
            }
            return "Too many attempts. Try again shortly."
        case .server(let status, let message):
            return message ?? "The server responded with status \(status)."
        case .network(let underlying):
            return "Network error: \(underlying)"
        case .keychain(let error):
            return error.localizedDescription
        case .badResponse(let status, let message):
            return message ?? "The server responded with status \(status)."
        }
    }
}
