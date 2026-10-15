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

/// The few things an app screen cares about, so every app words them the same way. Words are the
/// app's own; this is only the category.
public enum AuthProblem: Sendable, Equatable {
    /// The code is wrong or expired.
    case badCode
    /// Too many tries; wait.
    case tooManyAttempts
    /// No connection, or the server is down or overloaded (502, 503, 504). Calm, and worth retrying.
    case noService
    /// There is no session, or the server ended it. Sign in again.
    case signedOut
    /// Anything else.
    case other
}

extension HominemAuthError {
    /// The category of this error for a screen.
    public var problem: AuthProblem {
        switch self {
        case .invalidOTP: return .badCode
        case .rateLimited: return .tooManyAttempts
        case .network: return .noService
        case .notAuthenticated, .missingSessionToken: return .signedOut
        case .server(let status, _), .badResponse(let status, _):
            switch status {
            case 401: return .signedOut
            case 502, 503, 504: return .noService
            default: return .other
            }
        case .invalidURL, .keychain: return .other
        }
    }
}
