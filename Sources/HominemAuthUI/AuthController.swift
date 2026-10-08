import Foundation
import Observation
import HominemAuth

/// Observable state + glue for driving the Hominem email-OTP flow from a
/// SwiftUI app (iOS + macOS). Owns an `AuthClient` and exposes sign-in /
/// sign-out actions and session state.
///
/// Usage (iOS 17+ / macOS 14+):
/// ```swift
/// @State private var auth = AuthController(configuration: .production)
/// // ...
/// .environment(auth)
/// // ...
/// @Environment(AuthController.self) private var auth
/// ```
@available(iOS 17, macOS 14, *)
@Observable
@MainActor
public final class AuthController {
    public enum Phase: Equatable {
        case loading
        case signedOut
        case signedIn(AuthUser)
    }

    public private(set) var phase: Phase = .loading
    public private(set) var isBusy = false
    public var errorMessage: String?
    /// Earliest date a new OTP may be requested (rate-limit UX).
    public private(set) var resendAvailableAt: Date?

    public let client: AuthClient

    private let emailRegEx = try? NSRegularExpression(
        pattern: #"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$"#,
        options: [.caseInsensitive]
    )

    /// Resend cooldown after a successful `requestOTP`.
    public var resendCooldown: TimeInterval = 30

    public var canResend: Bool {
        guard let resendAvailableAt else { return true }
        return Date() >= resendAvailableAt
    }

    public init(client: AuthClient) {
        self.client = client
        if let cached = client.cachedUser() {
            self.phase = .signedIn(cached)
        } else {
            self.phase = .signedOut
        }
    }

    public convenience init(configuration: AuthConfiguration) {
        self.init(client: AuthClient(configuration: configuration))
    }

    /// Confirms the stored session (if any) against the API.
    public func refreshSession() async {
        guard client.isAuthenticated else {
            if case .loading = phase { phase = .signedOut }
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            if let user = try await client.getSession() {
                phase = .signedIn(user)
            } else {
                phase = .signedOut
            }
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
            if case .loading = phase { phase = .signedOut }
        }
    }

    /// Sends a verification code to `email`. Returns `false` for validation
    /// failures or rate-limit cooldown without touching the network.
    @discardableResult
    public func requestOTP(email: String) async -> Bool {
        let trimmed = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidEmail(trimmed) else {
            errorMessage = "Enter a valid email address."
            return false
        }
        guard canResend else {
            errorMessage = "Wait a moment before requesting another code."
            return false
        }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do {
            try await client.requestOTP(email: trimmed)
            resendAvailableAt = Date().addingTimeInterval(resendCooldown)
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    /// Verifies an OTP and transitions to `.signedIn` on success.
    @discardableResult
    public func verifyOTP(email: String, otp: String) async -> Bool {
        let code = otp.trimmingCharacters(in: .whitespacesAndNewlines)
        guard code.count >= 4 else {
            errorMessage = "Enter the code from your email."
            return false
        }
        isBusy = true
        errorMessage = nil
        defer { isBusy = false }
        do {
            let session = try await client.verifyOTP(email: email, otp: code)
            phase = .signedIn(session.user ?? AuthUser(id: "", email: email))
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    /// Signs out on the server and clears local state.
    public func signOut() async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await client.signOut()
        } catch {
            errorMessage = error.localizedDescription
        }
        phase = .signedOut
    }

    public func clearError() {
        errorMessage = nil
    }

    public var signedInUser: AuthUser? {
        if case .signedIn(let user) = phase { return user }
        return nil
    }

    public var isSignedIn: Bool {
        if case .signedIn = phase { return true }
        return false
    }

    private func isValidEmail(_ email: String) -> Bool {
        guard let emailRegEx else { return false }
        let range = NSRange(location: 0, length: (email as NSString).length)
        return emailRegEx.firstMatch(in: email, options: [], range: range) != nil
    }
}
