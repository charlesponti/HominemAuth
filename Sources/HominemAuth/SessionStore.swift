import Foundation

/// Persists the signed-in session (signed cookie values + cached user) in the
/// Keychain on iOS + macOS. Supports shared access groups for multi-app SSO.
public final class SessionStore: @unchecked Sendable {
    private let keychain: KeychainStore
    private let tokenKey = "session_token/v1"
    private let legacyTokenKey = "session_token"
    private let cookiesKey = "session_cookies/v1"
    private let userKey = "session_user"
    private let legacyUserKey = "session_user"

    public init(keychain: KeychainStore = KeychainStore()) {
        self.keychain = keychain
    }

    public convenience init(configuration: AuthConfiguration) {
        self.init(keychain: KeychainStore(
            service: configuration.keychainService,
            accessGroup: configuration.keychainAccessGroup
        ))
    }

    /// The signed session token, if stored (migrates legacy key on read).
    public var sessionToken: String? {
        if let token = (try? keychain.get(tokenKey)) ?? nil { return token }
        // One-time forward migration from pre-v1 key.
        if let legacy = (try? keychain.get(legacyTokenKey)) ?? nil {
            try? keychain.set(legacy, forKey: tokenKey)
            return legacy
        }
        // Fall back to cookies dict (prod secure-cookie names).
        return storedCookies()?.sessionToken
    }

    /// All stored session cookies (`session_token` + `session_data`, plain or
    /// `__Secure-` prefixed). Used to build the `Cookie` header.
    public func storedCookies() -> SessionCookies? {
        guard
            let raw = (try? keychain.get(cookiesKey)) ?? nil,
            let data = raw.data(using: .utf8)
        else { return nil }
        return try? JSONDecoder().decode(SessionCookies.self, from: data)
    }

    /// The cached user saved at sign-in time. Optimistic — use
    /// `AuthClient.getSession()` to confirm the session is still valid.
    public func cachedUser() -> AuthUser? {
        guard
            let raw = try? keychain.get(userKey),
            let data = raw.data(using: .utf8)
        else { return nil }
        return try? JSONDecoder().decode(AuthUser.self, from: data)
    }

    public func save(session: AuthSession) throws {
        try keychain.set(session.token, forKey: tokenKey)
        if let cookies = session.cookies,
           let data = try? JSONEncoder().encode(cookies),
           let raw = String(data: data, encoding: .utf8) {
            try? keychain.set(raw, forKey: cookiesKey)
        }
        if let user = session.user,
           let data = try? JSONEncoder().encode(user),
           let raw = String(data: data, encoding: .utf8) {
            try? keychain.set(raw, forKey: userKey)
        }
    }

    public func clear() {
        for key in [tokenKey, legacyTokenKey, cookiesKey, userKey, legacyUserKey] {
            try? keychain.delete(key)
        }
    }
}
