import Foundation

/// Persists the signed-in session (signed cookie values + cached user) in the
/// Keychain on iOS + macOS. Supports shared access groups for multi-app SSO.
public final class SessionStore: @unchecked Sendable {
    private let keychain: KeychainStore
    private let tokenKey = "session_token/v1"
    private let legacyTokenKey = "session_token"
    private let cookiesKey = "session_cookies/v1"
    private let userKey = "session_user"

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

    /// Saves the session. All of it is written or none of it is: if any part fails, what was
    /// written is removed, so a half-saved session can never be read back later.
    public func save(session: AuthSession) throws {
        do {
            try keychain.set(session.token, forKey: tokenKey)
            // A part this session does not have is removed, so nothing of an earlier session
            // (possibly another account) is left to be read back.
            if let cookies = session.cookies {
                try keychain.set(try Self.json(cookies), forKey: cookiesKey)
            } else {
                try keychain.delete(cookiesKey)
            }
            if let user = session.user {
                try keychain.set(try Self.json(user), forKey: userKey)
            } else {
                try keychain.delete(userKey)
            }
        } catch {
            clear()
            throw error
        }
    }

    private static func json<Value: Encodable>(_ value: Value) throws -> String {
        let data = try JSONEncoder().encode(value)
        guard let text = String(data: data, encoding: .utf8) else { throw KeychainError.unexpectedData }
        return text
    }

    public func clear() {
        for key in [tokenKey, legacyTokenKey, cookiesKey, userKey] {
            try? keychain.delete(key)
        }
    }
}
