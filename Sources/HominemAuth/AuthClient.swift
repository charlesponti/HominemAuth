import Foundation
import os

/// A URLSession-backed client for Hominem's Better Auth API.
///
/// The API exposes a single auth surface: email OTP:
///   1. `requestOTP(email:)`    → POST /api/auth/email-otp/send-verification-otp
///   2. `verifyOTP(email:otp:)`  → POST /api/auth/sign-in/email-otp (stores session)
///   3. `getSession()`           → GET  /api/auth/get-session
///   4. `signOut()`               → POST /api/auth/sign-out
///
/// Session cookies (plain + `__Secure-` prefixed for prod HTTPS, plus optional
/// `session_data` from Better Auth `cookieCache`) are stored in the Keychain
/// and re-attached as a `Cookie` header. Native clients also send `Origin`
/// (derived `scheme://host[:port]`) to satisfy Better Auth CSRF checks.
public actor AuthClient {
    public let configuration: AuthConfiguration
    public var baseURL: URL { configuration.baseURL }
    private let store: SessionStore
    private let urlSession: URLSession
    private let logger = Logger(subsystem: "com.hominem.auth", category: "AuthClient")

    public init(
        configuration: AuthConfiguration,
        store: SessionStore? = nil,
        urlSession: URLSession? = nil
    ) {
        self.configuration = configuration
        self.store = store ?? SessionStore(configuration: configuration)
        if let urlSession {
            self.urlSession = urlSession
        } else {
            let config = URLSessionConfiguration.ephemeral
            config.httpCookieStorage = nil
            config.httpShouldSetCookies = false
            config.httpCookieAcceptPolicy = .never
            config.requestCachePolicy = .reloadIgnoringLocalCacheData
            config.timeoutIntervalForRequest = configuration.requestTimeout
            config.timeoutIntervalForResource = configuration.requestTimeout * 2
            self.urlSession = URLSession(configuration: config)
        }
    }

    /// Backwards-compat init. No shared access group; use
    /// `init(configuration:)` for prod + multi-app SSO.
    public init(baseURL: URL, store: SessionStore = SessionStore()) {
        self.configuration = AuthConfiguration(baseURL: baseURL)
        self.store = store
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 15
        self.urlSession = URLSession(configuration: config)
    }

    // MARK: - Public API

    /// Requests a verification code be emailed to `email` for sign-in.
    public func requestOTP(email: String) async throws {
        let request = try makeRequest(
            path: "email-otp/send-verification-otp",
            method: "POST",
            body: ["email": email, "type": "sign-in"]
        )
        do {
            let (data, response) = try await urlSession.data(for: request)
            try validate(response: response, data: data)
        } catch let error as HominemAuthError {
            throw error
        } catch {
            throw mapNetworkError(error)
        }
    }

    /// Verifies an OTP and establishes a session, stored in the Keychain.
    @discardableResult
    public func verifyOTP(email: String, otp: String) async throws -> AuthSession {
        let request = try makeRequest(
            path: "sign-in/email-otp",
            method: "POST",
            body: ["email": email, "otp": otp]
        )
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw mapNetworkError(error)
        }
        do {
            try validate(response: response, data: data)
        } catch let error as HominemAuthError {
            // Wrong/expired code surfaces as 400 from Better Auth.
            if case .server(let status, let message) = error, status == 400 {
                throw HominemAuthError.invalidOTP(message: message)
            }
            throw error
        }

        // Prefer the SIGNED cookie value — the raw body token is rejected
        // when sent back. Keep values verbatim (URL-encoding and all).
        let payload = try? JSONDecoder().decode(VerifyPayload.self, from: data)
        let nestedToken = (try? JSONDecoder().decode(VerifySessionWrapper.self, from: data))?.session?.token
        let cookies = Self.extractCookies(from: response)
        let token = cookies?.sessionToken ?? payload?.token ?? nestedToken
        guard let token else {
            throw HominemAuthError.missingSessionToken
        }
        let session = AuthSession(token: token, user: payload?.user, cookies: cookies)
        do {
            try store.save(session: session)
        } catch let error as KeychainError {
            throw HominemAuthError.keychain(error)
        }
        return session
    }

    /// Confirms whether the stored session is still valid.
    ///
    /// - Returns the current user, or `nil` when there is no session or the server says it is
    ///   over (a 401/403, or a 200 with no session). Those two cases also clear the Keychain.
    /// - Throws for anything that says nothing about the session: no connection, a 5xx from the
    ///   server, a Keychain failure. The stored session is kept, so a server hiccup is never
    ///   mistaken for being signed out.
    public func getSession() async throws -> AuthUser? {
        guard let sentCredentials = cookieHeaderValue() else { return nil }

        let request = try makeRequest(path: "get-session")
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw mapNetworkError(error)
        }
        guard let http = response as? HTTPURLResponse else {
            throw HominemAuthError.server(status: -1, message: nil)
        }
        if http.statusCode == 401 || http.statusCode == 403 {
            clearIfUnchanged(sentCredentials)
            return nil
        }
        // Everything else that is not a success keeps the session and keeps its category
        // (rate limited with Retry-After, server error with its message).
        try validate(response: response, data: data)
        let payload = try? JSONDecoder().decode(SessionPayload.self, from: data)
        guard let user = payload?.user, payload?.session != nil else {
            clearIfUnchanged(sentCredentials)
            return nil
        }
        // A newer sign-in replaced the session while this check was in flight: its answer is
        // about the old session, so neither refresh the cache nor claim the new one is valid.
        guard cookieHeaderValue() == sentCredentials else { return try await getSession() }
        // Refresh the cached user only; the token and cookies are never rewritten here.
        do {
            try store.updateCachedUser(user)
        } catch let error as KeychainError {
            throw HominemAuthError.keychain(error)
        }
        return user
    }

    /// Ends the session server-side and clears the Keychain. Always clears
    /// locally, even if the server already considers the session dead (4xx).
    public func signOut() async throws {
        guard cookieHeaderValue() != nil else {
            store.clear()
            return
        }
        let request = try makeRequest(path: "sign-out", method: "POST")
        do {
            let (data, response) = try await urlSession.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                store.clear()
                throw HominemAuthError.server(status: -1, message: nil)
            }
            if (200..<300).contains(http.statusCode) || (400..<500).contains(http.statusCode) {
                store.clear()
                return
            }
            store.clear()
            throw HominemAuthError.server(status: http.statusCode, message: decodeErrorMessage(from: data))
        } catch let error as HominemAuthError {
            throw error
        } catch {
            throw mapNetworkError(error)
        }
    }

    /// Whether a session token is currently stored locally.
    public nonisolated var isAuthenticated: Bool {
        store.sessionToken != nil
    }

    /// The cached user from the last successful sign-in / session check.
    public nonisolated func cachedUser() -> AuthUser? {
        store.cachedUser()
    }

    // MARK: - Authenticated API access

    public func authenticatedRequest(path: String, method: String = "GET") async throws -> Data {
        try await authenticatedRequest(path: path, method: method, body: Optional<Data>.none)
    }

    /// Authenticated request with a JSON-encodable body. A 401 clears the stored session and throws
    /// `notAuthenticated`.
    /// - Parameters:
    ///   - path: Absolute API path, e.g. `/api/notes`. `/api/auth` calls should
    ///     go through the dedicated methods above instead.
    public func authenticatedRequest<Body: Encodable>(
        path: String,
        method: String = "GET",
        body: Body?
    ) async throws -> Data {
        guard let sentCredentials = cookieHeaderValue() else {
            throw HominemAuthError.notAuthenticated
        }
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw HominemAuthError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = configuration.requestTimeout
        applyCommonHeaders(to: &request)
        if let body {
            request.httpBody = try JSONEncoder().encode(body)
        }
        do {
            let (data, response) = try await urlSession.data(for: request)
            try validate(response: response, data: data)
            return data
        } catch let error as HominemAuthError {
            // The server no longer accepts this session: forget it here too, so the next launch
            // does not show a signed-in screen for a session that is gone.
            if case .server(let status, _) = error, status == 401 {
                clearIfUnchanged(sentCredentials)
                throw HominemAuthError.notAuthenticated
            }
            throw error
        } catch {
            throw mapNetworkError(error)
        }
    }

    // MARK: - Helpers

    private func makeRequest(
        path: String,
        method: String = "GET",
        body: [String: Any]? = nil
    ) throws -> URLRequest {
        guard let url = URL(string: "/api/auth/\(path)", relativeTo: baseURL) else {
            throw HominemAuthError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = configuration.requestTimeout
        applyCommonHeaders(to: &request)
        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } else if method != "GET" && method != "HEAD" {
            request.httpBody = Data("{}".utf8)
        }
        return request
    }

    private func applyCommonHeaders(to request: inout URLRequest) {
        request.setValue(configuration.origin, forHTTPHeaderField: "Origin")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let userAgent = configuration.userAgent {
            request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        }
        if let cookie = cookieHeaderValue() {
            request.setValue(cookie, forHTTPHeaderField: "Cookie")
        }
    }

    /// Builds the `Cookie` header from stored cookies, or legacy token.
    /// When only a legacy token exists (no cookie names captured), sends both
    /// plain + `__Secure-` variants so pre-migration sessions work in prod.
    private func cookieHeaderValue() -> String? {
        if let cookies = store.storedCookies() {
            return cookies.headerValue
        }
        guard let token = store.sessionToken else { return nil }
        return "better-auth.session_token=\(token); __Secure-better-auth.session_token=\(token)"
    }

    /// Clears the stored session only if it is still the one the rejected request was sent with,
    /// so a late 401 for an old session cannot erase a newer sign-in.
    private func clearIfUnchanged(_ sentCredentials: String) {
        if cookieHeaderValue() == sentCredentials { store.clear() }
    }

    private func validate(response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else {
            throw HominemAuthError.server(status: -1, message: nil)
        }
        guard (200..<300).contains(http.statusCode) else {
            logFailure(status: http.statusCode, url: http.url, data: data)
            if http.statusCode == 429 {
                throw HominemAuthError.rateLimited(retryAfter: retryAfter(from: http))
            }
            throw HominemAuthError.server(status: http.statusCode, message: decodeErrorMessage(from: data))
        }
    }

    private func retryAfter(from http: HTTPURLResponse) -> TimeInterval? {
        for (key, value) in http.allHeaderFields {
            guard let key = key as? String,
                  key.caseInsensitiveCompare("Retry-After") == .orderedSame,
                  let value = value as? String
            else { continue }
            return TimeInterval(value.trimmingCharacters(in: .whitespaces))
        }
        return nil
    }

    private func mapNetworkError(_ error: Error) -> HominemAuthError {
        if let urlError = error as? URLError {
            return .network(underlying: urlError.localizedDescription)
        }
        return .network(underlying: error.localizedDescription)
    }

    private func logFailure(status: Int, url: URL?, data: Data) {
        // Never log cookies, tokens, or emails. Status + path only.
        logger.error("request failed: \(status, privacy: .public) \(url?.path ?? "?", privacy: .public)")
        #if DEBUG
        if let body = String(data: data, encoding: .utf8) {
            logger.debug("error body: \(body, privacy: .private)")
        }
        #endif
    }

    private func decodeErrorMessage(from data: Data) -> String? {
        struct ErrorPayload: Decodable {
            let message: String?
            let error: String?
        }
        guard let payload = try? JSONDecoder().decode(ErrorPayload.self, from: data) else {
            return nil
        }
        return payload.message ?? payload.error
    }

    // MARK: - Cookie parsing

    static let sessionTokenNames = [
        "better-auth.session_token",
        "__Secure-better-auth.session_token",
    ]
    static let sessionDataNames = [
        "better-auth.session_data",
        "__Secure-better-auth.session_data",
    ]

    /// Extracts signed session cookies via `HTTPCookie` parsing (handles
    /// `Expires` commas correctly), with a manual `Set-Cookie` fallback.
    static func extractCookies(from response: URLResponse) -> SessionCookies? {
        guard let http = response as? HTTPURLResponse,
              let url = http.url
        else { return nil }

        var headerFields: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            guard let key = key as? String, let value = value as? String else { continue }
            headerFields[key] = value
        }
        let parsed = HTTPCookie.cookies(withResponseHeaderFields: headerFields, for: url)
        var tokenValue: String?
        var tokenName: String?
        var dataValue: String?
        var dataName: String?
        for cookie in parsed {
            if sessionTokenNames.contains(cookie.name), tokenValue == nil {
                tokenValue = cookie.value
                tokenName = cookie.name
            } else if sessionDataNames.contains(cookie.name), dataValue == nil {
                dataValue = cookie.value
                dataName = cookie.name
            }
        }
        if let tokenValue, let tokenName {
            return SessionCookies(
                sessionToken: tokenValue,
                sessionTokenName: tokenName,
                sessionDataName: dataName,
                sessionData: dataValue
            )
        }
        return extractCookiesFallback(headerFields: headerFields)
    }

    private static func extractCookiesFallback(headerFields: [String: String]) -> SessionCookies? {
        var setCookieValues: [String] = []
        for (key, value) in headerFields where key.caseInsensitiveCompare("Set-Cookie") == .orderedSame {
            setCookieValues.append(value)
        }
        // `allHeaderFields` may comma-join multiple Set-Cookie values; split
        // conservatively on ";", then match known cookie names.
        var found: [String: String] = [:]
        for combined in setCookieValues {
            // Split into individual cookie segments. Expires dates contain
            // commas but not semicolons, so ";" is safe here.
            for part in combined.split(separator: ";") {
                let trimmed = part.trimmingCharacters(in: .whitespacesAndNewlines)
                let pieces = trimmed.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard pieces.count == 2 else { continue }
                let name = pieces[0].trimmingCharacters(in: .whitespaces)
                if (sessionTokenNames + sessionDataNames).contains(name), found[name] == nil {
                    found[name] = String(pieces[1])
                }
            }
        }
        let tokenName = sessionTokenNames.first(where: { found[$0] != nil })
        guard let tokenName, let tokenValue = found[tokenName] else { return nil }
        let dataName = sessionDataNames.first(where: { found[$0] != nil })
        return SessionCookies(
            sessionToken: tokenValue,
            sessionTokenName: tokenName,
            sessionDataName: dataName,
            sessionData: dataName.flatMap { found[$0] }
        )
    }
}

// MARK: - Decodable payloads

private struct VerifyPayload: Decodable {
    let token: String?
    let user: AuthUser?
}

private struct VerifySessionWrapper: Decodable {
    struct NestedSession: Decodable {
        let token: String?
    }
    let session: NestedSession?
}

private struct SessionPayload: Decodable {
    struct Session: Decodable {
        let id: String
    }
    let session: Session?
    let user: AuthUser?
}
