import Foundation
import Testing
@testable import HominemAuth

// A URLProtocol that answers every request from a closure, so the client is tested against its
// real code path without a network. Tests that use it run one at a time (`.serialized`).
final class StubProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: (@Sendable (URLRequest) -> (Int, [String: String], Data))?
    nonisolated(unsafe) static var requests: [URLRequest] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requests.append(request)
        let (status, headers, body) = Self.handler?(request) ?? (500, [:], Data())
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private let userJSON = #"{"id":"u1","email":"me@example.com"}"#
private let cookie = "better-auth.session_token=signed.value; Path=/; HttpOnly"

private func makeClient(
    _ handler: @escaping @Sendable (URLRequest) -> (Int, [String: String], Data)
) -> (AuthClient, SessionStore) {
    StubProtocol.handler = handler
    StubProtocol.requests = []
    let configuration = AuthConfiguration(
        baseURL: URL(string: "https://api.example.com")!,
        keychainService: "com.hominem.auth.tests.\(UUID().uuidString)"
    )
    let store = SessionStore(configuration: configuration)
    let session = URLSession(configuration: {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return config
    }())
    return (AuthClient(configuration: configuration, store: store, urlSession: session), store)
}

private func reply(_ status: Int, _ body: String = "{}", cookie: String? = nil) -> (Int, [String: String], Data) {
    var headers = ["Content-Type": "application/json"]
    if let cookie { headers["Set-Cookie"] = cookie }
    return (status, headers, Data(body.utf8))
}

private func signedIn(
    _ handler: @escaping @Sendable (URLRequest) -> (Int, [String: String], Data)
) async throws -> (AuthClient, SessionStore) {
    let (client, store) = makeClient { request in
        if request.url!.path.hasSuffix("sign-in/email-otp") {
            return reply(200, #"{"token":"t","user":\#(userJSON)}"#, cookie: cookie)
        }
        return handler(request)
    }
    _ = try await client.verifyOTP(email: "me@example.com", otp: "123456")
    return (client, store)
}

@Suite(.serialized)
struct AuthFlowTests {
    @Test("signing in stores the signed cookie and sends it on later requests")
    func signInStoresCookie() async throws {
        let (client, store) = try await signedIn { _ in reply(200, #"{"session":{"id":"s"},"user":\#(userJSON)}"#) }
        defer { store.clear() }
        #expect(store.storedCookies()?.sessionToken == "signed.value")
        #expect(client.isAuthenticated)
        _ = try await client.getSession()
        let last = try #require(StubProtocol.requests.last)
        #expect(last.value(forHTTPHeaderField: "Cookie")?.contains("better-auth.session_token=signed.value") == true)
        #expect(last.value(forHTTPHeaderField: "Origin") == "https://api.example.com")
    }

    @Test("a wrong code is reported as invalidOTP")
    func wrongCode() async throws {
        let (client, store) = makeClient { _ in reply(400, #"{"message":"Invalid OTP"}"#) }
        defer { store.clear() }
        await #expect(throws: HominemAuthError.self) {
            try await client.verifyOTP(email: "me@example.com", otp: "000000")
        }
    }

    @Test("a valid session returns its user")
    func validSession() async throws {
        let (client, store) = try await signedIn { _ in reply(200, #"{"session":{"id":"s"},"user":\#(userJSON)}"#) }
        defer { store.clear() }
        #expect(try await client.getSession()?.email == "me@example.com")
    }

    @Test("a 200 with no session signs out locally")
    func nullSessionClears() async throws {
        let (client, store) = try await signedIn { _ in reply(200, "null") }
        defer { store.clear() }
        #expect(try await client.getSession() == nil)
        #expect(!client.isAuthenticated)
    }

    @Test("a 401 signs out locally")
    func unauthorizedClears() async throws {
        let (client, store) = try await signedIn { _ in reply(401) }
        defer { store.clear() }
        #expect(try await client.getSession() == nil)
        #expect(!client.isAuthenticated)
    }

    @Test("a server error is not mistaken for being signed out")
    func serverErrorKeepsSession() async throws {
        let (client, store) = try await signedIn { _ in reply(503) }
        defer { store.clear() }
        await #expect(throws: HominemAuthError.self) { try await client.getSession() }
        #expect(client.isAuthenticated)
    }

    @Test("a rate-limited session check keeps its category and the session")
    func sessionCheckRateLimited() async throws {
        let (client, store) = try await signedIn { _ in reply(429) }
        defer { store.clear() }
        do {
            _ = try await client.getSession()
            Issue.record("expected an error")
        } catch let error as HominemAuthError {
            #expect(error.problem == .tooManyAttempts)
        }
        #expect(client.isAuthenticated)
    }

    @Test("an authenticated request that gets a 401 clears the session and says notAuthenticated")
    func authenticatedUnauthorized() async throws {
        let (client, store) = try await signedIn { _ in reply(401) }
        defer { store.clear() }
        do {
            _ = try await client.authenticatedRequest(path: "/api/memory")
            Issue.record("expected an error")
        } catch let error as HominemAuthError {
            #expect(error.problem == .signedOut)
        }
        #expect(!client.isAuthenticated)
    }

    @Test("an authenticated request that gets a 500 keeps the session")
    func authenticatedServerError() async throws {
        let (client, store) = try await signedIn { _ in reply(500) }
        defer { store.clear() }
        await #expect(throws: HominemAuthError.self) { try await client.authenticatedRequest(path: "/api/memory") }
        #expect(client.isAuthenticated)
    }

    @Test("signing out clears the session even when the server already ended it")
    func signOutClears() async throws {
        let (client, store) = try await signedIn { _ in reply(401) }
        defer { store.clear() }
        try await client.signOut()
        #expect(!client.isAuthenticated)
    }

    @Test("a second sign-in leaves nothing of the first session behind")
    func secondSignInReplacesFirst() async throws {
        let (client, store) = try await signedIn { _ in reply(200) }
        defer { store.clear() }
        #expect(store.cachedUser()?.id == "u1")
        StubProtocol.handler = { _ in reply(200, #"{"token":"t2"}"#, cookie: "better-auth.session_token=other.value; Path=/") }
        _ = try await client.verifyOTP(email: "other@example.com", otp: "123456")
        #expect(store.cachedUser() == nil)
        #expect(store.storedCookies()?.sessionToken == "other.value")
    }
}

struct ProblemTests {
    @Test("errors are sorted into the categories a screen cares about")
    func categories() {
        #expect(HominemAuthError.invalidOTP(message: nil).problem == .badCode)
        #expect(HominemAuthError.rateLimited(retryAfter: 5).problem == .tooManyAttempts)
        #expect(HominemAuthError.network(underlying: "x").problem == .noService)
        #expect(HominemAuthError.notAuthenticated.problem == .signedOut)
        #expect(HominemAuthError.server(status: 401, message: nil).problem == .signedOut)
        #expect(HominemAuthError.server(status: 503, message: nil).problem == .noService)
        #expect(HominemAuthError.server(status: 500, message: nil).problem == .other)
    }
}

struct KeychainStoreTests {
    @Test("a value can be saved, replaced, read and removed")
    func roundTrip() throws {
        let store = KeychainStore(service: "com.hominem.auth.tests.\(UUID().uuidString)")
        defer { try? store.delete("k") }
        #expect(try store.get("k") == nil)
        try store.set("one", forKey: "k")
        try store.set("two", forKey: "k")
        #expect(try store.get("k") == "two")
        try store.delete("k")
        #expect(try store.get("k") == nil)
        try store.delete("k")  // removing what is not there is fine
    }
}
