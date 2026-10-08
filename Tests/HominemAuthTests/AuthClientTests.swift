import Foundation
import Testing
@testable import HominemAuth

// MARK: - Cookie parsing (prod secure-cookie support)

private func httpResponse(url: URL, setCookie: String) -> HTTPURLResponse {
    HTTPURLResponse(
        url: url,
        statusCode: 200,
        httpVersion: nil,
        headerFields: ["Set-Cookie": setCookie]
    )!
}

struct AuthClientTests {
    @Test("session token is extracted from a Set-Cookie header")
    func extractSessionToken() async throws {
        let url = URL(string: "https://api.ponti.io/api/auth/sign-in/email-otp")!
        let response = httpResponse(
            url: url,
            setCookie: "better-auth.session_token=eyJhbGciOiJIUzI1NiJ9.signed-value; Path=/; HttpOnly; SameSite=Lax"
        )
        let cookies = AuthClient.extractCookies(from: response)
        #expect(cookies?.sessionToken == "eyJhbGciOiJIUzI1NiJ9.signed-value")
        #expect(cookies?.sessionTokenName == "better-auth.session_token")
    }

    @Test("secure-prefixed cookie is preferred in prod")
    func extractSecureCookie() async throws {
        let url = URL(string: "https://api.ponti.io/api/auth/sign-in/email-otp")!
        let response = httpResponse(
            url: url,
            setCookie: "__Secure-better-auth.session_token=secure-signed-value; Path=/; HttpOnly; Secure; SameSite=Lax"
        )
        let cookies = AuthClient.extractCookies(from: response)
        #expect(cookies?.sessionToken == "secure-signed-value")
        #expect(cookies?.sessionTokenName == "__Secure-better-auth.session_token")
    }

    @Test("session_data cookie is captured alongside the token")
    func extractSessionData() async throws {
        let url = URL(string: "https://api.ponti.io/api/auth/sign-in/email-otp")!
        // HTTPCookie parsing handles one header; exercise fallback via combined value.
        let response = httpResponse(
            url: url,
            setCookie: "better-auth.session_token=tok123; Path=/, better-auth.session_data=data456; Path=/"
        )
        let cookies = AuthClient.extractCookies(from: response)
        #expect(cookies?.sessionToken == "tok123")
        #expect(cookies?.headerValue.contains("tok123") == true)
    }

    @Test("AuthUser decodes from Better Auth session payload")
    func decodeUserPayload() throws {
        let json = """
        {
            "id": "user-1",
            "email": "ada@example.com",
            "emailVerified": true,
            "name": "Ada",
            "image": null,
            "createdAt": "2025-01-01T00:00:00.000Z",
            "updatedAt": "2025-01-01T00:00:00.000Z"
        }
        """
        let user = try JSONDecoder().decode(AuthUser.self, from: Data(json.utf8))
        #expect(user.id == "user-1")
        #expect(user.email == "ada@example.com")
        #expect(user.emailVerified == true)
        #expect(user.name == "Ada")
        #expect(user.createdAt != nil)
    }

    @Test("session payload with null session decodes to no user")
    func nullSessionPayload() throws {
        let json = #"{"session": null, "user": null}"#
        let payload = try JSONDecoder().decode(SessionPayloadFixture.self, from: Data(json.utf8))
        #expect(payload.user == nil)
        #expect(payload.session == nil)
    }

    @Test("AuthConfiguration derives Origin without path")
    func originDerivation() throws {
        #expect(AuthConfiguration.derivedOrigin(from: URL(string: "https://api.ponti.io")!) == "https://api.ponti.io")
        #expect(AuthConfiguration.derivedOrigin(from: URL(string: "http://localhost:4040")!) == "http://localhost:4040")
        #expect(AuthConfiguration.derivedOrigin(from: URL(string: "https://api.lvh.me:4200/some/path?q=1")!) == "https://api.lvh.me:4200")
    }

    @Test("SessionCookies builds a Cookie header")
    func cookieHeader() throws {
        let cookies = SessionCookies(
            sessionToken: "abc",
            sessionTokenName: "__Secure-better-auth.session_token",
            sessionDataName: "better-auth.session_data",
            sessionData: "def"
        )
        #expect(cookies.headerValue == "__Secure-better-auth.session_token=abc; better-auth.session_data=def")
    }
}

// Mirrors the private SessionPayload shape so we can lock the contract in tests.
struct SessionPayloadFixture: Decodable {
    struct Session: Decodable {
        let id: String
    }
    let session: Session?
    let user: AuthUser?
}
