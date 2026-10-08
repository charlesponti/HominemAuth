import Foundation

/// A serializable Hominem user, matching the shape Better Auth returns for a
/// session (`/api/auth/get-session`, `/api/auth/sign-in/email-otp`).
public struct AuthUser: Codable, Hashable, Sendable {
    public let id: String
    public let email: String
    public let emailVerified: Bool?
    public let name: String?
    public let image: String?
    public let createdAt: Date?
    public let updatedAt: Date?

    public init(
        id: String,
        email: String,
        emailVerified: Bool? = nil,
        name: String? = nil,
        image: String? = nil,
        createdAt: Date? = nil,
        updatedAt: Date? = nil
    ) {
        self.id = id
        self.email = email
        self.emailVerified = emailVerified
        self.name = name
        self.image = image
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    private enum CodingKeys: String, CodingKey {
        case id, email, emailVerified, name, image, createdAt, updatedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        email = try container.decode(String.self, forKey: .email)
        emailVerified = try container.decodeIfPresent(Bool.self, forKey: .emailVerified)
        name = try container.decodeIfPresent(String.self, forKey: .name)
        image = try container.decodeIfPresent(String.self, forKey: .image)
        createdAt = Self.decodeDate(container: container, key: .createdAt)
        updatedAt = Self.decodeDate(container: container, key: .updatedAt)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(email, forKey: .email)
        try container.encodeIfPresent(emailVerified, forKey: .emailVerified)
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(image, forKey: .image)
        try container.encodeIfPresent(createdAt, forKey: .createdAt)
        try container.encodeIfPresent(updatedAt, forKey: .updatedAt)
    }

    private static func decodeDate(container: KeyedDecodingContainer<CodingKeys>, key: CodingKeys) -> Date? {
        // Better Auth emits ISO-8601 strings; be lenient to timestamps too.
        if let date = try? container.decodeIfPresent(Date.self, forKey: key) {
            return date
        }
        if let value = try? container.decodeIfPresent(String.self, forKey: key) {
            return ISO8601DateFormatter().date(from: value)
                ?? Self.fallbackDateFormatter.date(from: value)
        }
        if let timestamp = try? container.decodeIfPresent(Double.self, forKey: key) {
            return Date(timeIntervalSince1970: timestamp / 1000.0)
        }
        return nil
    }

    private static let fallbackDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        return formatter
    }()
}

/// Session cookies captured from `Set-Cookie` (verbatim values).
/// Supports both plain and `__Secure-` prefixed names for prod HTTPS.
public struct SessionCookies: Codable, Sendable, Equatable {
    /// Signed session token value (from `session_token` cookie).
    public let sessionToken: String
    /// Cookie name that carried the token (for round-tripping).
    public let sessionTokenName: String
    /// Optional cached session-data cookie (Better Auth `cookieCache`).
    public let sessionDataName: String?
    public let sessionData: String?

    public init(
        sessionToken: String,
        sessionTokenName: String = "better-auth.session_token",
        sessionDataName: String? = nil,
        sessionData: String? = nil
    ) {
        self.sessionToken = sessionToken
        self.sessionTokenName = sessionTokenName
        self.sessionDataName = sessionDataName
        self.sessionData = sessionData
    }

    /// `Cookie` header value, e.g. `a=1; b=2`.
    public var headerValue: String {
        var parts = ["\(sessionTokenName)=\(sessionToken)"]
        if let name = sessionDataName, let data = sessionData {
            parts.append("\(name)=\(data)")
        }
        return parts.joined(separator: "; ")
    }
}

/// A validated session on the Hominem API.
public struct AuthSession: Sendable, Equatable {
    /// The signed session-token value (not the full cookie).
    public let token: String
    public let user: AuthUser?
    /// Full cookies to send back (nil for legacy single-token sessions).
    public let cookies: SessionCookies?

    public init(token: String, user: AuthUser?, cookies: SessionCookies? = nil) {
        self.token = token
        self.user = user
        self.cookies = cookies
    }
}
