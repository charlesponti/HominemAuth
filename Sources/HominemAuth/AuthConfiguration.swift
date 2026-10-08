import Foundation

/// Prod-ready configuration for `AuthClient`.
///
/// Centralizes everything that differs between local / portless / prod:
/// base URL, derived `Origin` header, Keychain service + shared access group,
/// timeouts and User-Agent.
public struct AuthConfiguration: Sendable {
    public let baseURL: URL
    /// Explicit Origin override. Defaults to `scheme://host[:port]` of `baseURL`.
    public let origin: String
    public let keychainService: String
    /// Shared Keychain access group, e.g. `"<TeamID>.com.hominem.auth.shared"`.
    /// Nil = no sharing (works without Keychain Sharing entitlement).
    /// Set this identically in all iOS/macOS apps that must share a session.
    public let keychainAccessGroup: String?
    public let requestTimeout: TimeInterval
    public let userAgent: String?

    public init(
        baseURL: URL,
        origin: String? = nil,
        keychainService: String = "com.hominem.auth",
        keychainAccessGroup: String? = nil,
        requestTimeout: TimeInterval = 15,
        userAgent: String? = nil
    ) {
        self.baseURL = baseURL
        self.origin = origin ?? AuthConfiguration.derivedOrigin(from: baseURL)
        self.keychainService = keychainService
        self.keychainAccessGroup = keychainAccessGroup
        self.requestTimeout = requestTimeout
        self.userAgent = userAgent
    }

    /// `scheme://host[:port]` — what Better Auth's CSRF check expects.
    /// Never includes path/query/trailing slash.
    public static func derivedOrigin(from url: URL) -> String {
        var components = URLComponents()
        components.scheme = url.scheme?.lowercased() ?? "https"
        components.host = url.host
        if let port = url.port {
            components.port = port
        }
        return components.string ?? url.absoluteString
    }

    // MARK: - Presets

    /// Local dev API (`pnpm --filter @hominem/api dev`).
    public static let localDevelopment = AuthConfiguration(
        baseURL: URL(string: "http://localhost:4040")!
    )

    /// Portless dev proxy.
    public static let portlessDevelopment = AuthConfiguration(
        baseURL: URL(string: "https://api.lvh.me:4200")!
    )

    /// Production API.
    public static let production = AuthConfiguration(
        baseURL: URL(string: "https://api.ponti.io")!
    )
}
