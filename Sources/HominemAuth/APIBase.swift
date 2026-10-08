import Foundation

extension AuthClient {
    /// Base URL helpers for the Hominem API.
    /// Prefer `AuthConfiguration.localDevelopment/.portlessDevelopment/.production`
    /// for new code — this enum stays for backwards compat (e.g. GeoReview).
    public enum API {
        /// Local development API (`pnpm --filter @hominem/api dev`): http://localhost:4040
        public static let localDevelopment = AuthConfiguration.localDevelopment.baseURL

        /// Portless dev proxy: https://api.lvh.me:4200
        public static let portlessDevelopment = AuthConfiguration.portlessDevelopment.baseURL

        /// Production API: https://api.ponti.io
        public static let production = AuthConfiguration.production.baseURL
    }
}