# HominemAuth

Native iOS + macOS Swift client for the Hominem API's Better Auth deployment.
Email OTP only, `URLSession` + Keychain, Swift 6, `@Observable` UI.

## How it works

API verifies sessions via Better Auth cookies (`services/api/src/middleware/auth.ts`
→ `betterAuthServer.api.getSession({ headers })`).

1. `POST /api/auth/email-otp/send-verification-otp` `{ email, type: "sign-in" }`
2. `POST /api/auth/sign-in/email-otp` `{ email, otp }` → signed `Set-Cookie`
   (`better-auth.session_token` locally, `__Secure-better-auth.session_token`
   in prod HTTPS, plus optional `session_data` from `cookieCache`) → stored in Keychain.
3. Later requests attach `Cookie: <stored cookies>` + `Origin: scheme://host[:port]`
   (native CSRF, same as the API login proxy).

## Using it

`Package.swift` (the `HominemAuth` core needs iOS 15+ / macOS 12+; `HominemAuthUI` needs iOS 17+ / macOS 14+):

```swift
.package(path: "../HominemAuth")
```

```swift
import HominemAuth
import HominemAuthUI

// Prod with shared SSO group across your apps:
let config = AuthConfiguration(
    baseURL: AuthConfiguration.production.baseURL,
    keychainAccessGroup: "<TeamID>.com.hominem.auth.shared"
)
@State private var auth = AuthController(configuration: config)

// .environment(auth) in your App,
// @Environment(AuthController.self) var auth in views,
// AuthStatusControl(controller: auth) for toolbar,
// SignInView(controller: auth) for the sheet.
```

Headless:

```swift
let auth = AuthClient(configuration: .localDevelopment)
try await auth.requestOTP(email: "you@example.com")
// dev: read code from ~/.hominem/scripted-mailbox.jsonl (NOT 000000)
// prod: real 6-digit email via Resend
let session = try await auth.verifyOTP(email: "you@example.com", otp: "123456")
if let user = try await auth.getSession() { ... }
let data = try await auth.authenticatedRequest(path: "/api/health")
try await auth.signOut()
```

Env overrides used by GeoReview: `HOMINEM_API_URL`, `HOMINEM_API_PROD=1`,
`HOMINEM_KEYCHAIN_GROUP`.

## Notes

- **Dev OTP**: `NODE_ENV != production` uses the scripted email provider —
  random 6-digit OTP captured to `~/.hominem/scripted-mailbox.jsonl`
  (`readLatestScriptedOtp`). Prod sends real email via Resend.
- **Storage**: signed cookie values + cached user in Keychain, service
  `com.hominem.auth` by default. Set `keychainAccessGroup` identically in all
  apps for SSO; requires Keychain Sharing entitlement + capability in each app.
  Nil = app-private, no entitlement needed.
- **URLs**: local `http://localhost:4040`, portless `https://api.lvh.me:4200`,
  prod `https://api.ponti.io`.
- **Errors**: `invalidOTP`, `rateLimited(retryAfter:)`, `server(status:message:)`,
  `network`, `keychain`, `notAuthenticated`. `getSession()` returns nil (not throw)
  for expired/invalid sessions. `signOut()` always clears locally.
