# Changelog

## 0.2.0

- `getSession()` tells a finished session (401/403, or a 200 with no session: cleared, returns
  nil) from a server problem (5xx, no connection: throws, session kept). Before, any non-200
  answer returned nil, so a server hiccup looked like being signed out.
- `authenticatedRequest` clears the stored session on a 401 and throws `notAuthenticated`.
- `HominemAuthError.problem` and the `AuthProblem` category type, so apps stop copying the
  error-to-screen mapping.
- Saving a session is all or nothing, and a session without a user or cookies no longer leaves an
  earlier account's user behind.
- The Keychain store updates in place instead of delete-then-add, reports a failed delete, and
  uses the data-protection keychain on macOS when an access group is given (the group was
  silently ignored there before).
- Tests for sign-in, sign-out, 401, 5xx and the Keychain (7 tests became 19).

## 0.1.0

First release: email-code sign-in, Keychain session, `HominemAuthUI`.
