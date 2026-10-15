import Foundation
import Security

/// Keychain wrapper for the auth session, iOS + macOS.
///
/// Supports a shared `accessGroup` so multiple apps (e.g. Geo + future iOS
/// app) backed by the same Apple Developer Team can share one session.
/// Requires the Keychain Sharing entitlement + capability in each app when
/// `accessGroup` is non-nil. Nil = app-private, no entitlement needed.
///
/// On macOS a shared access group only works in the data-protection keychain; the older
/// file-based keychain ignores the group without an error. So when a group is given, the
/// data-protection keychain is used on macOS (the app must then be signed with the entitlement).
public struct KeychainStore: Sendable {
    private let service: String
    private let accessGroup: String?

    public init(
        service: String = "com.hominem.auth",
        accessGroup: String? = nil
    ) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func baseQuery(forKey key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
            #if os(macOS)
            query[kSecUseDataProtectionKeychain as String] = true
            #endif
        }
        return query
    }

    /// Saves `value`, replacing any existing one. Updates in place when the item exists, so a
    /// failed write never leaves the key empty.
    public func set(_ value: String, forKey key: String) throws {
        let data = Data(value.utf8)
        let base = baseQuery(forKey: key)
        // Available after first unlock, never syncs to iCloud. Works for
        // shared groups on the same device without extra setup.
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(base as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(base.merging(attributes) { $1 } as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            if status == errSecInteractionNotAllowed {
                throw KeychainError.interactionNotAllowed
            }
            throw KeychainError.writeFailed(status: Int(status))
        }
    }

    public func get(_ key: String) throws -> String? {
        var query = baseQuery(forKey: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        if status == errSecInteractionNotAllowed {
            throw KeychainError.interactionNotAllowed
        }
        guard status == errSecSuccess else {
            throw KeychainError.readFailed(status: Int(status))
        }
        guard let data = result as? Data else {
            throw KeychainError.unexpectedData
        }
        return String(data: data, encoding: .utf8)
    }

    /// Removes the item. A missing item is not an error.
    public func delete(_ key: String) throws {
        let status = SecItemDelete(baseQuery(forKey: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.writeFailed(status: Int(status))
        }
    }
}
