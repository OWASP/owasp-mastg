import Foundation
import LocalAuthentication
import Security

struct MastgTest {

    static func mastgTest(completion: @escaping (String) -> Void) {
        let account = "com.mastg.sectoken"
        let tokenData = "8767086b9f6f976g-a8df76".data(using: .utf8)!

        // 1. Store the token in the Keychain with no ACL flags, only protection
        // 1a. Build your add‐item query
        let storeQuery: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrAccount as String:    account,
            kSecValueData as String:      tokenData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]

        // Before adding, we delete any existing item
        SecItemDelete(storeQuery as CFDictionary)
        let storeStatus = SecItemAdd(storeQuery as CFDictionary, nil)
        guard storeStatus == errSecSuccess else {
        completion("❌ Failed to store token in Keychain (status \(storeStatus))")
        return
        }

        // 2. Now for retrieval, prompt the user explicitly with evaluatePolicy *from your app* (instead of letting the system do it)
        let context = LAContext()
        let reason  = "Authenticate to access your token"
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: reason)
        { success, error in
            DispatchQueue.main.async {
                guard success else {
                    return completion("🔒 Authentication failed")
                }

                // 3) On success, pull the item from Keychain
                let fetchQuery: [String: Any] = [
                    kSecClass as String:         kSecClassGenericPassword,
                    kSecAttrAccount as String:   account,
                    kSecReturnData as String:    true,
                    kSecMatchLimit as String:    kSecMatchLimitOne
                ]

                var result: CFTypeRef?
                let fetchStatus = SecItemCopyMatching(fetchQuery as CFDictionary, &result)

                if fetchStatus == errSecSuccess,
                   let data = result as? Data,
                   let token = String(data: data, encoding: .utf8) {
                    completion("✅ Retrieved token: \(token)")
                } else {
                    completion("❌ Authentication failed or token inaccessible (status \(fetchStatus))")
                }
            }
        }
    }
}
