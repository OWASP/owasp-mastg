import SwiftUI
import LocalAuthentication
import Security

struct MastgTest {

  static func mastgTest(completion: @escaping (String) -> Void) {
    let account = "com.mastg.sectoken"
    let tokenData = "8767086b9f6f976g-a8df76".data(using: .utf8)!
    
    // 1. Store the token in the Keychain with ACL flags
    // 1a. Create an access‐control object requiring user presence
    guard let accessControl = SecAccessControlCreateWithFlags(
      nil,
      kSecAttrAccessibleWhenUnlocked,
      .userPresence,
      nil
    ) else {
      completion("❌ Failed to create access control")
      return
    }
    
    // 1b. Build your add‐item query
    // Optional: you may provide a customized context to alter the default config, e.g. to set a "reuse duration".
    // See https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id#Optionally-Provide-a-Customized-Context
    // Keychain services automatically makes use of the LocalAuthentication framework, even if you don't provide one.
    //
    //  let context = LAContext()
    //  context.touchIDAuthenticationAllowableReuseDuration = 10
    let storeQuery: [String: Any] = [
      kSecClass as String:          kSecClassGenericPassword,
      kSecAttrAccount as String:    account,
      kSecValueData as String:      tokenData,
      kSecAttrAccessControl as String: accessControl,
      // kSecUseAuthenticationContext as String: context,
    ]
    
    // Before adding, we delete any existing item
    SecItemDelete(storeQuery as CFDictionary)
    let storeStatus = SecItemAdd(storeQuery as CFDictionary, nil)
    guard storeStatus == errSecSuccess else {
      completion("❌ Failed to store token in Keychain (status \(storeStatus))")
      return
    }
    
    // 2. Now let's retrieve the token
    // Optional: you may provide a context with a localized reason.
    // See https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id#Provide-a-Prompt-When-Reading-the-Item
    // Keychain services will use LAContext to prompt the user even if you don't provide one.
    //
    // let context = LAContext()
    // context.localizedReason = "Access your token from the keychain"
    let fetchQuery: [String: Any] = [
      kSecClass as String:         kSecClassGenericPassword,
      kSecAttrAccount as String:   account,
      kSecReturnData as String:    true,
      kSecMatchLimit as String:    kSecMatchLimitOne,
      //kSecUseAuthenticationContext as String: context,
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
