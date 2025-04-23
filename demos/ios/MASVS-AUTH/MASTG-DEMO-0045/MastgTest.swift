import SwiftUI
import LocalAuthentication

struct MastgTest {
  
  static let ACCOUNT_NAME = "token"
  static let SERVICE_NAME = "com.app"
  
  static func mastgTest(completion: @escaping (String) -> Void) {
    if storeTokenInKeychain(secretToken: "S3CU4E T0K3N") == false{
      completion("Failed to store in keychain")
      return
    }
    if let token = getTokenFromKeychain(){
      completion("Retrieved token from Keychain: \(token)")
    }
    else{
      completion("Empty keychain")
    }
  }
  
  static func createAccessControl() -> SecAccessControl? {
      var error: Unmanaged<CFError>?
    
      let accessControlFlags: SecAccessControlCreateFlags = [.biometryCurrentSet]
      let protectionClass:AnyObject! = kSecAttrAccessibleWhenUnlocked

      if let accessControl = SecAccessControlCreateWithFlags(nil, protectionClass, accessControlFlags, &error) {
          return accessControl
      } else {
          if let error = error {
              let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String
              print("Failed to create SecAccessControl object: \(errorDescription)")
          } else {
              print("Unknown error")
          }
          return nil
      }
  }


  
  static func storeTokenInKeychain(secretToken: String) -> Bool {
      guard let accessControl = createAccessControl() else {
          print("Failed to create SecAccessControl object")
          return false
      }

      let userDetails: [String: Any] = [
           kSecClass as String: kSecClassGenericPassword,
           kSecAttrAccount as String: ACCOUNT_NAME,
           kSecAttrService as String: SERVICE_NAME,
           kSecValueData as String: secretToken.data(using: .utf8)!,
           kSecAttrAccessControl as String: accessControl
       ]

      let addStatus = SecItemAdd(userDetails as CFDictionary, nil)
      switch addStatus {
      case errSecSuccess:
        return true;
      case errSecDuplicateItem:
        // For this sample, it's enough to have any item
        // in the keychain, so we return true as a success
        return true
      default:
        return false
      }
  }
  
  static func getTokenFromKeychain() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: ACCOUNT_NAME,
            kSecAttrService as String: SERVICE_NAME,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess {
            if let passwordData = item as? Data,
               let password = String(data: passwordData, encoding: .utf8) {
                return password
            }
        } else {
            print("Can't retrieve data from keychain: \(status)")
        }
        return nil
    }
}
