---
masvs_category: MASVS-AUTH
platform: ios
title: Keychain Services
---

The iOS keychain APIs can (and should) be used to implement local authentication. During this process, the app stores either a secret authentication token or another piece of secret data identifying the user in the keychain. In order to authenticate to a remote service, the user must unlock the keychain using their passphrase or fingerprint to obtain the secret data.

The keychain allows saving items with the special `SecAccessControl` attribute, which will allow access to the item from the keychain only after the user has passed Touch ID authentication (or passcode, if such a fallback is allowed by attribute parameters).

> **Note regarding temporariness of keys in the Keychain:**
> Unlike macOS and Android, iOS does not support temporariness of an item's accessibility in the keychain: when there is no additional security check when entering the keychain (e.g. `kSecAccessControlUserPresence` or similar is set), then once the device is unlocked, a key will be accessible.

In the following example we will save the string "test_strong_password" to the keychain. The string can be accessed only on the current device while the passcode is set (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` parameter) and after Touch ID authentication for the currently enrolled fingers only (`SecAccessControlCreateFlags.biometryCurrentSet` parameter):

```swift
// 1. Create the AccessControl object that will represent authentication settings

var error: Unmanaged<CFError>?

guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                          kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                          SecAccessControlCreateFlags.biometryCurrentSet,
                                                          &error) else {
    // failed to create AccessControl object

    return
}

// 2. Create the keychain services query. Pay attention that kSecAttrAccessControl is mutually exclusive with kSecAttrAccessible attribute

var query: [String: Any] = [:]

query[kSecClass as String] = kSecClassGenericPassword
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecAttrAccount as String] = "OWASP Account" as CFString
query[kSecValueData as String] = "test_strong_password".data(using: .utf8)! as CFData
query[kSecAttrAccessControl as String] = accessControl

// 3. Save the item

let status = SecItemAdd(query as CFDictionary, nil)

if status == noErr {
    // successfully saved
} else {
    // error while saving
}

// 4. Now we can request the saved item from the keychain. Keychain services will present the authentication dialog to the user and return data or nil depending on whether a suitable fingerprint was provided or not.

// 5. Create the query
var query = [String: Any]()
query[kSecClass as String] = kSecClassGenericPassword
query[kSecReturnData as String] = kCFBooleanTrue
query[kSecAttrAccount as String] = "My Name" as CFString
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecUseOperationPrompt as String] = "Please, pass authorisation to enter this area" as CFString

// 6. Get the item
var queryResult: AnyObject?
let status = withUnsafeMutablePointer(to: &queryResult) {
    SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
}

if status == noErr {
    let password = String(data: queryResult as! Data, encoding: .utf8)!
    // successfully received password
} else {
    // authorization not passed
}
```
