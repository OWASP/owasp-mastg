## Local Authentication on iOS

During local authentication, an app authenticates the user against credentials stored locally on the device. In other words, the user "unlocks" the app or some inner layer of functionality by providing a valid PIN, password, face-recognition or fingerprint, verified by referencing local data. Generally, this done so that users can more conveniently resume an existing session with a remote service or as a means of step-up authentication to protect some critical function.

As stated before in chapter "[Mobile App Authentication Architectures](0x04e-Testing-Authentication-and-Session-Management.md)": the tester should be aware that local authentication should always be enforced at a remote endpoint or based on a cryptographic primitive. Attackers can easily bypass local authentication if no data returns from the authentication process.

### Testing Local Authentication (MSTG-AUTH-8 and MSTG-STORAGE-11)

On iOS, a variety of methods are available for integrating local authentication into apps. The [Local Authentication framework](https://developer.apple.com/documentation/localauthentication "Local Authentication framework") provides a set of APIs for developers to extend an authentication dialog to a user. In the context of connecting to a remote service, it is possible (and recommended) to leverage the [keychain](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html "Keychain Services") for implementing local authentication.

Fingerprint authentication on iOS is known as *Touch ID*. The fingerprint ID sensor is operated by the [SecureEnclave security coprocessor](http://mista.nu/research/sep-paper.pdf "Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang") and does not expose fingerprint data to any other parts of the system. Next to Touch ID, Apple introduced *Face ID*: which allows authentication based on facial recognition. Both use similar APIs on an application level, the actual method of storing the data and retrieving the data (e.g. facial data or fingerprint related data is different).

Developers have two options for incorporating Touch ID/Face ID authentication:

- `LocalAuthentication.framework` is a high-level API that can be used to authenticate the user via Touch ID. The app can't access any data associated with the enrolled fingerprint and is notified only whether authentication was successful.
- `Security.framework` is a lower level API to access [keychain services](https://developer.apple.com/documentation/security/keychain_services "keychain Services"). This is a secure option if your app needs to protect some secret data with biometric authentication, since the access control is managed on a system-level and can not easily be bypassed. `Security.framework` has a C API, but there are several [open source wrappers available](https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id "How To Secure iOS User Data: The keychain and Touch ID"), making access to the keychain as simple as to NSUserDefaults. `Security.framework` underlies  `LocalAuthentication.framework`; Apple recommends to default to higher-level APIs whenever possible.

Please be aware that using either the `LocalAuthentication.framework` or the `Security.framework`, will be a control that can be bypassed by an attacker as it does only return a boolean and no data to proceed with. See [Don't touch me that way, by David Lindner et al](https://www.youtube.com/watch?v=XhXIHVGCFFM "Don't Touch Me That Way - David Lindner") for more details.

#### Local Authentication Framework

The Local Authentication framework provides facilities for requesting a passphrase or Touch ID authentication from users. Developers can display and utilize an authentication prompt by utilizing the function `evaluatePolicy` of the `LAContext` class.

Two available policies define acceptable forms of authentication:

- `deviceOwnerAuthentication`(Swift) or `LAPolicyDeviceOwnerAuthentication`(Objective-C): When available, the user is prompted to perform Touch ID authentication. If Touch ID is not activated, the device passcode is requested instead. If the device passcode is not enabled, policy evaluation fails.

- `deviceOwnerAuthenticationWithBiometrics` (Swift) or `LAPolicyDeviceOwnerAuthenticationWithBiometrics`(Objective-C): Authentication is restricted to biometrics where the user is prompted for Touch ID.

The `evaluatePolicy` function returns a boolean value indicating whether the user has authenticated successfully.

The Apple Developer website offers code samples for both [Swift](https://developer.apple.com/documentation/localauthentication "LocalAuthentication") and [Objective-C](https://developer.apple.com/documentation/localauthentication?language=objc "LocalAuthentication"). A typical implementation in Swift looks as follows.

```swift
let context = LAContext()
var error: NSError?

guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
    // Could not evaluate policy; look at error and present an appropriate message to user
}

context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Please, pass authorization to enter this area") { success, evaluationError in
    guard success else {
        // User did not authenticate successfully, look at evaluationError and take appropriate action
    }

    // User authenticated successfully, take appropriate action
}
```

*Touch ID authentication in Swift using the Local Authentication Framework (official code sample from Apple).*

#### Using Keychain Services for Local Authentication

The iOS keychain APIs can (and should) be used to implement local authentication. During this process, the app stores either a secret authentication token or another piece of secret data identifying the user in the keychain. In order to authenticate to a remote service, the user must unlock the keychain using their passphrase or fingerprint to obtain the secret data.

The keychain allows saving items with the special `SecAccessControl` attribute, which will allow access to the item from the keychain only after the user has passed Touch ID authentication (or passcode, if such a fallback is allowed by attribute parameters).

In the following example we will save the string "test_strong_password" to the keychain. The string can be accessed only on the current device while the passcode is set (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` parameter) and after Touch ID authentication for the currently enrolled fingers only (`SecAccessControlCreateFlags.biometryCurrentSet` parameter):

##### Swift

```swift
// 1. create AccessControl object that will represent authentication settings

var error: Unmanaged<CFError>?

guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                          kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                          SecAccessControlCreateFlags.biometryCurrentSet,
                                                          &error) else {
    // failed to create AccessControl object

    return
}

// 2. define keychain services query. Pay attention that kSecAttrAccessControl is mutually exclusive with kSecAttrAccessible attribute

var query: [String: Any] = [:]

query[kSecClass as String] = kSecClassGenericPassword
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecAttrAccount as String] = "OWASP Account" as CFString
query[kSecValueData as String] = "test_strong_password".data(using: .utf8)! as CFData
query[kSecAttrAccessControl as String] = accessControl

// 3. save item

let status = SecItemAdd(query as CFDictionary, nil)

if status == noErr {
    // successfully saved
} else {
    // error while saving
}
```

##### Objective-C

```objc

    // 1. create AccessControl object that will represent authentication settings
    CFErrorRef *err = nil;

    SecAccessControlRef sacRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        kSecAccessControlUserPresence,
        err);

    // 2. define keychain services query. Pay attention that kSecAttrAccessControl is mutually exclusive with kSecAttrAccessible attribute
    NSDictionary* query = @{
        (_ _bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrLabel: @"com.me.myapp.password",
        (__bridge id)kSecAttrAccount: @"OWASP Account",
        (__bridge id)kSecValueData: [@"test_strong_password" dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacRef
    };

    // 3. save item
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, nil);

    if (status == noErr) {
        // successfully saved
    } else {
        // error while saving
    }
```

Now we can request the saved item from the keychain. Keychain services will present the authentication dialog to the user and return data or nil depending on whether a suitable fingerprint was provided or not.

##### Swift

```swift
// 1. define query
var query = [String: Any]()
query[kSecClass as String] = kSecClassGenericPassword
query[kSecReturnData as String] = kCFBooleanTrue
query[kSecAttrAccount as String] = "My Name" as CFString
query[kSecAttrLabel as String] = "com.me.myapp.password" as CFString
query[kSecUseOperationPrompt as String] = "Please, pass authorisation to enter this area" as CFString

// 2. get item
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

##### Objective-C

```objc
// 1. define query
NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecReturnData: @YES,
    (__bridge id)kSecAttrAccount: @"My Name1",
    (__bridge id)kSecAttrLabel: @"com.me.myapp.password",
    (__bridge id)kSecUseOperationPrompt: @"Please, pass authorisation to enter this area" };

// 2. get item
CFTypeRef queryResult = NULL;
OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &queryResult);

if (status == noErr){
    NSData* resultData = ( __bridge_transfer NSData* )queryResult;
    NSString* password = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    NSLog(@"%@", password);
} else {
    NSLog(@"Something went wrong");
}
```

Usage of frameworks in an app can also be detected by analyzing the app binary's list of shared dynamic libraries. This can be done by using otool:

```shell
$ otool -L <AppName>.app/<AppName>
```

If `LocalAuthentication.framework` is used in an app, the output will contain both of the following lines (remember that `LocalAuthentication.framework` uses `Security.framework` under the hood):

```shell
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

If `Security.framework` is used, only the second one will be shown.

#### Static Analysis

It is important to remember that the LocalAuthentication framework is an event-based procedure and as such, should not be the sole method of authentication. Though this type of authentication is effective on the user-interface level, it is easily bypassed through patching or instrumentation. Therefore, it is best to use the keychain service method, which means you should:

- Verify that sensitive processes, such as re-authenticating a user performing a payment transaction, are protected using the keychain services method.
- Verify that access control flags are set for the keychain item which ensure that the keychain item its data can only be unlocked by means of authenticating the user. This can be with one of the following flags:
  - `kSecAccessControlBiometryCurrentSet` (before iOS 11.3 `kSecAccessControlTouchIDCurrentSet`). This will make sure that a user needs to authenticate with biometrics (e.g. Face ID or Touch ID) before accessing the data in the keychain item. Whenever the user adds a fingerprint or facial representation to the device, it will automatically invalidate the entry in the Keychain. This makes sure that the keychain item can only ever be unlocked by users that were enrolled when the item was added to the keychain.
  - `kSecAccessControlBiometryAny` (before iOS 11.3 `kSecAccessControlTouchIDAny`). This will make sure that a user needs to authenticate with biometrics (e.g. Face ID or Touch ID) before accessing the data in the Keychain entry. The Keychain entry will survive any (re-)enroling of new fingerprints or facial representation. This can be very practical if the user has a changing fingerprint. However, it also means that attackers, who are somehow able to enrole their fingerprints or facial representations to the device, can now access those entries as well.
  - `kSecAccessControlUserPresence` can be used as an alternative. This will allow the user to authenticate himself through a passcode if the biometric authentication no longer works. This is considered to be weaker than `kSecAccessControlBiometryAny` since it is much easier to steal someone's passcode entry by means of shouldersurfing, than it is to bypass the Touch ID or Face ID service.
- In order to make sure that biometrics can be used, verify that the `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` or the `kSecAttrAccessibleWhenPasscodeSet` protection class is set when the `SecAccessControlCreateWithFlags` method is called. Note that the `...ThisDeviceOnly` variant will make sure that the keychain item is not synchronized with other iOS devices.

> Note, a data protection class specifies the access methodology used to secure the data. Each class uses different policies to determine when the data
is accessible.

#### Dynamic Analysis

On a jailbroken device tools like [Swizzler2](https://github.com/vtky/Swizzler2 "Swizzler2") and [Needle](https://github.com/mwrlabs/needle "Needle") can be used to bypass LocalAuthentication. Both tools use Frida to instrument the `evaluatePolicy` function so that it returns `True` even if authentication was not successfully performed. Follow the steps below to activate this feature in Swizzler2:

- **Settings** -> **Swizzler**
- Enable **Inject Swizzler into Apps**
- Enable **Log Everything to Syslog**
- Enable **Log Everything to File**
- Enter the submenu **iOS Frameworks**
- Enable **LocalAuthentication**
- Enter the submenu **Select Target Apps**
- Enable the target app
- Close the app and start it again
- When the Touch ID prompt shows click **cancel**
- If the application flow continues without requiring the Touch ID then the bypass has worked.

If you're using Needle, run the `hooking/frida/script_touch-id-bypass` module and follow the prompts. This will spawn the application and instrument the `evaluatePolicy` function. When prompted to authenticate via Touch ID, tap cancel. If the application flow continues, then you have successfully bypassed Touch ID. A similar module (hooking/cycript/cycript_touchid) that uses Cycript instead of Frida is also available in Needle.

Alternatively, you can use [objection to bypass Touch ID](https://github.com/sensepost/objection/wiki/Understanding-the-Touch-ID-Bypass "Understanding the Touch ID Bypass") (this also works on a non-jailbroken device), patch the app, or use Cycript or similar tools to instrument the process.

Needle can be used to bypass insecure biometric authentication in iOS platforms. Needle utilizes Frida to bypass login forms developed using `LocalAuthentication.framework` APIs. The following module can be used to test for insecure biometric authentication:

```shell
[needle][container] > use hooking/frida/script_touch-id-bypass
[needle][script_touch-id-bypass] > run
```

If vulnerable, the module will automatically bypass the login form.

### Note regarding temporariness of keys in the Keychain

Unlike macOS and Android, iOS currently (at iOS 12) does not support temporariness of an item's accessibility in the keychain: when there is no additional security check when entering the keychain (e.g. `kSecAccessControlUserPresence` or similar is set), then once the device is unlocked, a key will be accessible.

### References

#### OWASP Mobile Top 10 2016

- M4 - Insecure Authentication - <https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication>

#### OWASP MASVS

- MSTG-AUTH-8: "Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore."
- MSTG-STORAGE-11: "The app enforces a minimum device-access-security policy, such as requiring the user to set a device passcode."

#### CWE

- CWE-287 - Improper Authentication - <https://cwe.mitre.org/data/definitions/287.html>
