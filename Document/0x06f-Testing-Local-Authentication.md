## Local Authentication on iOS

During local authentication, an app authenticates the user against credentials stored locally on the device. In other words, the user "unlocks" the app or some inner layer of functionality by providing a valid PIN, password, or fingerprint, verified by referencing local data. Generally, this done so that users can more conveniently resume an existing session with a remote service or as a means of step-up authentication to protect some critical function.

### Testing Local Authentication

On iOS, a variety of methods are available for integrating local authentication into apps. The [Local Authentication framework](https://developer.apple.com/documentation/localauthentication) provides a set of APIs for developers to extend an authentication dialog to a user. In the context of connecting to a remote service, it is possible (and recommended) to leverage the [Keychain]( https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html) for implementing local authentication.

Fingerprint authentication on iOS is known as *Touch ID*. The fingerprint ID sensor is operated by the [SecureEnclave security coprocessor](http://mista.nu/research/sep-paper.pdf "Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang") and does not expose fingerprint data to any other parts of the system. 

Developers have two options for incorporating Touch ID authentication:

- `LocalAuthentication.framework` is a high-level API that can be used to authenticate the user via Touch ID. The app can't access any data associated with the enrolled fingerprint and is notified only whether authentication was successful.
- `Security.framework` is a lower level API to access [Keychain Services](https://developer.apple.com/documentation/security/keychain_services "Keychain Services"). This is a secure option if your app needs to protect some secret data with biometric authentication, since the access control is managed on a system-level and can not easily be bypassed. `Security.framework` has a C API, but there are several [open source wrappers available](https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id "How To Secure iOS User Data: The Keychain and Touch ID"), making access to the Keychain as simple as to NSUserDefaults. `Security.framework` underlies  `LocalAuthentication.framework`; Apple recommends to default to higher-level APIs whenever possible.

##### Local Authentication Framework

The Local Authentication framework provides facilities for requesting a passphrase or TouchID authentication from users. Developers can display and utilize an authentication prompt by utilizing the function `evaluatePolicy` of the `LAContext` class. 

Two available policies define acceptable forms of authentication:

- `deviceOwnerAuthentication`(Swift) or `LAPolicyDeviceOwnerAuthentication`(Objective-C): When available, the user is prompted to perform TouchID authentication. If TouchID is not activated, the device passcode is requested instead. If the device passcode is not enabled, policy evaluation fails.

- `deviceOwnerAuthenticationWithBiometrics` (Swift) or `LAPolicyDeviceOwnerAuthenticationWithBiometrics`(Objective-C): Authentication is restricted to biometrics where the user is prompted for TouchID.

The `evaluatePolicy` function returns a boolean value indicating whether the user has authenticated successfully.

The Apple Developer website offers code samples for both [Swift](https://developer.apple.com/documentation/localauthentication) and [Objective-C](https://developer.apple.com/documentation/localauthentication?language=objc). A typical implementation in Swift looks as follows.

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
*TouchID authentication in Swift using the Local Authentication Framework (official code sample from Apple).*

#####  Using Keychain Services for Local Authentication

The iOS Keychain APIs can (and should) be used to implement local authentication. During this process, the app stores either a secret authentication token or another piece of secret data identifying the user in the Keychain. In order to authenticate to a remote service, the user must unlock the Keychain using their passphrase or fingerprint to obtain the secret data. 

The Keychain allows saving items with the special `SecAccessControl` attribute, which will allow access to the item from the Keychain only after the user has passed Touch ID authentication (or passcode, if such fallback is allowed by attribute parameters).

In the following example we will save the string "test_strong_password" to the Keychain. The string can be accessed only on the current device while the passcode is set (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` parameter) and after Touch ID authentication for the currently enrolled fingers only (`.touchIDCurrentSet parameter`):

**Swift**

```swift
// 1. create AccessControl object that will represent authentication settings

var error: Unmanaged<CFError>?

guard let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
	kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
	.touchIDCurrentSet,
	&error) else {
    // failed to create AccessControl object
}

// 2. define Keychain services query. Pay attention that kSecAttrAccessControl is mutually exclusive with kSecAttrAccessible attribute

var query: Dictionary<String, Any> = [:]

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

**Objective-C**

```objective-c
// 1. create AccessControl object that will represent authentication settings
CFErrorRef *err = nil;

SecAccessControlRef sacRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
	kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
	kSecAccessControlUserPresence,
	err);

// 2. define Keychain services query. Pay attention that kSecAttrAccessControl is mutually exclusive with kSecAttrAccessible attribute
NSDictionary *query = @{ (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
	(__bridge id)kSecAttrLabel: @"com.me.myapp.password",
	(__bridge id)kSecAttrAccount: @"OWASP Account",
	(__bridge id)kSecValueData: [@"test_strong_password" dataUsingEncoding:NSUTF8StringEncoding],
	(__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacRef };

// 3. save item
OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, nil);

if (status == noErr) {
	// successfully saved
} else {
	// error while saving
}
```

Now we can request the saved item from the Keychain. Keychain Services will present the authentication dialog to the user and return data or nil depending on whether a suitable fingerprint was provided or not.

**Swift**

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

**Objective-C**

```objective-c
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
    NSData *resultData = ( __bridge_transfer NSData *)queryResult;
    NSString *password = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
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

```
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

If `Security.framework` is used, only the second one will be shown.

#### Static Analysis

It is important to remember that Local Authentication framework is an event-based procedure and as such, should not the sole method of authentication. Though this type of authentication is effective on the user-interface level, it is easily bypassed through patching or instrumentation.

- Verify that sensitive processes, such as re-authenticating a user triggering a payment transaction, are protected using the Keychain services method.
- Verify that the `kSecAccessControlUserPresence` policy and `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` protection classes are set when the `SecAccessControlCreateWithFlags` method is called.

#### Dynamic Analysis

On a jailbroken device tools like [Swizzler2](https://github.com/vtky/Swizzler2 "Swizzler2") and [Needle](https://github.com/mwrlabs/needle "Needle") can be used to bypass LocalAuthentication. Both tools use Frida to instrument the `evaluatePolicy` function so that it returns `True` even if authentication was not successfully performed. Follow the steps below to activate this feature in Swizzler2:

- Settings->Swizzler
- Enable "Inject Swizzler into Apps"
- Enable "Log Everything to Syslog"
- Enable "Log Everything to File"
- Enter the submenu "iOS Frameworks"
- Enable "LocalAuthentication"
- Enter the submenu "Select Target Apps"
- Enable the target app
- Close the app and start it again
- When the TouchID prompt shows click "cancel"
- If the application flow continues without requiring the touchID then the bypass has worked.

If you're using Needle, run the "hooking/frida/script_touch-id-bypass" module and follow the prompts. This will spawn the application and instrument the `evaluatePolicy` function. When prompted to authenticate via Touch ID, tap cancel. If the application flow continues, then you have successfully bypassed Touch ID. A similar module (hooking/cycript/cycript_touchid) that uses cycript instead of frida is also available in Needle.

Alternatively, you can use [objection to bypass TouchID](https://github.com/sensepost/objection/wiki/Understanding-the-TouchID-Bypass "Understanding the TouchID Bypass") (this also works on a non-jailbroken device), patch the app, or use Cycript or similar tools to instrument the process.

Needle can be used to bypass insecure biometric authentication in iOS platforns. Needle utilizes frida to bypass login forms developed using `LocalAuthentication.framework` APIs. The following module can be used to test for insecure biometric authentication:

```
[needle][container] > use hooking/frida/script_touch-id-bypass
[needle][script_touch-id-bypass] > run
```

If vulnerable, the module will automatically bypass the login form.

### References

#### OWASP Mobile Top 10 2016

- M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

#### OWASP MASVS

- V4.7: "Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore."

#### CWE

- CWE-287 - Improper Authentication
