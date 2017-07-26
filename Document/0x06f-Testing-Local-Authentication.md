## Testing Local Authentication in iOS Apps

During local authentication, an app authenticates the user against credentials stored locally on the device. In other words, the user "unlocks" the app or some inner layer of functionality by providing a valid PIN, password, or fingerprint, verified by referencing local data. Generally, this is done so that users can more conveniently resume an existing session with a remote service or as a means of step-up authentication to protect some critical function.

### Testing Local Authentication

#### Overview

On iOS, several methods are available for integrating local authentication into apps. The [Local Authentication framework](https://developer.apple.com/documentation/localauthentication "Local Authentication framework") provides a set of APIs for developers to extend an authentication dialog to a user. In the context of connecting to a remote service, it is possible (and recommended) to leverage the [Keychain ](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/iPhoneTasks/iPhoneTasks.html "KeyChain") for implementing local authentication.

Biometric authentication on iOS is represented by the Touch ID fingerprint sensing system. The Touch ID sensor is operated by the [SecureEnclave security coprocessor](Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang - http://mista.nu/research/sep-paper.pdf "") and does not expose fingerprint data to any other parts of the system. With activated Touch ID a password is required only in certain cases (after 5 unsuccessful attempts, if the device has been rebooted or was not unlocked in last 48 hours, etc), which should encourage the user to [set longer and more complex passwords](https://www.apple.com/business/docs/iOS_Security_Guide.pdf "Touch ID and passcodes").

Third-party apps have two ways to incorporate system-provided Touch ID authentication:
- `LocalAuthentication.framework` is a higher level API that can be used to authenticate the user via Touch ID. The app can't access any data associated with the enrolled fingerprint and is notified only whether authentication was successful.
- `Security.framework` is a lower level API to access [Keychain Services](https://developer.apple.com/documentation/security/keychain_services "Keychain Services"). This is a secure option if your app needs to protect some secret data with biometric authentication, since the access control is managed on a system-level and can not easily be bypassed. `Security.framework` has a C API, but there are several [open source wrappers available](https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id "How To Secure iOS User Data: The Keychain and Touch ID"), making access to the Keychain as simple as to NSUserDefaults. `Security.framework` underlies  `LocalAuthentication.framework`; Apple recommends to default to higher-level APIs whenever possible.

##### Local Authentication Framework

The Local Authentication framework provides facilities for requesting a passphrase or Touch ID authentication from users. Developers can display and utilize an authentication prompt with the function <code>evaluatePolicy</code> of the <code>LAContext</code> class.

Two available policies define acceptable forms of authentication:

- <code>LAPolicyDeviceOwnerAuthentication</code>: when available, the user is prompted to perform Touch ID authentication. If Touch ID is not activated, the device passcode is requested instead. If the device passcode is not enabled, policy evaluation fails.

- <code>LAPolicyDeviceOwnerAuthenticationWithBiometrics</code>: authentication is restricted to biometrics where the user is prompted for Touch ID.

The <code>evaluatePolicy</code> function returns a boolean value indicating whether the user has authenticated successfully.

An [example for Touch ID authentication using the Local Authentication Framework](https://developer.apple.com/documentation/localauthentication "LocalAuthentication Code Sample") is available in the official documentation from Apple.

#####  Using Keychain Services

The iOS Keychain APIs can (and should) be used to implement local authentication. During this process, the app requests either a secret authentication token or another piece of secret data stored in the Keychain to identify the user. In order to authenticate a remote service, the user must unlock the Keychain using their passphrase or fingerprint to obtain the secret data. A sample implementation can be found in the [official Apple documentation](https://developer.apple.com/library/content/samplecode/KeychainTouchID/Introduction/Intro.html "KeychainTouchID: Using Touch ID with Keychain and LocalAuthentication").

The Keychain mechanism is explained in greater detail in an earlier chapter, "Testing Data Storage".

#### Static Analysis

It is important to remember that the Local Authentication framework is an event-based procedure and as such, should not be the sole method of authentication. Though this type of authentication is effective on the user-interface level, it is easily bypassed through patching or instrumentation, as explained in the dynamic analysis section.

When testing local authentication on iOS, ensure sensitive flows are protected using the Keychain services method. For example, some apps resume an existing user session with Touch ID authentication. In these cases, session credentials or tokens (e.g. refresh tokens) should be securely stored in the Keychain (as described above) as well as "locked" with local authentication.


##### LocalAuthentication.framework

From developer's point of view, working with `LocalAuthentication.framework` is pretty straightforward: create an instance of `LAContext`, ensure that OS and device support the biometric authentication policy, evaluate policy with completion handler and explain why the user is requested to pass authentication right now.

`LAPolicy` has two options:
	- `deviceOwnerAuthentication`(Swift) or `LAPolicyDeviceOwnerAuthentication`(Objective-C) - using Touch ID or the device password
	- `deviceOwnerAuthenticationWithBiometrics` (Swift) or `LAPolicyDeviceOwnerAuthenticationWithBiometrics`(Objective-C) - use Touch ID only

An appropriate error will be returned to the completion handler in the following cases:
    - the authentication failed,
    - the user canceled authentication,
    - the user has chosen fallback,
    - the system canceled authentication,
    - a passcode is not set on the device,
    - Touch ID is not available,
    - Touch ID is not enrolled.

**Swift**

```
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

**Objective-C**

```
LAContext *myContext = [[LAContext alloc] init];
NSError *authError = nil;

if ([myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError]) {
    [myContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                  localizedReason:@"Please, pass authorisation to enter this area"
                            reply:^(BOOL success, NSError *error) {
            if (success) {
                // User authenticated successfully, take appropriate action
            } else {
                // User did not authenticate successfully, look at error and take appropriate action
            }
        }];
} else {
    // Could not evaluate policy; look at authError and present an appropriate message to user
}
```

##### Security.framework

The Keychain allows saving items with the special `SecAccessControl` attribute, which will allow access to the item from the Keychain only after the user will pass Touch ID authentication (or passcode, if such fallback is allowed by attribute parameters).

In the following example we will save the string "test_strong_password" to the Keychain. The string can be accessed only on the current device while the passcode is set (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` parameter) and after Touch ID authentication for the currently enrolled fingers only (`.touchIDCurrentSet parameter`):

**Swift**

```
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

```
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

```
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

```
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

```
$ otool -L <AppName>.app/<AppName>
```

If `LocalAuhentication.framework` is used in an app, the output will contain both of the following lines (remember that `LocalAuhentication.framework` uses `Security.framework` under the hood):

```
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

If `Security.framework` is used, only the second one will be shown.

#### Dynamic Analysis

When using an app the usage of Touch ID authentication is quite obvious: a system-style alert asks the user to put the finger on the sensor or fall back to the password (if allowed):

--TODO create screenshots

<img src="Images/Chapters/0x06f/biometric_auth.jpg" width="500px"/>
- *Touch ID authentication UI*

<img src="Images/Chapters/0x06f/biometric_auth_fallback_passcode.jpg" width="500px"/>
- *Touch ID authentication UI with fallback to passcode*

On a jailbroken device tools like [Swizzler2](https://github.com/vtky/Swizzler2 "Swizzler2") can be used to bypass LocalAuthentication, that will always sent back `True` to evaluatePolicy:

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

It is also possible to use [objection to bypass TouchID](https://github.com/sensepost/objection/wiki/Understanding-the-TouchID-Bypass "Understanding the TouchID Bypass") on a non-jailbroken device.

On a jailbroken device contents of Keychain can be dumped and items' parameters inspected.
-- TODO [Will items saved via `Security.framework` Access Control API have any specific parameter in Keychain db?]

#### Remediation

The Local Authentication framework makes adding either Touch ID or similar authentication a simple procedure. More sensitive processes, such as re-authenticating a user or using a remote payment service with this method, is strongly discouraged. Instead, the best approach for handling local authentication in these scenarios involves utilizing Keychain to store a user secret (e.g. refresh token). This may be accomplished as follows:

- Use the <code>SecAccessControlCreateWithFlags()</code> to call a security access control reference. Specify the <code>kSecAccessControlUserPresence</code> policy and <code>kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly</code> protection class.
- Insert the data using the returned <code>SecAccessControlRef</code> value into the attributes dictionary.

#### References

##### OWASP Mobile Top 10 2016

- M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

- V4.7: "Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore."

##### CWE

- CWE-287 - Improper Authentication
