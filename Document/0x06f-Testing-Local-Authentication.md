## Testing Local Authentication in iOS Apps

During local authentication, an app authenticates the user against credentials stored locally on the device. In other words, the user "unlocks" the app or some inner layer of functionality by providing a valid PIN, password, or fingerprint, verified by referencing local data. Generally, this is done so that users can more conveniently resume an existing session with a remote service or as a means of step-up authentication to protect some critical function.

### Testing Local Authentication

#### Overview

On iOS, two methods are available for integrating local authentication into apps. The [Local Authentication framework](https://developer.apple.com/documentation/localauthentication "Local Authentication API Reference") provides a set of APIs for developers to extend an authentication dialog to a user. In the context of connecting to a remote service, it is possible (and recommended) to leverage the [Keychain Services](https://developer.apple.com/library/content/samplecode/KeychainTouchID/Introduction/Intro.html "") for implementing local authentication.

The Local Authentication framework provides facilities for requesting a passphrase or TouchID authentication from users. Developers can display and utilize an authentication prompt by utilizing the function <code>evaluatePolicy</code> of the <code>LAContext</code> class.

Two available policies define acceptable forms of authentication:

- LAPolicyDeviceOwnerAuthentication: When available, the user is prompted to perform TouchID authentication. If TouchID is not activated, the device passcode is requested instead. If the device passcode is not enabled, policy evaluation fails.

- LAPolicyDeviceOwnerAuthenticationWithBiometrics: Authentication is restricted to biometrics where user the is prompted for TouchID.

The <code>evaluatePolicy</code> function returns a boolean value indicating whether the user has authenticated successfully.

```
let myContext = LAContext()
let myLocalizedReasonString = <#String explaining why app needs authentication#>

var authError: NSError? = nil
if #available(iOS 8.0, OSX 10.12, *) {
    if myContext.canEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, error: &authError) {
        myContext.evaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, localizedReason: myLocalizedReasonString) { (success, evaluateError) in
            if (success) {
                // User authenticated successfully, take appropriate action
            } else {
                // User did not authenticate successfully, look at error and take appropriate action
            }
        }
    } else {
        // Could not evaluate policy; look at authError and present an appropriate message to user
    }
} else {
    // Fallback on earlier versions
}
```
*TouchID authentication using the Local Authentication Framework (official code sample from Apple).*

#####  Using Keychain Services for Local Authentication

The iOS Keychain APIs can (and should) be used to implement local authentication. During this process, the app requests either a secret authentication token or another piece of secret data identifying the user stored by the Keychain. In order to authenticate a remote service, the user must unlock the Keychain using their passphrase or fingerprint to obtain the secret data.

The Keychain mechanism is explained in greater detail in an earlier chapter, "Testing Data Storage".



##### Local Authentication Framework

Biometric authentication on iOS is represented by the Touch ID fingerprint sensing system. Touch ID sensor is operated by the SecureEnclave<sup>[1]</sup> security coprocessor and do not expose fingerprint data to any other parts of the system. With Touch ID set up, password is required only in certain cases (after 5 unsuccessful attempts, if device has been rebooted or was not unlocked in last 48 hours, etc), which encourages the user to set longer and more complex passwords<sup>[2]</sup>.

Third-party apps have two ways to incorporate system-provided Touch ID authentication:
- `LocalAuthentication.framework`<sup>[3]</sup> is a higher level API that can be used to authenticate user via Touch ID. The app can’t access any data associated with the enrolled fingerprint and is notified only whether authentication passed successfully or not. Altho authentication is managed by system, make that your code is written in a hard-to-bypass way.
- `Security.framework`<sup>[4]</sup> is a lower level API to access Keychain Services. When saving the item to Keychain, `SecAccessControlCreateFlags` can be included into request to define when the item can be retrieved back: after `.devicePasscode` (`kSecAccessControlDevicePasscode`) will be entered, authentication via `.touchIDAny` (`kSecAccessControlTouchIDAny`) passed, `.userPresence` (`kSecAccessControlUserPresence`) verified via TouchID with possible fallback to device passcode, etc. This is a perfect option if your app needs to associate some secret data with biometric authentication, since access control is managed on a system-level and can not be bypassed to get stored data. `Security.framework` has C API, but there are dozens of open source wrappers making access to Keychain as simple as to NSUserDefaults<sup>[5]</sup>. `Security.framework` underlies  `LocalAuthentication.framework`; Apple recommends to default to higher-level APIs whenever possible.

#### Static Analysis

It is important to remember that Local Authentication framework is an event-based procedure and as such, should not the sole method of authentication. Though this type of authentication is effective on the user-interface level, it is easily bypassed through patching or instrumentation.

When testing local authentication on iOS, ensure sensitive flows are protected using the Keychain services method. For example, some apps resume an existing user session with TouchID authentication. In these cases, session credentials or tokens (e.g. refresh tokens) should be securely stored in the Keychain (as described above) as well as "locked" with local authentication.


##### LocalAuthentication.framework
From developer's point of view, work with `LocalAuthentication.framework` is pretty straightforward: create instance of `LAContext`, ensure that OS and device support biometric authentication policy, evaluate policy with completion handler and title string explaining to user why she is requested to pass authentication right now.
`LAPolicy` has two options:
	- `deviceOwnerAuthentication`(Swift) or `LAPolicyDeviceOwnerAuthentication`(Objective-C) - using Touch ID or the device password
	- `deviceOwnerAuthenticationWithBiometrics` (Swift) or `LAPolicyDeviceOwnerAuthenticationWithBiometrics`(Objective-C) - use Touch ID only

Appropriate error will be returned to completion handler in following cases: authentication failed, user cancelled authentication, user have chosen fallback, system cancelled authentication, passcode is not set on device, TouchID is not available, TouchID is not enrolled.

###### Swift
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

###### Objective-C
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
Keychain allows to save items with special SecAccessControl attribute, which will allow to get item from Keychain only after user will pass Touch ID authentication (or passcode, if such fallback is allowed by attribute parameters).



In following example we will save "S00p3r_haCk3r_strong_password" string to Keychain which can be accessed only on current device while passcode is set (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` parameter) after Touch ID authentication for currently enrolled fingers only (`.touchIDCurrentSet parameter`):
###### Swift
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
query[kSecValueData as String] = "S00p3r_haCk3r_strong_password".data(using: .utf8)! as CFData
query[kSecAttrAccessControl as String] = accessControl

// 3. save item

let status = SecItemAdd(query as CFDictionary, nil)

if status == noErr {
	// successfully saved
} else {
	// error while saving
}
```
###### Objective-C
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
	(__bridge id)kSecValueData: [@"S00p3r_haCk3r_strong_password" dataUsingEncoding:NSUTF8StringEncoding],
	(__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacRef };

// 3. save item
OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, nil);

if (status == noErr) {
	// successfully saved
} else {
	// error while saving
}
```
Now we can request saved item from Keychain:  Keychain Services will present authentication dialog to the user and return data or nil depending on whether suitable fingerprint was provided. Optionally, prompt string can be specified.
###### Swift
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
###### Objective-C
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


Usage of frameworks in app can also be detected by analyzing app binary's list of shared dynamic libraries by running:
 `$ otool -L <AppName>.app/<AppName>`

If `LocalAuhentication.framework` was used in app, output will contain both of following lines (remember that `LocalAuhentication.framework` uses `Security.framework` under the hood), if `Security.framework` - only second one:
```
/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication
/System/Library/Frameworks/Security.framework/Security
```

#### Dynamic Analysis

On a running app usage of TouchID authentication is quite obvious: at appropriate moment system-style alert asks user to put her finger on sensor or fallback to password (if allowed):
![TouchID authentication UI](/Images/Chapters/0x6f/biometric_auth_try_again.jpg)
![TouchID authentication UI with fallback to passcode](/Images/Chapters/0x6f/biometric_auth_try_again.jpg)

On a jailbroken device contents of Keychain can be dumped and items' parameters inspected.
-- TODO [Will items saved via `Security.framework` Access Control API have any specific parameter in Keychain db?]

If a potential local authentication bypass issue is discovered, it is likely exploitable by patching the app or using <code>Cycript</code> to instrument the process. This is explained in greater detail in the "Reverse Engineering and Tampering" chapter.



#### Remediation

The Local Authentication framework makes adding either TouchID or similar authentication a simple procedure. More sensitive processes, such as re-authenticating a user using a remote payment service with this method, is strongly discouraged. Instead, the best approach for handling local authentication in these scenarios involves utilizing Keychain to store a user secret (e.g. refresh token). This may be accomplished as follows:

- Use the <code>SecAccessControlCreateWithFlags()</code> to call a security access control reference. Specify the <code>kSecAccessControlUserPresence</code> policy and <code>kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly</code> protection class.


- Insert the data using the returned <code>SecAccessControlRef</code> value into the attributes dictionary.


#### References

##### OWASP Mobile Top 10 2016

- M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS

- V4.7: "Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore."

##### CWE

- CWE-287 - Improper Authentication

##### Info

- [1] Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang - http://mista.nu/research/sep-paper.pdf
- [2] iOS Security Guide - https://www.apple.com/business/docs/iOS_Security_Guide.pdf

- [4] Security API Reference - https://developer.apple.com/documentation/security
- [5] How To Secure iOS User Data: The Keychain and Touch ID Tutorial - https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id
