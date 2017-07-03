## Testing Local Authentication in iOS Apps

Most of the authentication and session management requirements of the MASVS are generic ones, that do not rely on a specific implementation on iOS or Android.

As a result only requirement "4.6	Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore." is described in this chapter. All other test need to verify server side implementations and can be found in the Appendix "Testing Authentication".


### Testing Biometric Authentication

#### Overview

Biometric authentication on iOS is represented by the Touch ID fingerprint sensing system. Touch ID sensor is operated by the SecureEnclave<sup>[1]</sup> security coprocessor and do not expose fingerprint data to any other parts of the system. With Touch ID set up, password is required only in certain cases (after 5 unsuccessful attempts, if device has been rebooted or was not unlocked in last 48 hours, etc), which encourages the user to set longer and more complex passwords<sup>[2]</sup>.

Third-party apps have two ways to incorporate system-provided Touch ID authentication:
- `LocalAuthentication.framework`<sup>[3]</sup> is a higher level API that can be used to authenticate user via Touch ID. The app can’t access any data associated with the enrolled fingerprint and is notified only whether authentication passed successfully or not. Altho authentication is managed by system, make that your code is written in a hard-to-bypass way.
- `Security.framework`<sup>[4]</sup> is a lower level API to access Keychain Services. When saving the item to Keychain, `SecAccessControlCreateFlags` can be included into request to define when the item can be retrieved back: after `.devicePasscode` (`kSecAccessControlDevicePasscode`) will be entered, authentication via `.touchIDAny` (`kSecAccessControlTouchIDAny`) passed, `.userPresence` (`kSecAccessControlUserPresence`) verified via TouchID with possible fallback to device passcode, etc. This is a perfect option if your app needs to associate some secret data with biometric authentication, since access control is managed on a system-level and can not be bypassed to get stored data. `Security.framework` has C API, but there are dozens of open source wrappers making access to Keychain as simple as to NSUserDefaults<sup>[5]</sup>. `Security.framework` underlies  `LocalAuthentication.framework`; Apple recommends to default to higher-level APIs whenever possible.

#### Static Analysis
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

#### References
- [1] Demystifying the Secure Enclave Processor by Tarjei Mandt, Mathew Solnik, and David Wang - http://mista.nu/research/sep-paper.pdf
- [2] iOS Security Guide - https://www.apple.com/business/docs/iOS_Security_Guide.pdf
- [3] Local Authentication API Reference - https://developer.apple.com/reference/localauthentication
- [4] Security API Reference - https://developer.apple.com/documentation/security
- [5] How To Secure iOS User Data: The Keychain and Touch ID Tutorial - https://www.raywenderlich.com/147308/secure-ios-user-data-keychain-touch-id


##### OWASP Mobile Top 10 2016
* M4 - Insecure Authentication - https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication

##### OWASP MASVS
* 4.6: "Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore."

##### CWE

-- TODO [Add relevant CWE for "Testing Biometric Authentication"] --
- CWE-312 - Cleartext Storage of Sensitive Information

##### Info

- [1] Meyer's Recipe for Tomato Soup - http://www.finecooking.com/recipes/meyers-classic-tomato-soup.aspx
- [2] Another Informational Article - http://www.securityfans.com/informational_article.html

##### Tools

-- TODO [Add relevant tools for "Testing Biometric Authentication"] --
* Enjarify - https://github.com/google/enjarify
