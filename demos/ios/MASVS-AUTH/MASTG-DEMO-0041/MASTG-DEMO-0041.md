---
platform: ios
title: Uses of LAContext.evaluatePolicy with r2
id: MASTG-DEMO-0041
code: [swift]
test: MASTG-TEST-0266
---

### Sample

The following sample insecurely accesses sensitive resources, a secret token, **relying solely** on the LocalAuthentication API for access control instead of using the Keychain API and requiring user presence. It does so by using the `evaluatePolicy` method of the `LAContext` class to authenticate the user with biometrics (`deviceOwnerAuthenticationWithBiometrics`).

This method is weak because it depends on an if statement to check if the authentication was successful, which can be bypassed by an attacker using techniques such as @MASTG-TECH-0135.

{{ MastgTest.swift }}

### Steps

1. Unzip the app package and locate the main binary file (@MASTG-TECH-0058), which in this case is `./Payload/MASTestApp.app/MASTestApp`.
2. Run `run.sh`.

{{ insecureAuthenticationBiometricsApi.r2 }}

{{ run.sh }}

### Observation

{{ output.asm }}

The output reveals the use of `LAContext().evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: ...)` in the app. However, it doesn't look exactly the same as in `MastgTest.swift` because the compiler transforms some functions into Objective-C counterparts. An equivalent Objective-C representation in the binary looks like `objc_msgSend(void *address, "evaluatePolicy:localizedReason:", LAPolicyDeviceOwnerAuthenticationWithBiometrics, ...)`. By looking at the output we can find this pattern at lines 15-20.

The third argument of `objc_msgSend(...)` is `LAPolicyDeviceOwnerAuthenticationWithBiometrics` because `w2` register at the time of the function invocation is set to `1` with a `mov` instruction at Line 17. `1` is an [enum](https://developer.apple.com/documentation/localauthentication/lapolicy) representation of `LAPolicyDeviceOwnerAuthenticationWithBiometrics`.

You can find all the possible values defined in LAPublicDefines.h by running (requires @MASTG-TOOL-0070):

```sh
grep kLAPolicyDeviceOwnerAuthentication /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAPublicDefines.h

#define kLAPolicyDeviceOwnerAuthenticationWithBiometrics        1
#define kLAPolicyDeviceOwnerAuthentication                      2
#define kLAPolicyDeviceOwnerAuthenticationWithWatch             3
#define kLAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch 4
#define kLAPolicyDeviceOwnerAuthenticationWithWristDetection    5
#define kLAPolicyDeviceOwnerAuthenticationWithCompanion         kLAPolicyDeviceOwnerAuthenticationWithWatch
#define kLAPolicyDeviceOwnerAuthenticationWithBiometricsOrCompanion kLAPolicyDeviceOwnerAuthenticationWithBiometricsOrWatch
```

Or you can view the full LAPublicDefines.h header online in public SDK mirrors on GitHub such as [GitHub - xybp888/iOS-SDKs](https://github.com/xybp888/iOS-SDKs/blob/master/iPhoneOS18.4.sdk/System/Library/Frameworks/LocalAuthentication.framework/Headers/LAPublicDefines.h#L12-L18).

### Evaluation

The test fails because the output only shows references to biometric verification with LocalAuthentication API and no calls to any Keychain APIs requiring user presence (`SecAccessControlCreateWithFlags`).

This approach can be easily bypassed as shown in @MASTG-TECH-0119.
