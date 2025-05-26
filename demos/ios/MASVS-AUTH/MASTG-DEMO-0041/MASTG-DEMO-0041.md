---
platform: ios
title: Uses of LAContext.evaluatePolicy with r2
id: MASTG-DEMO-0041
code: [swift]
test: MASTG-TEST-0266
---

### Sample

The following sample insecurely accesses sensitive resources, a secret token, **relying solely** on the LocalAuthentication API for access control instead of using the Keychain API and requiring user presence. It does so by using the `evaluatePolicy` method of the `LAContext` class to authenticate the user with biometrics (`deviceOwnerAuthenticationWithBiometrics`).

This method is weak because it depends on an if statement to check if the authentication was successful, which can be bypassed by an attacker using Frida or similar tools.

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

### Evaluation

The test fails because the output only shows references to biometric verification with LocalAuthentication API and no calls to any Keychain APIs requiring user presence.

This approach can be easily bypassed as shown in @MASTG-TECH-0119.
