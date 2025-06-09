---
platform: ios
title: References to APIs for Detecting Secure Screen Lock
id: MASTG-TEST-0248
apis: [LAContext.canEvaluatePolicy, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly]
type: [static]
weakness: MASWE-0008
best-practices: []
profiles: [L2]
---

## Overview

This test verifies that an app is running on a device with a secure [screen lock (e.g. a passcode)](https://support.apple.com/en-us/guide/iphone/iph14a867ae/ios).

On iOS, apps can determine whether a secure screen lock is set using the **LocalAuthentication** framework. Specifically, the [LAContext.canEvaluatePolicy(_:error:)](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)) method with the [.deviceOwnerAuthentication](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication) or [.deviceOwnerAuthenticationWithBiometrics](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics) policy can be used to check if authentication mechanisms, including a passcode, are available.

Apps leveraging the **Keychain Services API** can require passcode authentication before accessing sensitive data using the [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) attribute.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary and look for uses of [LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)) API, or data stored with [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) attribute.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use any API to verify the secure screen lock presence.
