---
platform: android
title: References to APIs for Detecting Secure Lock Screen
id: MASTG-TEST-0242
apis: [KeyguardManager, BiometricManager#canAuthenticate]
type: [static]
weakness: MASWE-0008
best-practices: []
---

## Overview

This test verifies whether an app is running on a device with a passcode set. Android apps can determine whether a secure lock screen (such as PIN, pattern, or password) is enabled by using platform-provided APIs. Specifically, apps can utilize the `KeyguardManager` API, which provides the `isDeviceSecure()` and `isKeyguardSecure()` methods to check if the device has a secure lock mechanism in place.  

Additionally, apps can use the `BiometricManager#canAuthenticate(int)` API to check whether biometric authentication is available and can be used. Since biometric authentication on Android requires a secure lock screen as a fallback, this method can serve as an alternative check when `KeyguardManager` is unavailable or restricted by device manufacturers.  

If an app relies on biometrics for authentication, it should ensure that biometric authentication is enforced using the `BiometricPrompt` API or by requiring authentication for cryptographic key access via the **Android KeyStore System**. However, apps **cannot force** users to enable biometrics at the system level, only enforce its use within the app for accessing sensitive functionality.

## Steps

1. Use @MASTG-TOOL-0110 to identify the API that checks whether a secure lock screen has been set.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use any API to verify the secure lock screen presence.
