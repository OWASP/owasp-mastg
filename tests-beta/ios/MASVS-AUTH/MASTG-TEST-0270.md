---
platform: ios
title: References to APIs Detecting Biometric Enrollment Changes
id: MASTG-TEST-0270
apis: [kSecAccessControlBiometryCurrentSet,SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0046
---

## Overview

This test verifies that an app detects a change in biometric enrollment. For example, an app may require a biometric authentication to perform a sensitive operation. An attacker who has obtained the user's passcode can add a new fingerprint in the system settings and authenticate in the app. `kSecAccessControlBiometryCurrentSet` flag enables the app to invalidate an the entry in the Keychain when a user adds a fingerprint or facial representation to the device. This makes sure that the keychain item can only ever be unlocked by users that were enrolled when the item was added to the keychain

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary and look for uses of [SecAccessControlCreateWithFlags(...)](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) API with [kSecAccessControlBiometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset?language=objc) flag.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app uses `SecAccessControlCreateWithFlags(...)` without `kSecAccessControlBiometryCurrentSet` flag to authenticate.
