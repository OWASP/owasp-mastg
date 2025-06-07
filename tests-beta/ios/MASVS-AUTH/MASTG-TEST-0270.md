---
platform: ios
title: References to APIs Detecting Biometric Enrollment Changes
id: MASTG-TEST-0270
apis: [kSecAccessControlBiometryCurrentSet,SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0046
profiles: [L2]
---

## Overview

This test checks whether the app fails to protect sensitive operations against unauthorized access following biometric enrollment changes. An attacker who obtains the device passcode could add a new fingerprint or facial representation via system settings and use it to authenticate in the app.

The test identifies the absence of the [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) access control flag when storing sensitive items in the Keychain via [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)). This flag ensures that the associated Keychain item becomes inaccessible if the biometric database changes (e.g., when a new fingerprint or face is added). As a result, only users whose biometric data was enrolled at the time the item was created can unlock it, preventing unauthorized access through later-enrolled biometrics.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary and look for uses of [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) API with [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) flag.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if the app uses `SecAccessControlCreateWithFlags` with any flag except the `kSecAccessControlBiometryCurrentSet` flag for any sensitive data resource worth protecting.
