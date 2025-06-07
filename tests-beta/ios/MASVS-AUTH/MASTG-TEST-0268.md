---
platform: ios
title: References to APIs Allowing Fallback to Non-Biometric Authentication
id: MASTG-TEST-0268
apis: [kSecAccessControlUserPresence, kSecAccessControlDevicePasscode, SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0045
profiles: [L2]
---

## Overview

This test checks if the app uses authentication mechanisms that rely on the user's passcode instead of biometrics or allow fallback to device passcode when biometric authentication fails. Specifically, it checks for use of [`kSecAccessControlDevicePasscode`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/devicepasscode) or [`kSecAccessControlUserPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence).

The `kSecAccessControlUserPresence` flag is described in the Apple docs as the option that's typically used as it "lets the system choose a mechanism, depending on the current situation". However, this allows fallback to passcode in some cases (e.g. when biometrics aren't configured yet), which is considered weaker than requiring biometrics alone because passcodes are more susceptible to compromise (e.g., through shoulder surfing).

**Note:** This test does not consider [`LAPolicy.deviceOwnerAuthentication`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication) for LocalAuthentication flows because that shouldn't be used on its own. See @MASTG-TEST-0266.

## Steps

1. Run a static analysis scan using @MASTG-TOOL-0073 to detect usage of `SecAccessControlCreateWithFlags` with the `kSecAccessControlUserPresence` or `kSecAccessControlDevicePasscode` flags.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if the app uses `SecAccessControlCreateWithFlags` with the `kSecAccessControlUserPresence` or `kSecAccessControlDevicePasscode` flags for any sensitive data resource that needs protection.

The test passes only if the app uses `SecAccessControlCreateWithFlags` with stricter flags, such as [`kSecAccessControlBiometryAny`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany), [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) to enforce biometric-only access for any sensitive data resource that needs protection (being `kSecAccessControlBiometryCurrentSet` the one considered the most secure).

**Note:** Using `kSecAccessControlUserPresence` or `kSecAccessControlDevicePasscode` is not inherently a vulnerability, but in high-security applications (e.g., finance, government, health), their use can represent a weakness or misconfiguration that reduces the intended security posture. So this issue better categorized as a security weakness or hardening issue, not a critical vulnerability.
