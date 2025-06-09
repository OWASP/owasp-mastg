---
platform: ios
title: Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication
id: MASTG-TEST-0269
apis: [kSecAccessControlUserPresence, kSecAccessControlDevicePasscode, SecAccessControlCreateWithFlags]
type: [dynamic]
weakness: MASWE-0045
profiles: [L2]
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0268.

## Steps

1. Use runtime method hooking (see @MASTG-TECH-0095) and look for uses of [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) and specific flags.

## Observation

The output should contain a list of locations where the `SecAccessControlCreateWithFlags` function is called including all used flags.

## Evaluation

The test fails if the app uses `SecAccessControlCreateWithFlags` with the `kSecAccessControlUserPresence` or `kSecAccessControlDevicePasscode` flags for any sensitive data resource that needs protection.

The test passes only if the app uses `SecAccessControlCreateWithFlags` with stricter flags, such as [`kSecAccessControlBiometryAny`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany), [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) to enforce biometric-only access for any sensitive data resource that needs protection (being `kSecAccessControlBiometryCurrentSet` the one considered the most secure).
