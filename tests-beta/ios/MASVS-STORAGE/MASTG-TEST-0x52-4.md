---
platform: ios
title: Runtime Keychain Storage with Secure Access Policies
id: MASTG-TEST-0x52-3
apis: [kSecAccessControlUserPresence, kSecAccessControlDevicePasscode, SecAccessControlCreateWithFlags]
type: [dynamic]
best-practices: [MASTG-BEST-0014]
weakness: MASWE-0008
---

## Overview

This test is a dynamic counterpart to @MASTG-TEST-0x52-3.


## Steps

1. Use runtime method hooking (see @MASTG-TECH-0095) and look for uses of [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) and specific flags.

## Observations

The output should contain a list of locations where the `SecAccessControlCreateWithFlags` function is called including all used flags.

## Evaluation

The test case fails if the items in the Keychain don't satisfy your app's security requirements. For example, your app might store sensitive data that you want to keep accessible only on this device. Then, such an item in the Keychain should use `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`.
