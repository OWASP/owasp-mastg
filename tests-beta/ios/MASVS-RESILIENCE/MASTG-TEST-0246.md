---
platform: ios
title: Runtime Use of Secure Lock Verification APIs
id: MASTG-TEST-0246
apis: [LAContext.canEvaluatePolicy, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly]
type: [dynamic]
weakness: MASWE-0008
best-practices: []
---

## Overview

This test verifies that an application is running on a device with a set passcode. A set passcode ensures that data on the device is encrypted and access to the device is restricted.

## Steps

1. Run a dynamic analysis tool like @MASTG-TOOL-0039 and look for uses of [LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)) API or data stored with [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) attribute.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use API that verifies passcode presence.
