---
platform: ios
title: Runtime Use of Secure Screen Lock Detection APIs
id: MASTG-TEST-0246
apis: [LAContext.canEvaluatePolicy, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly]
type: [dynamic]
weakness: MASWE-0008
best-practices: []
profiles: [L2]
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0248.

## Steps

1. Run a dynamic analysis tool like @MASTG-TOOL-0039 and look for uses of [LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)) API or data stored with [kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly](https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly) attribute.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use any API to verify the secure screen lock presence.
