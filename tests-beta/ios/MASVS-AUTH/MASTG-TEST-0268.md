---
platform: ios
title: References to APIs Allowing Fallback to Non-Biometric Authentication
id: MASTG-TEST-0268
apis: [kSecAccessControlUserPresence]
type: [static]
weakness: MASWE-0045
---

## Overview

This test verifies that an app denies a fallback to passcode authentication if the biometric no longer works. The use of [kSecAccessControlUserPresence](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence?language=objc) API allows for such a fallback. This is considered to be weaker than [kSecAccessControlBiometryAny](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany?language=objc) since it is much easier to steal someone's passcode entry by means of shouldersurfing, than it is to bypass the Touch ID or Face ID service.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary and look for uses of [LAContext.evaluatePolicy(...)](https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)) API,attribute.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app uses `LAContext.evaluatePolicy` API to authenticate the user.
