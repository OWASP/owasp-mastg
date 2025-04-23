---
platform: ios
title: Runtime Use Of APIs Detecting Biometric Enrollment Changes
id: MASTG-TEST-0271
apis: [kSecAccessControlBiometryCurrentSet,SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0046
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0270.

## Steps

1. Run a dynamic analysis tool like @MASTG-TOOL-0039 and look for uses of [SecAccessControlCreateWithFlags(...)](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) with [kSecAccessControlUserPresence](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence?language=objc) flag.

## Observation

The output should contain a list of locations where `SecAccessControlCreateWithFlags` function is used with `kSecAccessControlBiometryCurrentSet` flag.

## Evaluation

The test fails if an app uses `SecAccessControlCreateWithFlags(...)` without `kSecAccessControlBiometryCurrentSet` flag to authenticate.
