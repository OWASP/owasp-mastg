---
platform: ios
title: Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication
id: MASTG-TEST-0269
apis: [kSecAccessControlUserPresence,SecAccessControlCreateWithFlags]
type: [dynamic]
weakness: MASWE-0045
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0268.

## Steps

1. Run a dynamic analysis tool like @MASTG-TOOL-0039 and look for uses of [SecAccessControlCreateWithFlags(...)](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) with [kSecAccessControlUserPresence](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence?language=objc) flag.

## Observation

The output should contain a list of locations where `SecAccessControlCreateWithFlags` API with `kSecAccessControlUserPresence` flag are used.

## Evaluation

The test fails if an app uses `SecAccessControlCreateWithFlags(...)` with `kSecAccessControlUserPresence` flag to authenticate.
