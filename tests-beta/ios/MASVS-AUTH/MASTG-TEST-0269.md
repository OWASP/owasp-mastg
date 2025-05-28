---
platform: ios
title: Runtime Use Of APIs Allowing Fallback to Non-Biometric Authentication
id: MASTG-TEST-0269
apis: [kSecAccessControlUserPresence, kSecAccessControlDevicePasscode, SecAccessControlCreateWithFlags]
type: [dynamic]
weakness: MASWE-0045
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0268.

## Steps

1. Use runtime method hooking (see @MASTG-TECH-0095) and look for uses of [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) and specific flags.

## Observation

The output should contain a list of locations where `SecAccessControlCreateWithFlags` function is called including all used flags.

## Evaluation

The test fails if the app uses `SecAccessControlCreateWithFlags` with `kSecAccessControlUserPresence` or `kSecAccessControlDevicePasscode` flags.
