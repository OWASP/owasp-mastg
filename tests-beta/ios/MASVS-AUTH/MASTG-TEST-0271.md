---
platform: ios
title: Runtime Use Of APIs Detecting Biometric Enrollment Changes
id: MASTG-TEST-0271
apis: [kSecAccessControlBiometryCurrentSet,SecAccessControlCreateWithFlags]
type: [static]
weakness: MASWE-0046
profiles: [L2]
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0270.

## Steps

1. Use runtime method hooking (see @MASTG-TECH-0095) and look for uses of [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) and specific flags.

## Observation

The output should contain a list of locations where the `SecAccessControlCreateWithFlags` function is called including all used flags.

## Evaluation

The test fails if the app uses `SecAccessControlCreateWithFlags` with any flag except the `kSecAccessControlBiometryCurrentSet` flag for any sensitive data resource worth protecting.
