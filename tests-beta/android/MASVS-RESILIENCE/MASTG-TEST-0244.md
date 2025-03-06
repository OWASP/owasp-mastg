---
platform: android
title: Runtime Use of Secure Lock Verification APIs
id: MASTG-TEST-0244
apis: [KeyguardManager]
type: [dynamic]
weakness: MASWE-0008
best-practices: []
---

## Overview

This test verifies that an app is running on a device with a secure lock screen (e.g. a passcode).

## Steps

1. Run a dynamic analysis tool like @MASTG-TOOL-0039 and look for uses of `KeyguardManager.isDeviceSecure`.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use API that verifies passcode presence.
