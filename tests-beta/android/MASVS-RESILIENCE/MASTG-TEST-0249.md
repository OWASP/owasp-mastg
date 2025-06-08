---
platform: android
title: Runtime Use of Secure Screen Lock Detection APIs
id: MASTG-TEST-0249
apis: [KeyguardManager, BiometricManager#canAuthenticate]
type: [dynamic]
weakness: MASWE-0008
best-practices: []
profiles: [L2]
---

## Overview

This test is the dynamic counterpart to @MASTG-TEST-0247.

## Steps

1. Run a dynamic analysis tool like @MASTG-TOOL-0039 and look for uses of `KeyguardManager.isDeviceSecure` and `BiometricManager.canAuthenticate` APIs.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use any API to verify the secure screen lock presence.
