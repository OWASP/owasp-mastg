---
platform: ios
title: References to Device-Access-Security Policy APIs
id: MASTG-TEST-0243
apis: [LAContext.canEvaluatePolicy, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly]
type: [static]
weakness: MASWE-0008
best-practices: []
---

## Overview

This test verifies that an application is running on a device with a set passcode. A set passcode ensures that data on the device is encrypted and access to the device is restricted.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0073 on the app binary, or use a dynamic analysis tool like @MASTG-TOOL-0039, and look for uses of `LAContext.canEvaluatePolicy` API.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if an app doesn't use API that verifies Device-Access-Security Policy.
