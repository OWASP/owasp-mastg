---
title: References to APIs for Root Detection
platform: android
id: MASTG-TEST-0245
type: [static]
weakness: MASWE-0097
best-practices: []
false_negative_prone: true
apis: [Runtime.exec]
---

## Overview

This test checks if the app tries to detect whether the device is rooted. It does not guarantee that the device is secure because some rooting tools might bypass the detection techniques described below. You can use this test as an indicator that the app includes some root detection.

The testing process involves analyzing the device environment to identify common indicators of root access. This includes checking for the presence of:

- root management tools - e.g. Magisk, KernelSU
- suspicious files or directories - e.g `/system/bin/su`, `/system/xbin/su`
- modified system properties - e.g. `ro.debuggable`, `ro.secure`

## Steps

1. Run @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 on the app binary to detect root detections that use `Runtime.exec`, `File.exists()` and `getprop` APIs.

## Observation

The output should include any instances of common root detection checks in the app binary.

## Evaluation

The test fails if the app does not implement root detection mechanisms. This test is not exhaustive and may not identify all possible root detection checks because the detections may:

- be written in the native part of the app
- use different API than covered by this test
- be obfuscated

Even if the test uncovers root detections, they might not be sufficient against more advanced rooting tools. The most effective way is to test an app against a set of rooting tools. This test should only verify that the developer included the intended detection mechanisms.
