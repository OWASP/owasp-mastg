---
title: Root Indicators Detection
platform: android
id: MASTG-TEST-0245
type: [static]
weakness: MASWE-0097
best-practices: []
false_negative_prone: true
---

## Overview

This test verifies that a mobile app can accurately detect if the Android device it is running on is rooted.

The testing process involves analyzing the device environment to identify common indicators of root access. This includes checking for the presence of root management tools, suspicious files or directories, and modified system properties on the device itself. It does so by statically analyzing the device for [common root detection checks](../../../Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#root-etection-and-common-root-detection-methods).

## Steps

1. **Check for root detection indicators:**

   - Apps may check for the presence of files commonly associated with rooted devices (e.g., /system/xbin/su, /data/data/com.superuser.android.id) or for root management apps (e.g., SuperSU, Magisk).
   - Run a static analysis tool such as @MASTG-TOOL-0002 or @MASTG-TOOL-0011 on the app binary to look for common root detection checks.

2. **Non-standard system behavior detection:**

   - Check if the app monitors processes that shouldn't normally be running, such as su or sh, which are typically associated with root management tools.
   - Reviewing the app's smali or assembler code can reveal whether the app checks for or interacts with such processes.

3. **System properties modification detection:**

   - Apps may monitor system properties (e.g., ro.debuggable, ro.secure) for changes, adding another layer to the root detection process.

4. **Critical system directories modification detection:**

   - Check if the app attempts to modify files or settings in critical system directories, such as /data or /system, which should remain immutable on unrooted devices.

## Observation

The output should include any instances of common root detection checks in the app binary.

## Evaluation

The test passes if the root detection mechanisms are correctly implemented to identify indicators of root access.

The test is considered unsuccessful if the app does not implement root detection mechanisms.This test is not exhaustive and may not identify all possible root detection checks. More advanced techniques, such as manual reverse engineering or deobfuscation, might be necessary to uncover additional, more sophisticated root detection methods.
