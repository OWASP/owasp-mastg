---
title: Root Indicators Detection
platform: android
id: MASTG-TEST-0245
type: [static]
weakness: MASWE-0097
best-practices: []
---

## Overview

This test is specifically designed to evaluate the effectiveness of root detection mechanisms. Its goal is to ensure that rooted devices are accurately identified so that any associated security risks can be addressed, ultimately safeguarding the integrity of the device and protecting user data.

The testing process involves analyzing the device environment to identify common indicators of root access. This includes checking for the presence of root management tools, suspicious files or directories, and modified system properties on the device itself. It does so by statically analyzing the device for [common root detection checks](../../../Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md#root-etection-and-common-root-detection-methods). 

## Steps

1. **Check for root indicators:**

   - Look for files such as Superuser.apk, /sbin/su, /system/bin/su, /system/xbin/su.
   - Check for presence of root management apps such as Magisk, SuperSu that are commonly used to manage root access.

2. **Check for modified system properties:**
   - ro.secure=0 (should be 1 on production devices).
   - ro.debuggable=1 (indicates the device is in debug mode).
   - Look for properties like ro.allow.mock.location=1 or persist.sys.usb.config=adb which can indicate modifications related to root.
3. **Check for modifications to critical system directories:**
   - Look for attempts to modify files or settings in directories such as /data or /system, which should remain immutable on an unrooted device.
4. **Check for non-standard system behavior:**
   - Look for processes that shouldn’t normally be running, like su or sh, which are typically used by root management tools.
   - Analyze running processes for any unusual or unauthorized apps, such as root management tools, that should not be running on a non-rooted device.
5. **Analyze and report findings.**

## Observation

The output should contain a comprehensive set of findings that demonstrate the accuracy of the root detection mechanisms on the device. Specifically, it should include traces of any root indicators, such as the presence of root management tools, suspicious system files, and modified system properties. The output should also include evidence of any attempts to modify critical system directories or processes that are not normally running on a non-rooted device.

## Evaluation

The test passes if the root detection mechanisms successfully identify signs of rooting on the device, such as the presence of root management tools, suspicious system files, or modified system properties. The test is considered unsuccessful if a rooted device is not properly detected, if a non-rooted device is mistakenly flagged as rooted (false positive), or if any bypass technique is able to completely circumvent the detection mechanism.

To enhance the reliability of root detection, a combination of static and dynamic analysis methods should be used, such as checking system properties along with monitoring runtime behavior.
