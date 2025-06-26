---
masvs_v1_id:
- MSTG-STORAGE-11
masvs_v2_id:
- MASVS-STORAGE-1
platform: android
title: Testing the Device-Access-Security Policy
masvs_v1_levels:
- L2
profiles: [L2]
status: deprecated
covered_by: [MASTG-TEST-0247, MASTG-TEST-0249]
deprecation_note: New version available in MASTG V2
---

## Overview

Apps that process or query sensitive information should run in a trusted and secure environment. To create this environment, the app can check the device for the following:

- PIN- or password-protected device locking
- Recent Android OS version
- USB Debugging activation
- Device encryption
- Device rooting (see also "Testing Root Detection")

## Static Analysis

To test the device-access-security policy that the app enforces, a written copy of the policy must be provided. The policy should define available checks and their enforcement. For example, one check could require that the app run only on Android 6.0 (API level 23) or a more recent version, closing the app or displaying a warning if the Android version is less than 6.0.

Check the source code for functions that implement the policy and determine whether it can be bypassed.

You can implement checks on the Android device by querying [_Settings.Secure_](https://developer.android.com/reference/android/provider/Settings.Secure.html "Settings.Secure") for system preferences. [_Device Administration API_](https://developer.android.com/guide/topics/admin/device-admin.html "Device Administration API") offers techniques for creating applications that can enforce password policies and device encryption.

## Dynamic Analysis

The dynamic analysis depends on the checks enforced by the app and their expected behavior. If the checks can be bypassed, they must be validated.
