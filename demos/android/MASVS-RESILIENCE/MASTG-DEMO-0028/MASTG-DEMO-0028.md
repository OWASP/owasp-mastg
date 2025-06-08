---
platform: android
title: Uses of KeyguardManager.isDeviceSecure and BiometricManager.canAuthenticate with semgrep
id: MASTG-DEMO-0028
code: [kotlin]
test: MASTG-TEST-0247
---

### Sample

This sample checks if the device has a secure lock screen via `KeyguardManager.isDeviceSecure` and if the device supports strong biometric authentication using `BiometricManager.canAuthenticate`.

{{ MastgTest.kt # MastgTest_reversed.java }}

### Steps

Let's run @MASTG-TOOL-0110 rules against the sample code.

{{ ../../../../rules/mastg-android-device-passcode-present.yml }}

{{ run.sh }}

### Observation

The output shows all usages of APIs related to secure screen lock detection.

{{ output.txt }}

### Evaluation

The test passes because the output shows references to APIs that check for secure screen lock presence, specifically:

- `KeyguardManager.isDeviceSecure` in line 33
- `BiometricManager.canAuthenticate` in line 39
