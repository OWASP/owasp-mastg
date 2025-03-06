---
platform: android
title: Runtime Use of KeyguardManager.isDeviceSecure API with Frida
id: MASTG-DEMO-0027
code: [kotlin]
test: MASTG-TEST-0249
---

### Sample

The following sample checks whether the device has a set passcode.

{{ MastgTest.kt }}

### Steps

1. Install the app on your device
2. Make sure you have @MASTG-TOOL-0001 installed
3. Run `run.sh` to run spawn your app with Frida
4. Exercise the app
5. Close the app

{{ run.sh }}

### Observation

{{ output.txt }}

The output reveals the use of `KeyguardManager.isDeviceSecure`.

### Evaluation

The test passes because the output shows the runtime use of `KeyguardManager.isDeviceSecure` which verifies whether the device has a passcode set.
