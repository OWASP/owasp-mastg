---
platform: ios
title: Runtime Use of LAContext.canEvaluatePolicy with Frida
id: MASTG-DEMO-0026
code: [swift]
test: MASTG-TEST-0246
---

### Sample

The following sample checks whether the device has a set passcode.

{{ MastgTest.swift }}

### Steps

1. Install the app on your device
2. Make sure you have @MASTG-TOOL-0039 installed
3. Run `run.sh` to run spawn your app with Frida
4. Exercise the app
5. Close the app

{{ run.sh }}

### Observation

{{ output.txt }}

The output reveals the use of `LAcontext.canEvaluatePolicy(0x2)` in the app. Policy `0x2` is [`.deviceOwnerAuthentication`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication).

### Evaluation

The test passes because the output shows the runtime use of `LAcontext.canEvaluatePolicy(.deviceOwnerAuthentication)` which verifies whether the device has passcode set.
