---
platform: ios
title: Runtime Use of LAContext.evaluatePolicy with Frida
id: MASTG-DEMO-0042
code: [swift]
test: MASTG-TEST-0267
---

### Sample

This demo uses the same sample as @MASTG-DEMO-0041.

{{ ../MASTG-DEMO-0041/MastgTest.swift }}

### Steps

1. Install the app on a device (@MASTG-TECH-0056)
2. Make sure you have @MASTG-TOOL-0039 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn your app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C`

{{ run.sh # script.js }}

### Observation

{{ output.txt }}

The output reveals the use of `LAContext.evaluatePolicy(0x1, ...)` in the app. Policy `0x1` is [`.deviceOwnerAuthenticationWithBiometrics`](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthenticationwithbiometrics).

### Evaluation

The test fails because the output only shows calls to biometric verification with LocalAuthentication API and no calls to any Keychain APIs requiring user presence (`SecAccessControlCreateWithFlags`).
