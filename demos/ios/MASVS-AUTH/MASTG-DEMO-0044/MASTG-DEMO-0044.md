---
platform: ios
title: Runtime Use of kSecAccessControlUserPresence with Frida
id: MASTG-DEMO-0044
code: [swift]
test: MASTG-TEST-0269
---

### Sample

This demo uses the same sample as @MASTG-DEMO-0043.

{{ ../MASTG-DEMO-0043/MastgTest.swift }}

### Steps

1. Install the app on a device (@MASTG-TECH-0056)
2. Make sure you have @MASTG-TOOL-0039 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn your app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C`

{{ run.sh # script.js }}

### Observation

{{ output.txt }}

The output reveals the use of `SecAccessControlCreateWithFlags` in the app and lists all used flags.

### Evaluation

The test fails because the output shows the runtime use of `SecAccessControlCreateWithFlags(..., kSecAccessControlUserPresence)` which allows for a fallback to passcode authentication.

Since this data requires protection with biometrics, It's recommended to use the [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) or [`kSecAccessControlBiometryAny`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometryany) flags instead, being `kSecAccessControlBiometryCurrentSet` the most secure.
