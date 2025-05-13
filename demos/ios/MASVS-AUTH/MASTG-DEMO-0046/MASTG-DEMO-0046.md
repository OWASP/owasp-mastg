---
platform: ios
title: Runtime Use of kSecAccessControlBiometryCurrentSet with Frida
id: MASTG-DEMO-0046
code: [swift]
test: MASTG-TEST-0271
---

### Sample

This demo uses the same sample as @MASTG-DEMO-0045.

{{ ../MASTG-DEMO-0045/MastgTest.swift }}

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

The test fails because the output shows the runtime use of `SecAccessControlCreateWithFlags` with `kSecAccessControlBiometryAny`, which accepts any additional biometrics added after the Keychain entry was created. It's recommended to use the [`kSecAccessControlBiometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset?language=objc) flag instead.
