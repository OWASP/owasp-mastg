---
platform: ios
title: Runtime Use of kSecAccessControlBiometryCurrentSet with Frida
id: MASTG-DEMO-0046
code: [swift]
test: MASTG-TEST-0271
---

### Sample

The following sample checks whether the app uses a biometric authentication API that detects the addition of a new biometric in the system settings after the application adds an entry to the keychain.

{{ MastgTest.swift }}

### Steps

1. Install the app on a device (@MASTG-TECH-0056)
2. Make sure you have @MASTG-TOOL-0039 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn your app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C`

{{ run.sh # script.js }}

### Observation

{{ output.txt }}

The output reveals the use of `SecAccessControlCreateWithFlags(...)` in the app and lists all used flags. In this case, `kSecAccessControlBiometryAny` flag was used. Note that the script also prints `[WARNING] The authentication may use biometric added after an entry in the keychain was created!` message when insecure flag is used.

### Evaluation

The test fails because the output shows the runtime use of `SecAccessControlCreateWithFlags(..., kSecAccessControlBiometryAny)`. `kSecAccessControlBiometryAny` allows for authentication with biometric added in the system settings after the app created an entry in the keychain. It's recommended to use [kSecAccessControlBiometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset?language=objc) flag instead.
