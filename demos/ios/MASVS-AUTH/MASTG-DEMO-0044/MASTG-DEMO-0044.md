---
platform: ios
title: Runtime Use of kSecAccessControlUserPresence with Frida
id: MASTG-DEMO-0044
code: [swift]
test: MASTG-TEST-0269
---

### Sample

The following sample checks whether the app uses a biometric authentication API that allows for a fallback to passcode authentication.

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

The output reveals the use of `SecAccessControlCreateWithFlags(...)` in the app and lists all used flags. In this case, `kSecAccessControlUserPresence` flag was used. Note that the script also prints `[WARNING] The authentication may fallback to device's passcode` message when insecure flags are used.

### Evaluation

The test fails because the output shows the runtime use of `SecAccessControlCreateWithFlags(..., kSecAccessControlUserPresence)` which allows for a fallback to passcode authentication.
