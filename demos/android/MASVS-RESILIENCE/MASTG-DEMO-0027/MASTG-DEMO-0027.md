---
platform: android
title: Runtime Use of KeyguardManager.isDeviceSecure and BiometricManager.canAuthenticate APIs with Frida
id: MASTG-DEMO-0027
code: [kotlin]
test: MASTG-TEST-0249
---

### Sample

This sample checks if the device has a secure lock screen via `KeyguardManager.isDeviceSecure` and if the device supports strong biometric authentication using `BiometricManager.canAuthenticate`.

{{ MastgTest.kt }}

### Steps

1. Install the app on a device (@MASTG-TECH-0005)
2. Make sure you have @MASTG-TOOL-0001 installed on your machine and the frida-server running on the device
3. Run `run.sh` to spawn the app with Frida
4. Click the **Start** button
5. Stop the script by pressing `Ctrl+C`

{{ run.sh # script.js }}

### Observation

The output reveals the use of `KeyguardManager.isDeviceSecure` and `BiometricManager.canAuthenticate`.

{{ output.txt }}

### Evaluation

The test passes because the output shows the use of `KeyguardManager.isDeviceSecure` and `BiometricManager.canAuthenticate` at runtime. We can see that:

- `KeyguardManager.isDeviceSecure` is called from the file `MastgTest.kt`, class `MastgTest`, method `isDeviceSecure` at line 24.
- `BiometricManager.canAuthenticate` is called from the file `MastgTest.kt`, class `MastgTest`, method `checkStrongBiometricStatus` at line 38.

Note that in this case the output contains file names and even line numbers, but in real-world scenarios, this information may not be available or not be that useful (e.g. when using a production build or when the app is obfuscated). The output is still valuable because it shows that the APIs are being used at runtime.
