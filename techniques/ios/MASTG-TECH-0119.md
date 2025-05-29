---
title: Bypassing Biometric Authentication
platform: ios
---

This technique can usually be used to bypass apps that use biometric authentication and only return a success or failure result (e.g. `if authenticated {...}` check) **instead of using the Keychain API and requiring user presence**.

## Method for Jailbroken and Non-jailbroken Devices

If you have a jailbroken device with frida-server installed, you can bypass event-bound biometrics authentication by running @MASTG-TOOL-0038:

```bash
objection -g MASTestApp explore
ios ui biometrics_bypass
```

Below, you can see a sample output for using this technique against the demo app from @MASTG-DEMO-0042.

<img src="Images/Techniques/0119-ObjectionBiometricsBypass.png" width="90%" />
<img src="Images/Techniques/0119-ObjectionBiometricsBypassScreenshot.png" width="30%" />

## Method for Non-jailbroken Devices

@MASTG-TOOL-0038 cannot attach to apps on non-jailbroken devices unless the app has been repackaged with the `get-task-allow` flag. @MASTG-TECH-0084 describes how to re-sign an app with this flag. Once re-signed, you can use the same technique as for jailbroken devices.
