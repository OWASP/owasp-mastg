---
title: Bypassing Biometric Authentication
platform: ios
---

This technique can typically be used to bypass biometric authentication in apps that perform it by only returning a _success_ or _failure_ result (e.g., `if authenticated {...}` check) **instead of using the [`SecAccessControlCreateWithFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)) Keychain API and requiring user presence**.

## Method for Jailbroken and Non-jailbroken Devices

If you have a jailbroken device with frida-server installed, you can bypass biometric authentication by running @MASTG-TOOL-0038 with the `ios ui biometrics_bypass` command:

```bash
objection -g MASTestApp explore
ios ui biometrics_bypass
```

See the sample output below for using this technique against the @MASTG-DEMO-0042 demo app.

<img src="Images/Techniques/0119-ObjectionBiometricsBypass.png" width="90%" />
<img src="Images/Techniques/0119-ObjectionBiometricsBypassScreenshot.png" width="30%" />

## Method for Non-jailbroken Devices

@MASTG-TOOL-0038 cannot attach to apps on non-jailbroken devices unless the app has been repackaged with the `get-task-allow` flag. @MASTG-TECH-0084 describes how to re-sign an app with this flag. After re-signing, you can use the same method as with jailbroken devices.
