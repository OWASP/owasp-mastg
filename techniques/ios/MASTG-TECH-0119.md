---
title: Bypassing Biometric Authentication
platform: ios
---

Some applications will implement Biometrics Authentication, that only return a success or failure result. This makes it susceptible to logic manipulation (e.g., bypassing an `if authenticated { ... }` check).

This section describes a technique to bypass Event-Bound Biometrics Authentication.

## Method for Jailbroken and Non-jailbroken Devices

If you have a jailbroken device with frida-server installed, you can bypass Event-Bound Biometrics Authentication by running @MASTG-TOOL-0038 tool with the the following commands:

```
objection -g MASTestApp explore
ios ui biometrics_bypass
```

Below, you can see a sample output for using this technique against the demo app from @MASTG-DEMO-0042.

<img src="Images/Techniques/0119-ObjectionBiometricsBypass.png" width="100%" />
<img src="Images/Techniques/0119-ObjectionBiometricsBypassScreenshot.png" width="100%" />

## Method for Non-jailbroken Devices

@MASTG-TOOL-0038 cannot attach to apps on non-jailbroken unless an app is repackaged with a `get-task-allow` flag. @MASTG-TECH-0084 describes how to resign an app with this flag. Once resigned, you can use the same technique as for the jailbroken devices.
