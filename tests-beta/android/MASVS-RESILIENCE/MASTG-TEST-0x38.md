---
title: Usage of Insecure Signature Version
platform: android
id: MASTG-TEST-0x39-1
type: [static]
available_since: 24
weakness: MASWE-0104
---

## Overview

Applications need to be properly signed to safeguard their integrity and protect them from tampering. Android has evolved its signing schemes over time to enhance security, with newer versions offering more robust mechanisms. Check [APK Signing Schemes](../../../Document/0x05a-Platform-Overview.md#signing-process) for more details.

This test checks if the insecure v1 signature scheme is enabled for applications targetting Android 7.0 (API level 24) and above.

## Steps

1. Obtain the `minSdkVersion` attribute from the AndroidManifest.xml, e.g., via @MASTG-TOOL-0121.
2. List all used signature schemes using @MASTG-TECH-0116 to verify the APK signatures.

## Observation

The output should contain the value of the `minSdkVersion` attribute and the used signature schemes (for example `Verified using v3 scheme (APK Signature Scheme v3): true`).

## Evaluation

The test case fails if the app targets Android 7.0 (API level 24) and above, and only the v1 signature scheme is enabled.

The signing configuration can be managed through Android Studio or the `signingConfigs` section in `build.gradle` or `build.gradle.kts`. To activate both the v3 and v4 schemes, the following values must be set:

```default
// build.gradle
android {
  ...
  signingConfigs {
    config {
        ...
        enableV3Signing true
        enableV4Signing true
    }
  }
}
```

Note that APK v4 signing is optional and the lack of it does not represent a vulnerability. It is meant to allow developers to quickly deploy large APKs using the [ADB Incremental APK installation](https://developer.android.com/about/versions/11/features#incremental) in Android 11 and above.
