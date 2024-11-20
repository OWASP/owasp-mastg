---
title: Usage of Insecure Signature Version
platform: android
id: MASTG-TEST-0224
type: [static]
available_since: 24
weakness: MASWE-0104
---

## Overview

Not using newer APK signing schemes means that the app lacks the enhanced security provided by more robust, updated mechanisms.

This test checks if the outdated v1 signature scheme is enabled. The v1 scheme is vulnerable to certain attacks, such as the "Janus" vulnerability ([CVE-2017-13156](https://nvd.nist.gov/vuln/detail/CVE-2017-13156)), because it does not cover all parts of the APK file, allowing malicious actors to potentially **modify parts of the APK without invalidating the signature**. Relying solely on v1 signing therefore increases the risk of tampering and compromises app security.

To learn more about APK Signing Schemes, see ["Signing Process"](../../../Document/0x05a-Platform-Overview.md#signing-process).

## Steps

1. Obtain the `minSdkVersion` attribute from the AndroidManifest.xml, e.g., via @MASTG-TECH-0117.
2. List all used signature schemes as shown in @MASTG-TECH-0116.

## Observation

The output should contain the value of the `minSdkVersion` attribute and the used signature schemes (for example `Verified using v3 scheme (APK Signature Scheme v3): true`).

## Evaluation

The test case fails if the app has a `minSdkVersion` attribute of 24 and above, and only the v1 signature scheme is enabled.

To mitigate this issue, ensure that the app is signed with at least the v2 or v3 APK signing scheme, as these provide comprehensive integrity checks and protect the entire APK from tampering. For optimal security and compatibility, consider using v3, which also supports key rotation.

Optionally, you can add v4 signing to enable faster [incremental updates](https://developer.android.com/about/versions/11/features#incremental) in Android 11 and above, but v4 alone does not provide security protections and should be used alongside v2 or v3.

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
