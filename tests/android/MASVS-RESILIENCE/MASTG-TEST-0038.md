---
masvs_v1_id:
- MSTG-CODE-1
masvs_v2_id:
- MASVS-RESILIENCE-2
platform: android
title: Making Sure that the App is Properly Signed
masvs_v1_levels:
- R
profiles: [R]
status: deprecated
covered_by: [MASTG-TEST-0224, MASTG-TEST-0225]
deprecation_note: New version available in MASTG V2
---

## Overview

Ensure that the release builds are properly signed to safeguard their integrity and protect them from tampering. Android has evolved its signing schemes over time to enhance security, with newer versions offering more robust mechanisms.

- **Android 7.0 (API level 24) and above**: Use at least the **v2 signature scheme**, which signs the APK as a whole, providing stronger protection compared to the older v1 (JAR) signing method.
- **Android 9 (API level 28) and above**: It's recommended to use both the **v2 and v3 signature schemes**. The v3 scheme supports **key rotation**, enabling developers to replace keys in the event of a compromise without invalidating old signatures.
- **Android 11 (API level 30) and above**: Optionally include the **v4 signature scheme** to enable faster incremental updates.

Avoid using the **v1 signature scheme** (JAR signing) unless absolutely necessary for backward compatibility with Android 6.0 (API level 23) and below as it is considered insecure. For example, it is affected by the **Janus vulnerability (CVE-2017-13156)**, which can allow malicious actors to modify APK files without invalidating the v1 signature. As such, **v1 should never be relied on exclusively for devices running Android 7.0 and above**.

You should also ensure that the APK's code-signing certificate is valid and belongs to the developer.

For further guidance, refer to the official [Android app signing documentation](https://developer.android.com/studio/publish/app-signing) and best practices for [configuring apps for release](https://developer.android.com/tools/publishing/preparing.html#publishing-configure).

## Static Analysis

APK signatures can be verified with the [apksigner](https://developer.android.com/tools/apksigner) tool. It is located at `[SDK-Path]/build-tools/[version]/apksigner`.

```bash
$ apksigner verify --verbose example.apk
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
```

The contents of the signing certificate can be also examined with apksigner:

```bash
$ apksigner verify --print-certs --verbose example.apk
[...]
Signer #1 certificate DN: CN=Example Developers, OU=Android, O=Example
Signer #1 certificate SHA-256 digest: 1fc4de52d0daa33a9c0e3d67217a77c895b46266ef020fad0d48216a6ad6cb70
Signer #1 certificate SHA-1 digest: 1df329fda8317da4f17f99be83aa64da62af406b
Signer #1 certificate MD5 digest: 3dbdca9c1b56f6c85415b67957d15310
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #1 public key SHA-256 digest: 296b4e40a31de2dcfa2ed277ccf787db0a524db6fc5eacdcda5e50447b3b1a26
Signer #1 public key SHA-1 digest: 3e02ebf64f1bd4ca85732186b3774e9ccd60cb86
Signer #1 public key MD5 digest: 24afa3496f98c66343fc9c8a0a7ff5a2
```

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

## Dynamic Analysis

Static analysis should be used to verify the APK signature.
