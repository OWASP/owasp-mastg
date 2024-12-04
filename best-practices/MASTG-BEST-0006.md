---
title: Use Up-to-Date APK Signing Schemes
alias: use-up-to-date-apk-signing-schemes
id: MASTG-BEST-0006
platform: android
---

Ensure that the app is signed with at least the v2 or v3 APK signing scheme, as these provide comprehensive integrity checks and protect the entire APK from tampering. For optimal security and compatibility, consider using v3, which also supports key rotation.

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
