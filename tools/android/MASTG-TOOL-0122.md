---
title: apksigner
platform: android
source: (https://developer.android.com/tools/apksigner
---

[apksigner](https://developer.android.com/tools/apksigner) is contained in the @MASTG-TOOL-0006 at `[SDK-Path]/build-tools/[version]/apksigner`.

It can be used to verify APK signatures:

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
