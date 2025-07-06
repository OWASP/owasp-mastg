---
title: Running on a recent Platform Version Not Ensured
id: MASWE-0077
alias: run-on-recent-platform-version
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-CODE-1]

refs:
- https://developer.android.com/guide/topics/manifest/uses-sdk-element
- https://developer.apple.com/documentation/bundleresources/information_property_list/minimumosversion
draft:
  description: e.g. via minSdkVersion on Android and MinimumOSVersion on iOS. with
    this we Ensure services/components availability (MASVS-STORAGE-1), also the NSC/ATS
    availability - Android > 7.0 / iOS > 9.0 (MASVS-NETWORK-1) and WebView secure
    config (MASVS-PLATFORM-2).
  topics:
  - check the OS version
status: placeholder

---

## Overview

Every release of the mobile OS includes security patches and new security features. By supporting older versions, apps stay vulnerable to well-known threats. This control ensures that the app is running on an up-to-date platform version that has patches and security features available which in turn provides the app with a better level of protection.

## Impact

The impact depends on the platform, minimum version and the security issues present in that version. For example on Android before API Level 17 Content Providers may be exported by default if the exported attribute is omitted from their definition in the manifest and JavaScriptInterfaces could be abused to call methods from arbitrary Java classes using reflection.

## Modes of Introduction

- **Android:** The value of the `minSdkVersion` attribute in the `<uses-sdk>` element within the `AndroidManifest.xml` file.
- **iOS:** The value of the `MinimumOSVersion` attribute in the `Info.plist` file.

## Mitigations

- **Android:** Update the value of the `minSdkVersion` attribute in the `<uses-sdk>` element within the `AndroidManifest.xml` file.
- **Android:** On Android if the `targetSdkVersion` is recent and the app is running on a recent version of Android the issue is also mitigated for that specific installation.
- **iOS:** Update value of the `MinimumOSVersion` via the iOS Deployment Target setting of the project in Xcode.
