---
title: Use Up-to-Date minSdkVersion
alias: use-up-to-date-min-sdk-version
id: MASTG-BEST-0010
platform: android
---

Ensure that the `minSdkVersion` in the `build.gradle` file is set to the latest version of the Android platform that aligns with your app's requirements while maintaining compatibility with your user base.

Companies often hesitate to increase `minSdkVersion` because they want their app to be available on as many devices as possible. Even though Google doesn't enforce a specific `minSdkVersion`, [as they do with the `targetSdkVersion`](https://support.google.com/googleplay/android-developer/answer/11926878), it's crucial to understand the implications of setting a low `minSdkVersion`, as it **directly impacts security**, **exposes users to vulnerabilities**, and **prevents the app from leveraging critical security protections**.

## Clarifying the Difference: `targetSdkVersion` vs `minSdkVersion`

- `targetSdkVersion`: Defines the highest API level the app is _designed_ to run on. The app _can_ run on lower API levels, but it won't necessarily take advantage of all new security enforcements.
- `minSdkVersion`: Defines the lowest API level the app is _allowed_ to run on. This is crucial because many security features are only available on devices running a certain API level or higher. If you set a low `minSdkVersion`, your app **completely misses out on these protections** on older devices.

Even if you set a high `targetSdkVersion`, the app can still run on older devices **without** the latest security improvements. If you set `targetSdkVersion=33` (Android 13) but `minSdkVersion=21` (Android 5), the app can still be installed on Android 5 devices, **which lack years of critical security updates**. Malware on these older devices can exploit missing security features that app-level code alone cannot address, as evidenced by vulnerabilities listed in the [Android Security Bulletins](https://source.android.com/docs/security/bulletin).

While increasing `minSdkVersion` may slightly reduce the number of devices your app can run on, **it significantly enhances security** by ensuring that **all users have a baseline level of protection**.

## Common Misconceptions

There are many misconceptions about the `minSdkVersion` and `targetSdkVersion` in Android development. The Android documentation sometimes mentions "targeting" when they actually mean "running on." For example:

> [Opt out of cleartext traffic](https://developer.android.com/privacy-and-security/security-config#CleartextTrafficPermitted): The guidance in this section applies only to apps that target Android 8.1 (API level 27) or lower. Starting with Android 9 (API level 28), cleartext support is disabled by default.

The note says the guidance applies to apps **targeting API 27 or lower**. But in reality, **even if an app targets API 28+ but is running on an older Android version (below API 28), cleartext traffic is still allowed** unless explicitly disabled. Developers might assume that just increasing `targetSdkVersion` automatically blocks cleartext, which is incorrect.

## Notable Android Platform Security Improvements Over Time

- Android 4.2 (API level 16) in November 2012 (introduction of SELinux)
- Android 4.3 (API level 18) in July 2013 (SELinux became enabled by default)
- Android 4.4 (API level 19) in October 2013 (several new APIs and ART introduced)
- Android 5.0 (API level 21) in November 2014 (ART used by default and many other features added)
- Android 6.0 (API level 23) in October 2015 (many new features and improvements, including granting; detailed permissions setup at runtime rather than all or nothing during installation)
- Android 7.0 (API level 24-25) in August 2016 (new JIT compiler on ART)
- Android 8.0 (API level 26-27) in August 2017 (a lot of security improvements)
- Android 9 (API level 28) in August 2018 (restriction of background usage of mic or camera, introduction of lockdown mode, default HTTPS for all apps)
- **Android 10 (API level 29)** in September 2019 (enforces TLS 1.3, access location "only while using the app", device tracking prevention, improve secure external storage)
    - [Privacy (overview)](https://developer.android.com/about/versions/10/highlights#privacy_for_users "Android 10 Privacy Overview")
    - [Privacy (details 1)](https://developer.android.com/about/versions/10/privacy "Android 10 Privacy Details 1")
    - [Privacy (details 2)](https://developer.android.com/about/versions/10/privacy/changes "Android 10 Privacy Details 2")
    - [Security (overview)](https://developer.android.com/about/versions/10/highlights#security "Android 10 Security Overview")
    - [Security (details)](https://developer.android.com/about/versions/10/behavior-changes-all#security "Android 10 Security Details")
- **Android 11 (API level 30)** in September 2020 (scoped storage enforcement, Permissions auto-reset, [reduced package visibility](https://developer.android.com/training/package-visibility), APK Signature Scheme v4)
    - [Privacy (overview)](https://developer.android.com/about/versions/11/privacy "Android 11 Privacy Overview")
    - [Privacy Behavior changes (all apps)](https://developer.android.com/about/versions/11/behavior-changes-all "Android 11 Privacy Behavior changes (all apps)")
    - [Security Behavior changes (all apps)](https://developer.android.com/about/versions/11/behavior-changes-all#security "Android 11 Security Behavior changes (all apps)")
    - [Privacy Behavior changes (apps targeting version)](https://developer.android.com/about/versions/11/behavior-changes-11#privacy "Android 11 Privacy Behavior changes (apps targeting version)")
    - [Security Behavior changes (apps targeting version)](https://developer.android.com/about/versions/11/behavior-changes-11#security "Android 11 Security Behavior changes (apps targeting version)")
- **Android 12 (API level 31-32)** in August 2021 (Material You, Web intent resolution, Privacy Dashboard)
    - [Security and privacy](https://developer.android.com/about/versions/12/features#security-privacy "Android 12 Security and privacy")
    - [Behavior changes (all apps)](https://developer.android.com/about/versions/12/behavior-changes-all#security-privacy "Android 12 Behavior changes (all apps)")
    - [Behavior changes (apps targeting version)](https://developer.android.com/about/versions/12/behavior-changes-12#security-privacy "Android 12 Behavior changes (apps targeting version)")
- **Android 13 (API level 33)** in 2022 (Safer exporting of context-registered receivers, new photo picker)
    - [Security and privacy](https://developer.android.com/about/versions/13/features#privacy-security "Android 13 Security and privacy")
    - [Privacy Behavior changes (all apps)](https://developer.android.com/about/versions/13/behavior-changes-all#privacy "Android 13 Privacy Behavior changes (all apps)")
    - [Security Behavior changes (all apps)](https://developer.android.com/about/versions/13/behavior-changes-all#security "Android 13 Security Behavior changes (all apps)")
    - [Privacy Behavior changes (apps targeting version)](https://developer.android.com/about/versions/13/behavior-changes-13#privacy "Android 13 Privacy Behavior changes (apps targeting version)")
    - [Security Behavior changes (apps targeting version)](https://developer.android.com/about/versions/13/behavior-changes-13#security "Android 13 Security Behavior changes (apps targeting version)")
- **Android 14 (API level 34)** in 2023:
    - [Summary of changes](https://developer.android.com/about/versions/14/summary "Android 14 Summary of changes")
    - [Security Behavior changes (all apps)](https://developer.android.com/about/versions/14/behavior-changes-all#security "Android 14 Security Behavior changes (all apps)")
    - [Security Behavior changes (apps targeting version)](https://developer.android.com/about/versions/14/behavior-changes-14#security "Android 14 Security Behavior changes (apps targeting version)")
- **Android 15 (API level 35)** in 2024:
    - [Summary of changes](https://developer.android.com/about/versions/15/summary "Android 15 Summary of changes")
    - [Security Behavior changes (all apps)](https://developer.android.com/about/versions/15/behavior-changes-all#security "Android 15 Security Behavior changes (all apps)")
    - [Security Behavior changes (apps targeting version)](https://developer.android.com/about/versions/15/behavior-changes-15#security "Android 15 Security Behavior changes (apps targeting version)")
- **Android 16 (API level 36)** in 2025 (:material-flask: BETA):
    - [Summary of changes](https://developer.android.com/about/versions/16/summary "Android 16 Summary of changes")
    - [Security Behavior changes (all apps)](https://developer.android.com/about/versions/16/behavior-changes-all#security "Android 16 Security Behavior changes (all apps)")
    - [Security Behavior changes (apps targeting version)](https://developer.android.com/about/versions/16/behavior-changes-16#security "Android 16 Security Behavior changes (apps targeting version)")
