---
title: Debuggable Flag Not Disabled
id: MASWE-0067
alias: debuggable-flag
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v1: [MSTG-RESILIENCE-2]
  masvs-v2: [MASVS-PLATFORM-1, MASVS-RESILIENCE-4]

refs:
- https://developer.android.com/topic/security/risks/android-debuggable
- https://developer.android.com/guide/topics/manifest/application-element
draft:
  description: not setting android:debuggable="false" on Android or get-task-allow="true"
    in the entitlements file on iOS
  topics: null
status: draft

---

## Overview

The `android:debuggable` flag in an Android application's `AndroidManifest.xml`  and the `get-task-allow` determines whether the application is debuggable. These settings, intended for debugging during development, allow attackers to attach debuggers, inspect application memory, modify code at runtime and easily reverse engineer the application. This significantly increases the attack surface and compromises the integrity of the application by providing opportunities for data theft, malicious code injection, and exposure of sensitive information such as API keys. To ensure your application is protected from these potential threats, it's important to explicitly disable these debugging features in release builds through proper build configurations and deployment profiles.

## Impact

- **Allows runtime code inspection**: If the Debuggable flag is not disabled, an attacker can connect a debugger to the app, allowing them to modify its functionality and manipulate values during runtime, which can compromise or change the application's logic.

## Mode of Introduction

- **Incorrect Configuration in files**: Before releasing the app, developers may forget to remove or update the flag.
- **Incorrect Build Configuration**: If debuggable true is mistakenly set in the release build type, it can lead to the production app being debuggable.
- **Merging from Development Branches**: If debugging is enabled in a development or testing branch and merged into the production branch without review, the flag may persist in the release build.

## Mitigations

- **Set debuggable to false**: Ensure `android:debuggable` or `get-task-allow` is set to false in production builds.  
