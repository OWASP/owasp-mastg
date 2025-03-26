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
status: new

---

## Overview

The `android:debuggable` flag in the `AndroidManifest.xml` file of an Android app, along with the `get-task-allow` attribute in the iOS app's `entitlements.plist`, indicates whether the application can be debugged. If these flags remain enabled in the app's production build, it opens the door for attackers to attach debuggers, examine the app's memory, alter code during execution, and effectively reverse engineer the application.

## Impact

- **Runtime Manipulation**: When an attacker connects a debugger to the application, they can manipulate variables and alter the app's behavior in real time. This also provides them with the means to extract sensitive information, such as encryption keys, API keys, user credentials, and tokens stored in the application.

## Mode of Introduction

- **Misconfigured Build Settings**: Misconfigured build settings can accidentally leave an application in a state that is debuggable, exposing it to security vulnerabilities. This can result from improper selection of build variants, errors in CI/CD configurations, or mistakenly applying debug settings to production environments.
- **Insufficient Security Measures**: The lack of security checks within the development and deployment pipeline considerably raises the risk of misconfigurations, such as unintentionally releasing debuggable builds into the production environment.

## Mitigations

- Ensure the `android:debuggable` flag in the `AndroidManifest.xml` and `get-task-allow` attribute in `entitlements.plist` is set to `false` in all release builds.
