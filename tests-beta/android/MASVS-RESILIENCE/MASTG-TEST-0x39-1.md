---
title: Debuggable Flag Not Disabled in the AndroidManifest
platform: android
id: MASTG-TEST-0x39-1
type: [static]
weakness: MASWE-0067
---

## Overview

This test case checks if the application has the debuggable flag ([`android:debuggable`](https://developer.android.com/guide/topics/manifest/application-element#debug)) set to `true` in the AndroidManifest.xml. If this flag is set, an attacker can attach a debugger, and e.g., read and modify internals of the application.

Having this flag set to `true` [is not considered a vulnerability](https://developer.android.com/privacy-and-security/risks/android-debuggable), however, it allow attackers to have more access to the app and resources than intended.

!!! note Other ways to debug the application
    Not enabling debugging in the AndroidManifest.xml does fully prevent all possibilities to debug the app. See @MASWE-0101 for more details on how to prevent debugging.

## Steps

1. View the AndroidManifest.xml using @MASTG-TECH-0110.
2. The output shows if the application is debuggable (e.g. if `application-debuggable` is set in the output of @MASTG-TOOL-0123).

## Observation

The output should contain the contents of the AndroidManifest.xml.

## Evaluation

The test case fails if the debuggable flag is set.
