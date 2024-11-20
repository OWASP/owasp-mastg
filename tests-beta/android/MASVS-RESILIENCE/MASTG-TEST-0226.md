---
title: Debuggable Flag Enabled in the AndroidManifest
platform: android
id: MASTG-TEST-0226
type: [static]
weakness: MASWE-0067
---

## Overview

This test case checks if the application has the debuggable flag ([`android:debuggable`](https://developer.android.com/guide/topics/manifest/application-element#debug)) set to `true` in the AndroidManifest.xml. If this flag is set, an attacker can attach a debugger, and e.g., read and modify internals of the application.

Having this flag set to `true` [is not considered a vulnerability](https://developer.android.com/privacy-and-security/risks/android-debuggable), however, it allow attackers to have more access to the app and resources than intended.

!!! note Other ways to debug the application
    Not enabling debugging in the AndroidManifest.xml does fully prevent all possibilities to debug the app. See @MASWE-0101 for more details on how to prevent debugging.

## Steps

1. View the AndroidManifest.xml using @MASTG-TECH-0117.
2. Search the output for the debuggable flag (e.g. `android:debuggable` if using @MASTG-TOOL-0011 or `application-debuggable` if using @MASTG-TOOL-0124).

## Observation

The output should contain the value of the debuggable flag from the AndroidManifest.xml or be empty.

## Evaluation

The test case fails if the debuggable flag is set to `true`.
