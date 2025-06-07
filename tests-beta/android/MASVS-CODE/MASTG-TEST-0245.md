---
platform: android
title: References to Platform Version APIs
id: MASTG-TEST-0245
apis: [Build]
type: [static]
weakness: MASWE-0077
best-practices: []
profiles: [L2]
---

## Overview

This test verifies whether an app is running on a recent version of the Android operating system.

In Kotlin, Android apps can determine the OS version using the `Build.VERSION.SDK_INT` property, which returns the API level of the current system. By comparing it to a specific version constant, such as `Build.VERSION_CODES.UPSIDE_DOWN_CAKE` for Android 14 (API level 34), apps can conditionally execute code based on the OS version. In this example, "Upside Down Cake" is the internal codename for Android 14.

Android apps specify a `minSdkVersion`, which defines the oldest OS version they support. While a high `minSdkVersion` reduces the need for runtime version checks, dynamically verifying the OS version using `Build.VERSION.SDK_INT` remains beneficial. It allows apps to take advantage of newer, more secure features when available while maintaining backward compatibility.

## Steps

1. Use either @MASTG-TECH-0014 with a tool such as @MASTG-TOOL-0110 to identify APIs that check the version of the operating system.

## Observation

The output should contain a list of locations where relevant APIs are used.

## Evaluation

The test fails if the app does not include any API calls to verify the operating system version.
