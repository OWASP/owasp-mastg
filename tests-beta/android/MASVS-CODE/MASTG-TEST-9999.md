---
platform: android
title: Not Ensuring Recent Platform Version
id: MASTG-TEST-9999
type: [static]
weakness: MASWE-0077
---

## Overview

This test verifies whether your app ensures it is running on a recent version of Android by checking the value of `minSdkVersion` within `AndroidManifest.xml`. For the purposes of this test the value is checked to see if it is less than API level 30 (Android 11, released 2020). However, you should ensure you are using a value that is appropriate for the app being tested and balance between current market share of an API and security. If you are the app's developer the Play console has metrics specific to an app's user distribution but you can also find general metrics at [ApiLevels.com](https://apilevels.com/)

## Steps

Use `grep` to search the `AndroidManifest.xml` for `android:minSdkVersion`  (@MASTG-TECH-0014).

## Observation

The output should contain the line of the manifest that defines the `minSdkVersion`.

## Evaluation

The test case fails if `minSdkVersion` does not exist or the value is less than 30.
