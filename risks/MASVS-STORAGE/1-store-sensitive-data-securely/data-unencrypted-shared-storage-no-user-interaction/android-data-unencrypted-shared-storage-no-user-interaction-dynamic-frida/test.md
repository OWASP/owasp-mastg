---
platform: android
title: Runtime Use of APIs to Access External Storage
apis: [Environment#getExternalStorageDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, FileOutPutStream]
type: [dynamic]
---

## Overview

Android apps use a variety of APIs to obtain a file path and store a file. Collecting a comprehensive list of these APIs can be challenging, especially if an app uses a third-party framework, loads code at runtime, or includes native code. The most effective approach to testing applications that write to device storage is usually dynamic analysis, and specifically [method tracing](../../../../../techniques/android/MASTG-TECH-0033.md).

## Steps

1. Make sure you have Frida installed.

2. Install the app.

3. Execute a `run.sh` to spawn an app with Frida and log all interactions with files.

4. Navigate to the screen of the mobile app that you want to analyse.

5. Close the app to stop Frida.

## Observation

The **method trace output** contains a list of file locations that your app interacts with.

## Evaluation

The test case fails if the files found above are not encrypted and leak sensitive data.

To confirm this, you can manually inspect the files using [adb shell](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/) to retrieve them from the device, and [reverse engineer the app](../../../../../techniques/android/MASTG-TECH-0017.md) and [inspect the code](../../../../../techniques/android/MASTG-TECH-0023.md).
