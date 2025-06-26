---
platform: android
title: Runtime Use of APIs to Access External Storage
id: MASTG-TEST-0201
apis: [Environment#getExternalStorageDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, FileOutputStream]
type: [dynamic]
weakness: MASWE-0007
profiles: [L1, L2]
---

## Overview

Android apps use a variety of [APIs to access the external storage](../../../0x05d-Testing-Data-Storage.md/#external-storage-apis). Collecting a comprehensive list of these APIs can be challenging, especially if an app uses a third-party framework, loads code at runtime, or includes native code. The most effective approach to testing applications that write to device storage is usually dynamic analysis, and specifically method tracing (@MASTG-TECH-0033).

## Steps

1. Make sure you have @MASTG-TOOL-0001 installed.
2. Install the app.
3. Execute a script to spawn the app with Frida and log all interactions with files.
4. Navigate to the screen of the app that you want to analyse.
5. Close the app to stop Frida.

The Frida script should log all file interactions by hooking into the relevant APIs such as `getExternalStorageDirectory`, `getExternalStoragePublicDirectory`, `getExternalFilesDir` or `FileOutPutStream`. You could also use `open` as a catch-all for file interactions. However, this won't catch all file interactions, such as those that use the `MediaStore` API and should be done with additional filtering as it can generate a lot of noise.

## Observation

The output should contain a list of files that the app wrote to the external storage during execution and, if possible, the APIs used to write them.

## Evaluation

The test case fails if the files found above are not encrypted and leak sensitive data.

To confirm this, you can manually inspect the files using adb shell (@MASTG-TECH-0002) to retrieve them from the device, and reverse engineer the app (@MASTG-TECH-0017) and inspect the code (@MASTG-TECH-0023).
