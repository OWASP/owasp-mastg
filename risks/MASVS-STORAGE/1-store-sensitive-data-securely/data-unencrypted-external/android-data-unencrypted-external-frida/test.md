---
platform: android
title: Storing Data in External Locations
apis: [Environment#getExternalStorageDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, SharedPreferences, FileOutPutStream]
type: [dynamic]
---

## Overview

Android apps use a variety of APIs to obtain a file path and store a file. Collecting a comprehensive list of these APIs can be challenging, especially if an app uses a third-party framework, loads code at runtime, or includes native code. The most effective approach to testing applications that write to device memory is usually dynamic analysis, and specifically method tracing.

## Steps

1. Install the app.

2. Execute a [method trace](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-00xx/) to spawn an app and log all interactions with files.

3. Navigate to the screen of the mobile app that you want to analyse. 

4. Close the app to stop `frida-trace`


## Observation

The **method trace output** contains a list of file locations that your app interacts with. You may need to use [adb shell](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0002/) to inspect these files manually.

## Evaluation

The test case fails if the files found above are not encrypted and leak sensitive data.

For example, the following output shows sample files that should be manually inspected.

```shell
/storage/emulated/0/Android/data/com.example/keys.json
/storage/emulated/0/Android/data/com.example/files/config.xml
/sdcard/secret.txt"
```
