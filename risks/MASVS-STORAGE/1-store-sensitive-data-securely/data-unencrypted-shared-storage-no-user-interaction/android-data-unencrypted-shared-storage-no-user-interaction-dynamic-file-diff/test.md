---
platform: android
title: Listing Files Stored to External Locations on Runtime
apis: [Environment#getExternalStorageDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, SharedPreferences, FileOutPutStream]
type: [dynamic]
---

## Overview

Comparing the list of all files in the shared and external storage before and after excersising the app may reveal sensitive files stored unintentionally.

## Steps

1. Make sure you have ADB installed

2. Install the app.

3. Execute `run_before.sh` before opening the app to mark the timestamp.

4. Exercise the app

5. Execute `run_after.sh` to list all the files created by the app in the external storage.


## Observation

The **output** contains a list of files that were created during the excersising the app app.

## Evaluation

The test case fails if the files found above are not encrypted and leak sensitive data.

For example, the following output shows sample files that should be manually inspected.

```shell
/storage/emulated/0/Android/data/com.example/keys.json
/storage/emulated/0/Android/data/com.example/files/config.xml
/sdcard/secret.txt"
```
