---
platform: android
title: Use of APIs to access External Storage Locations
apis: [Environment#getExternalStoragePublicDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, MediaStore]
type: [static]
---

## Overview

This test looks for Android manifest permissions and APIs that allow an app to write to locations that are shared with other apps. This means that a third-party app with the proper permissions may be able to access data written to these locations. Therefore, this test verifies whether an app:

- declares permissions required to write data to shared locations
- uses API to obtain location to shared locations 
- uses MediaStore API

Additionally, if the "external storage" is actually stored externally, e.g. on an SD card, it can be removed from the device and inserted into a card reader to extract sensitive data.

### Testing Manifest permissions

An app must declare in the Manifest file an intention to write to shared locations. Below you can find a list of such manifest permissions:

- [WRITE_EXTERNAL_STORAGE](https://developer.android.com/reference/android/Manifest.permission#WRITE_EXTERNAL_STORAGE): allows an app to write a file to the "external storage", regardless of the actual storage origin (external disk or internally emulated by the system).
    - This permission is **deprecated since Android 11.0 (API level 30)** but can be preserved with [requestLegacyExternalStorage](https://developer.android.com/reference/android/R.attr#requestLegacyExternalStorage) and [preserveLegacyExternalStorage](https://developer.android.com/reference/android/R.attr#preserveLegacyExternalStorage).
    - If the app declares a minSdkVersion of 19 or higher, you don't need to declare this permission to read and write files in your application-specific directories returned by [Context.getExternalFilesDir(String)](https://developer.android.com/reference/android/content/Context#getExternalFilesDir(java.lang.String)) and [Context.getExternalCacheDir()](https://developer.android.com/reference/android/content/Context#getExternalCacheDir()).  
    - On Android 4.4 (API level 19) or higher, your app doesn't need to request any storage-related permissions to access app-specific directories within external storage. The files stored in these directories are removed when your app is uninstalled. See <https://developer.android.com/training/data-storage/app-specific#external>.
    - On devices that run Android 9 (API level 28) or lower, your app can access the app-specific files that belong to other apps, provided that your app has the appropriate storage permissions. To give users more control over their files and to limit file clutter, apps that target Android 10 (API level 29) and higher are given scoped access into external storage, or [scoped storage](https://developer.android.com/training/data-storage#scoped-storage), by default. When scoped storage is enabled, apps cannot access the app-specific directories that belong to other apps.
- [MANAGE_EXTERNAL_STORAGE](https://developer.android.com/reference/android/Manifest.permission#MANAGE_EXTERNAL_STORAGE): a successor permission of `WRITE_EXTERNAL_STORAGE`. It allows an an app to read and write files to shared locations special app access called ["All files access"](https://developer.android.com/preview/privacy/storage#all-files-access). This permission only applies to apps target Android 11.0 (API level 30) and its usage is  restricted by Google Play unless the app satisfies [certain requirements](https://support.google.com/googleplay/android-developer/answer/10467955).

### Testing External Storage APIs

There are APIs such as [`getExternalStoragePublicDirectory`](https://developer.android.com/reference/kotlin/android/os/Environment#getExternalStoragePublicDirectory(kotlin.String)) that return paths to a shared location that other apps can access. [Demo 1](demo-1/demo.md) illustrates a case where an app obtains a path to an "external" location and writes sensitive data to it. This location is Shared Storage Requiring No User Interaction, so a third-party app with proper permissions can read this sensitive data.

#### External app-specific files

A malicious app with proper permissions running on Android 10 or below can access data that you write to "external" [app-specific-directories](https://developer.android.com/training/data-storage/app-specific).

### Testing MediaStore API

If your app stores data with MediaStore API, a third-party app with proper permissions may read this data.

## Steps

1. Run a [static analysis](../../../../../techniques/android/MASTG-TECH-0014.md) tool on the app to find if it uses storage locations shared with other apps, and identify the calls to those APIs and the relevant permissions.


## Observation

The output should contain a list of permissions and locations where paths to external storage are returned.

## Evaluation

Inspect app's source code using the provided information. The test case fails if you find code that writes sensitive unencrypted to these locations.

## References

- [Manage all files on a storage device](https://developer.android.com/training/data-storage/manage-all-files)
- [Access media files from shared storage](https://developer.android.com/training/data-storage/shared/media)

