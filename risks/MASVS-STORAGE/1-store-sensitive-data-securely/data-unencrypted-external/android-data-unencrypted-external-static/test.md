---
platform: android
title: Use of APIs to access External Storage Locations
apis: [Environment#getExternalStoragePublicDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, MediaStore]
type: [static]
---

## Overview

This test searches for Manifest permissions and APIs that let your app write to locations which are shared with other apps. It means that a third-party app with a proper permissions may access data you write to these locations. Therefore, this test verifies whether an app:
* declares permissions required to write data to shared locations
* uses API to obtain location to shared locations 
* uses MediaStore API

Additionally, if the "external storage" is actually stored externally e.g. on an sd-card, it can be removed from the device and connected to a card reader to extract sensitive data.

### Testing Manifest permissions

An app must declare in the Manifest file an intention to write to shared locations. Below you can find a list of such manifest permissions:
* [WRITE_EXTERNAL_STORAGE](https://developer.android.com/reference/android/Manifest.permission#WRITE_EXTERNAL_STORAGE) - allows an app to write a file to the "external storage" which either resides on an external disk, or is internally emulated by the system. Regardless the actual storage origin, this permissions allows an app to write files to locations shared with other apps. This permission is deprecated starting from `target API 30` but can be preserved with [requestLegacyExternalStorage](https://developer.android.com/reference/android/R.attr#requestLegacyExternalStorage) and [preserveLegacyExternalStorage](https://developer.android.com/reference/android/R.attr#preserveLegacyExternalStorage).  
* [MANAGE_EXTERNAL_STORAGE](https://developer.android.com/reference/android/Manifest.permission#MANAGE_EXTERNAL_STORAGE) - a successor permission of `WRITE_EXTERNAL_STORAGE`. It allows an an app to read and write files to shared locations.

### Testing External Storage APIs

There are APIs such as [[[getExternalStoragePublicDirectory]]](https://developer.android.com/reference/kotlin/android/os/Environment#getExternalStoragePublicDirectory(kotlin.String))
that return paths to a shared locations that other apps can access. [Example 1](./example-1/example.md) illustrates a case where an app obtains a path to an "external" location and writes sensitive data to it. This location is Shared Storage Requiring No User Interaction, so a third-party app with proper permissions can read this sensitive data.

#### External app-specific files

A malicious app with proper permissions running on Android 10 or below can access data that you write to "external" [app-specific-directories](https://developer.android.com/training/data-storage/app-specific).

### Testing MediaStore API

If your app stores data with MediaStore API, a third-party app with proper permissions may read this data.

## Steps

1. Run a [static analysis](../../../../../techniques/android/MASTG-TECH-0014.md) tool on an app to find whether your app uses storage locations shared with other apps and pinpoint the invocations of these APIs. 


## Observation

The output should contain a list of permissions and locations where paths to external storage are returned.

## Evaluation

Inspect app's source code using the provided information. The test case fails if you find code that writes sensitive unencrypted to these locations.

## References

1. https://developer.android.com/training/data-storage/manage-all-files
2. https://developer.android.com/training/data-storage/shared/media
