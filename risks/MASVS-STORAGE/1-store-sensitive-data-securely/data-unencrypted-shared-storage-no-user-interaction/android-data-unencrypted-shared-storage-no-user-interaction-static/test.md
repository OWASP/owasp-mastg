---
platform: android
title: References to APIs and Permissions for Accessing External Storage
apis: [Environment#getExternalStoragePublicDirectory, Environment#getExternalStorageDirectory, Environment#getExternalFilesDir, Environment#getExternalCacheDir, MediaStore, WRITE_EXTERNAL_STORAGE, MANAGE_EXTERNAL_STORAGE]
type: [static]
---

## Overview

This test uses static analysis to look for uses of [APIs allowing an app to write to locations that are shared with other apps](../../../../../Document/0x05d-Testing-Data-Storage.md#external-storage) such as the external storage APIs or the `MediaStore` API as well as the relevant Android manifest storage-related permissions.

This static test is great for identifying all code locations where the app is writing data to shared storage. However, it does not provide the actual data being written, and in some cases, the actual path in the device storage where the data is being written. Therefore, it is recommended to combine this test with others that take a dynamic approach, as this will provide a more complete view of the data being written to shared storage.

## Steps

1. [Reverse engineer the app](../../../../../techniques/android/MASTG-TECH-0017.md).
2. Run a [static analysis](../../../../../techniques/android/MASTG-TECH-0014.md) tool on the reverse engineered app targeting calls to any external storage APIs and Android manifest storage permissions.

## Observation

The output should contain a list of APIs and storage-related permissions used to write to shared storage and their code locations.

## Evaluation

Inspect the app's Android manifest and reverse engineered code using the information provided.

The test case fails if:

- the app has the proper permissions declared in the Android manifest (e.g. `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE`, etc.)
- **and** the data being written to shared storage is sensitive and not encrypted.

To determine the latter, you may need to carefully [review the reversed code](../../../../../techniques/android/MASTG-TECH-0023.md) and/or combine this test with others that take a dynamic approach, as this will provide a more complete view of the data being written to shared storage.

## References

- [Manage all files on a storage device](https://developer.android.com/training/data-storage/manage-all-files)
- [Access media files from shared storage](https://developer.android.com/training/data-storage/shared/media)
